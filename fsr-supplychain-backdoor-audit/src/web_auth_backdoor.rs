//! Engine 2: Django / uWSGI Middleware & Nginx Traffic-Mirror / Auth-Bypass Backdoor Analyzer.
//!
//! Audits two critical web-tier planes on FortiSOAR appliances:
//!   1. Nginx Configuration (`/etc/nginx/nginx.conf`, `/etc/nginx/conf.d/*.conf`,
//!      `/etc/nginx/default.d/*.conf`):
//!      - `mirror` / `mirror_request_body` silent API/credential cloning directives,
//!      - `lua_package_path`, `access_by_lua*`, `header_filter_by_lua*`, `body_filter_by_lua*`,
//!        `content_by_lua*`, and unauthorized dynamic `load_module` implants,
//!      - Non-loopback `proxy_pass` targets or hardcoded `Authorization` header injection on `/api/`.
//!   2. FortiSOAR Django / Sealab / uWSGI Layer (`settings.py`, `local_settings.py`, `wsgi.py`,
//!      `middleware*.py`, `auth*.py`, `backends*.py`):
//!      - Non-standard classes injected into `MIDDLEWARE` or `AUTHENTICATION_BACKENDS`,
//!      - Magic HTTP header (`request.META` / `request.headers`) or hardcoded master-password
//!        checks granting `user.is_superuser = True` / `user.is_staff = True` or unauthenticated
//!        `User.objects.filter(is_superuser=True)` elevation.

use std::fs;
use std::path::{Path, PathBuf};

use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};

use crate::connector_skimmer_audit::{collect_files_with_exts, display_under_root, join_rooted};

/// Legitimate Django + FortiSOAR (`cyops` / `sealab`) middleware & auth backend prefixes.
const ALLOWED_DJANGO_CLASS_PREFIXES: &[&str] = &[
    "django.middleware.",
    "django.contrib.sessions.",
    "django.contrib.auth.",
    "django.contrib.messages.",
    "django.contrib.sites.",
    "corsheaders.middleware.",
    "whitenoise.middleware.",
    "rest_framework.",
    "oauth2_provider.",
    "cyops.",
    "cyops_auth.",
    "sealab.",
    "cs_auth.",
    "das.",
    "gateway.",
    "tenants.",
];

/// Output of Engine 2 (`web_auth_backdoor`).
pub struct WebAuthBackdoorResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 2 across Nginx configurations and FortiSOAR Django/uWSGI Python modules.
pub fn run_web_auth_backdoor_audit(root: &Path) -> WebAuthBackdoorResult {
    let mut findings = Vec::new();

    // 1. Nginx configuration inspection
    let nginx_files = discover_nginx_conf_files(root);
    let mut nginx_scanned = 0u64;
    for nf in &nginx_files {
        if let Ok(content) = fs::read_to_string(nf) {
            nginx_scanned += 1;
            let rel_label = display_under_root(root, nf);
            audit_nginx_config_text(&rel_label, &content, &mut findings);
        }
    }

    // 2. Django / Sealab / uWSGI settings & middleware inspection
    let django_files = discover_django_web_files(root);
    let mut django_scanned = 0u64;
    for df in &django_files {
        let Ok(meta) = fs::metadata(df) else {
            continue;
        };
        if meta.len() > 2 * 1024 * 1024 {
            continue;
        }
        if let Ok(content) = fs::read_to_string(df) {
            django_scanned += 1;
            let rel_label = display_under_root(root, df);
            let fname = df
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            if fname.contains("settings") || fname == "wsgi.py" {
                audit_django_settings_and_wsgi(&rel_label, &content, &mut findings);
            }
            if fname.contains("middleware")
                || fname == "wsgi.py"
                || fname.contains("auth")
                || fname.contains("backend")
            {
                audit_django_magic_header_and_bypass(&rel_label, &content, &mut findings);
            }

            // 3. Universal DAS / Python startup hook / Tornado `_execute` & `sys.modules` Cython `.so` monkey-patch scan
            audit_python_das_license_monkeypatch(&rel_label, &fname, &content, &mut findings);
        }
    }

    // 4. FortiSOAR `cyops-auth` (`/server/csdassrv.py`, `utilities/licensemanager.py`, `__init__.py`)
    //    & Python startup hook (`site-packages/*.py`, `.pth`) structural integrity audit
    //    evaluated against a version-tagged baseline manifest (`baselines/fortisoar-*.json`).
    let baseline = select_and_load_cyops_baseline(root);
    let cyops_auth_checked = audit_cyops_auth_and_startup_hooks(root, &baseline, &mut findings);

    let summary = JsonValue::OrderedObject(vec![
        (
            "baseline_profile_id".to_string(),
            JsonValue::str(&baseline.profile_id),
        ),
        (
            "baseline_reference_release".to_string(),
            JsonValue::str(&baseline.reference_release),
        ),
        (
            "detected_target_version".to_string(),
            JsonValue::str(&baseline.detected_target_version),
        ),
        (
            "baseline_source".to_string(),
            JsonValue::str(&baseline.source_label),
        ),
        (
            "nginx_configs_scanned".to_string(),
            JsonValue::Uint(nginx_scanned),
        ),
        (
            "django_web_files_scanned".to_string(),
            JsonValue::Uint(django_scanned),
        ),
        (
            "cyops_auth_and_startup_files_checked".to_string(),
            JsonValue::Uint(cyops_auth_checked),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    WebAuthBackdoorResult { summary, findings }
}

/// Parses an Nginx configuration file for `mirror`, Lua hooks, rogue modules, and `/api/` auth bypasses.
pub fn audit_nginx_config_text(file_label: &str, content: &str, findings: &mut Vec<Finding>) {
    let mut scope_stack: Vec<String> = Vec::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let clean = strip_nginx_comment(raw_line).trim();
        if clean.is_empty() {
            continue;
        }

        // Track `{` / `}` block context (`location /api/ { ... }`)
        if clean.ends_with('{') {
            let header = clean.trim_end_matches('{').trim().to_string();
            scope_stack.push(header);
        }

        let current_scope = scope_stack
            .last()
            .cloned()
            .unwrap_or_else(|| "main".to_string());

        for stmt in clean.split(';') {
            let directive_line = stmt.trim().trim_end_matches('{').trim();
            if directive_line.is_empty() || directive_line == "}" {
                continue;
            }
            let mut parts = directive_line.split_whitespace();
            let Some(directive) = parts.next() else {
                continue;
            };
            let rest = directive_line[directive.len()..].trim();

            // 2a. Silent traffic cloning (`mirror <uri>` where `<uri>` != `off`)
            if directive == "mirror" && !rest.eq_ignore_ascii_case("off") {
                findings.push(
                    Finding::new(
                        EngineId::WebAuthBackdoor,
                        "CRITICAL_NGINX_TRAFFIC_MIRROR_OR_BYPASS",
                        Severity::Critical,
                        format!("{}:{}", file_label, line_no),
                        format!(
                            "Nginx `mirror {}` directive in scope `{}` silently duplicates incoming API requests (including Authorization/Cookie headers)",
                            rest, current_scope
                        ),
                    )
                    .with_evidence("file", JsonValue::str(file_label))
                    .with_evidence("line", JsonValue::Uint(line_no as u64))
                    .with_evidence("scope", JsonValue::str(&current_scope))
                    .with_evidence("directive", JsonValue::str(directive_line)),
                );
            }

            // 2b-1. OpenResty / Lua / dynamic module injection
            let is_lua_hook = directive == "lua_package_path"
                || directive == "lua_package_cpath"
                || directive.starts_with("init_by_lua")
                || directive.starts_with("access_by_lua")
                || directive.starts_with("rewrite_by_lua")
                || directive.starts_with("content_by_lua")
                || directive.starts_with("header_filter_by_lua")
                || directive.starts_with("body_filter_by_lua")
                || directive.starts_with("log_by_lua");

            if is_lua_hook {
                findings.push(
                    Finding::new(
                        EngineId::WebAuthBackdoor,
                        "CRITICAL_NGINX_TRAFFIC_MIRROR_OR_BYPASS",
                        Severity::Critical,
                        format!("{}:{}", file_label, line_no),
                        format!(
                            "Unauthorized Nginx Lua interception directive `{}` in `{}` ({}:{})",
                            directive, current_scope, file_label, line_no
                        ),
                    )
                    .with_evidence("file", JsonValue::str(file_label))
                    .with_evidence("line", JsonValue::Uint(line_no as u64))
                    .with_evidence("directive", JsonValue::str(directive_line)),
                );
            }

            if directive == "load_module" {
                let unquoted = rest.trim_matches('"').trim_matches('\'');
                let standard_mod = unquoted.starts_with("/usr/lib64/nginx/modules/")
                    || unquoted.starts_with("modules/");
                if !standard_mod || unquoted.contains("lua") || unquoted.contains("tmp") {
                    findings.push(
                        Finding::new(
                            EngineId::WebAuthBackdoor,
                            "CRITICAL_NGINX_TRAFFIC_MIRROR_OR_BYPASS",
                            Severity::Critical,
                            format!("{}:{}", file_label, line_no),
                            format!(
                                "Suspicious Nginx dynamic module `load_module {}` loaded from non-standard or Lua path",
                                rest
                            ),
                        )
                        .with_evidence("file", JsonValue::str(file_label))
                        .with_evidence("line", JsonValue::Uint(line_no as u64))
                        .with_evidence("module_path", JsonValue::str(unquoted)),
                    );
                }
            }

            // 2b-2. External `proxy_pass` or hardcoded credential header injection on `/api/`
            if directive == "proxy_pass" && is_external_proxy_pass_target(rest) {
                findings.push(
                    Finding::new(
                        EngineId::WebAuthBackdoor,
                        "CRITICAL_NGINX_TRAFFIC_MIRROR_OR_BYPASS",
                        Severity::Critical,
                        format!("{}:{}", file_label, line_no),
                        format!(
                            "Nginx scope `{}` forwards traffic via `proxy_pass {}` to non-local external endpoint",
                            current_scope, rest
                        ),
                    )
                    .with_evidence("file", JsonValue::str(file_label))
                    .with_evidence("line", JsonValue::Uint(line_no as u64))
                    .with_evidence("scope", JsonValue::str(&current_scope))
                    .with_evidence("proxy_pass_target", JsonValue::str(rest)),
                );
            }

            if (directive == "proxy_set_header" || directive == "add_header")
                && is_hardcoded_auth_bypass_header(rest)
            {
                findings.push(
                    Finding::new(
                        EngineId::WebAuthBackdoor,
                        "CRITICAL_NGINX_TRAFFIC_MIRROR_OR_BYPASS",
                        Severity::Critical,
                        format!("{}:{}", file_label, line_no),
                        format!(
                            "Hardcoded authentication/privilege header injection `{} {}` in Nginx scope `{}`",
                            directive, rest, current_scope
                        ),
                    )
                    .with_evidence("file", JsonValue::str(file_label))
                    .with_evidence("line", JsonValue::Uint(line_no as u64))
                    .with_evidence("scope", JsonValue::str(&current_scope))
                    .with_evidence("directive", JsonValue::str(directive_line)),
                );
            }
        }

        let close_braces = clean.bytes().filter(|&b| b == b'}').count();
        for _ in 0..close_braces {
            let _ = scope_stack.pop();
        }
    }
}

/// Audits Django `settings.py` / `wsgi.py` for rogue `MIDDLEWARE` and `AUTHENTICATION_BACKENDS` entries.
pub fn audit_django_settings_and_wsgi(
    file_label: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    // 1. Parse list/tuple blocks assigned to `MIDDLEWARE`, `MIDDLEWARE_CLASSES`, `AUTHENTICATION_BACKENDS`
    let mut collecting_target: Option<(&str, usize)> = None;
    let mut bracket_depth = 0i32;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let code = strip_hash_comment(raw_line).trim();
        if code.is_empty() {
            continue;
        }

        // Catch runtime mutation (`MIDDLEWARE.insert(0, '...')` or `AUTHENTICATION_BACKENDS.append(...)`)
        for list_name in [
            "MIDDLEWARE",
            "MIDDLEWARE_CLASSES",
            "AUTHENTICATION_BACKENDS",
        ] {
            if code.contains(&format!("{}.insert(", list_name))
                || code.contains(&format!("{}.append(", list_name))
                || code.contains(&format!("{} +=", list_name))
            {
                for cls in extract_quoted_strings(code) {
                    if cls.contains('.') && !is_allowed_django_class(&cls) {
                        findings.push(
                            Finding::new(
                                EngineId::WebAuthBackdoor,
                                "CRITICAL_DJANGO_AUTH_BYPASS_MIDDLEWARE",
                                Severity::Critical,
                                format!("{}:{}", file_label, line_no),
                                format!(
                                    "Unauthorized class `{}` dynamically injected into `{}` in {}:{}",
                                    cls, list_name, file_label, line_no
                                ),
                            )
                            .with_evidence("file", JsonValue::str(file_label))
                            .with_evidence("line", JsonValue::Uint(line_no as u64))
                            .with_evidence("setting_list", JsonValue::str(list_name))
                            .with_evidence("injected_class", JsonValue::str(&cls)),
                        );
                    }
                }
            }
        }

        if collecting_target.is_none() {
            for target_key in [
                "MIDDLEWARE",
                "MIDDLEWARE_CLASSES",
                "AUTHENTICATION_BACKENDS",
            ] {
                if let Some(rhs) = match_setting_assignment(code, target_key) {
                    bracket_depth = count_open_minus_close(rhs);
                    for cls in extract_quoted_strings(rhs) {
                        check_django_class_entry(file_label, line_no, target_key, &cls, findings);
                    }
                    if bracket_depth > 0 {
                        collecting_target = Some((target_key, line_no));
                    }
                    break;
                }
            }
        } else if let Some((target_key, _start_line)) = collecting_target {
            for cls in extract_quoted_strings(code) {
                check_django_class_entry(file_label, line_no, target_key, &cls, findings);
            }
            bracket_depth += count_open_minus_close(code);
            if bracket_depth <= 0 {
                collecting_target = None;
                bracket_depth = 0;
            }
        }
    }
}

/// Scans Django middleware, auth backend, and WSGI Python files for magic-header or hardcoded
/// password backdoors that elevate `user.is_superuser = True` / `is_staff = True`.
pub fn audit_django_magic_header_and_bypass(
    file_label: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let lines: Vec<&str> = content.lines().collect();

    // Sliding window (up to 18 lines within the same handler/method) correlating:
    //   Trigger: `request.META` / `request.headers` / `HTTP_X_` / hardcoded password equality
    //   Action:  `is_superuser = True`, `is_staff = True`, `User.objects.filter(is_superuser=True)`,
    //            or `request.user = ...` bypass
    let mut reported_windows: Vec<usize> = Vec::new();

    for (idx, &raw_line) in lines.iter().enumerate() {
        let code = strip_hash_comment(raw_line).trim();
        if code.is_empty() {
            continue;
        }

        let is_header_or_secret_trigger = code.contains("request.META")
            || code.contains("request.headers")
            || code.contains("environ.get(")
            || code.contains("HTTP_X_")
            || (code.contains("password") && code.contains("==") && !extract_quoted_strings(code).is_empty());

        if !is_header_or_secret_trigger {
            continue;
        }

        let end = (idx + 18).min(lines.len());
        let mut elevation_line: Option<(usize, String)> = None;
        for (j, &follow_raw) in lines.iter().enumerate().take(end).skip(idx) {
            let follow = strip_hash_comment(follow_raw).trim();
            let elevates = (follow.contains("is_superuser") && follow.contains("True"))
                || (follow.contains("is_staff") && follow.contains("True") && follow.contains('='))
                || (follow.contains("User.objects") && follow.contains("is_superuser=True"))
                || (follow.contains("get_user_model()") && follow.contains("is_superuser=True"));

            if elevates {
                elevation_line = Some((j + 1, follow.to_string()));
                break;
            }
        }

        if let Some((elev_lno, elev_stmt)) = elevation_line {
            if reported_windows.iter().any(|&prev| elev_lno.abs_diff(prev) <= 3) {
                continue;
            }
            reported_windows.push(elev_lno);

            findings.push(
                Finding::new(
                    EngineId::WebAuthBackdoor,
                    "CRITICAL_DJANGO_AUTH_BYPASS_MIDDLEWARE",
                    Severity::Critical,
                    format!("{}:{}", file_label, idx + 1),
                    format!(
                        "Django authentication bypass / magic-header backdoor in {}:{} -> line {} grants superuser/staff privileges (`{}`)",
                        file_label,
                        idx + 1,
                        elev_lno,
                        elev_stmt
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("trigger_line", JsonValue::Uint((idx + 1) as u64))
                .with_evidence("elevation_line", JsonValue::Uint(elev_lno as u64))
                .with_evidence("trigger_statement", JsonValue::str(code))
                .with_evidence("elevation_statement", JsonValue::str(&elev_stmt)),
            );
        }
    }
}

fn check_django_class_entry(
    file_label: &str,
    line_no: usize,
    list_name: &str,
    cls: &str,
    findings: &mut Vec<Finding>,
) {
    if !cls.contains('.') {
        return;
    }
    if !is_allowed_django_class(cls) {
        findings.push(
            Finding::new(
                EngineId::WebAuthBackdoor,
                "CRITICAL_DJANGO_AUTH_BYPASS_MIDDLEWARE",
                Severity::Critical,
                format!("{}:{}", file_label, line_no),
                format!(
                    "Non-standard class `{}` registered in Django `{}` ({}:{})",
                    cls, list_name, file_label, line_no
                ),
            )
            .with_evidence("file", JsonValue::str(file_label))
            .with_evidence("line", JsonValue::Uint(line_no as u64))
            .with_evidence("setting_list", JsonValue::str(list_name))
            .with_evidence("class_path", JsonValue::str(cls)),
        );
    }
}

fn is_allowed_django_class(cls: &str) -> bool {
    let lower = cls.to_ascii_lowercase();
    if lower.contains("backdoor")
        || lower.contains("bypass")
        || lower.contains("magic")
        || lower.contains("skimmer")
        || lower.contains("implant")
    {
        return false;
    }
    ALLOWED_DJANGO_CLASS_PREFIXES
        .iter()
        .any(|pfx| cls.starts_with(pfx))
}

fn is_external_proxy_pass_target(rest: &str) -> bool {
    let clean = rest.trim().trim_matches('"').trim_matches('\'');
    let Some(after_scheme) = clean
        .strip_prefix("http://")
        .or_else(|| clean.strip_prefix("https://"))
    else {
        return false; // unix:... or named upstream
    };
    if after_scheme.starts_with("unix:") || after_scheme.starts_with('$') {
        return false;
    }
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = host_port.split(':').next().unwrap_or(host_port).to_ascii_lowercase();
    // Legitimate FortiSOAR Nginx upstreams are local (`127.0.0.1`, `localhost`, `[::1]`) or named internal upstreams without dots
    if host == "127.0.0.1" || host == "localhost" || host == "[::1]" || !host.contains('.') {
        return false;
    }
    true
}

fn is_hardcoded_auth_bypass_header(rest: &str) -> bool {
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 2 {
        return false;
    }
    let hdr_name = parts[0].to_ascii_lowercase();
    let val = parts[1..].join(" ");
    // Legitimate Nginx forwards `$http_authorization` or `$remote_user` variables; hardcoded literal Bearer/Basic/Admin tokens are backdoors!
    if val.contains('$') {
        return false;
    }
    let clean_val = val.trim_matches('"').trim_matches('\'').to_ascii_lowercase();
    (hdr_name == "authorization"
        && (clean_val.starts_with("bearer ")
            || clean_val.starts_with("basic ")
            || clean_val.starts_with("token ")))
        || ((hdr_name == "x-authenticated-user"
            || hdr_name == "x-forwarded-user"
            || hdr_name == "remote-user")
            && (clean_val == "csadmin" || clean_val == "root" || clean_val == "admin"))
}

fn match_setting_assignment<'a>(code: &'a str, key: &str) -> Option<&'a str> {
    let rest = code.strip_prefix(key)?.trim_start();
    let rhs = rest.strip_prefix('=')?.trim_start();
    if rhs.starts_with('=') {
        return None;
    }
    Some(rhs)
}

fn count_open_minus_close(s: &str) -> i32 {
    let mut d = 0i32;
    for b in s.bytes() {
        match b {
            b'[' | b'(' => d += 1,
            b']' | b')' => d -= 1,
            _ => {}
        }
    }
    d
}

fn extract_quoted_strings(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\'' || bytes[i] == b'"' {
            let q = bytes[i];
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != q {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            if i <= bytes.len() {
                out.push(s[start..i.min(bytes.len())].to_string());
            }
        }
        i += 1;
    }
    out
}

fn strip_nginx_comment(line: &str) -> &str {
    strip_hash_comment(line)
}

fn strip_hash_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_sq = false;
    let mut in_dq = false;
    let mut esc = false;
    for (i, &b) in bytes.iter().enumerate() {
        if esc {
            esc = false;
            continue;
        }
        if b == b'\\' {
            esc = true;
            continue;
        }
        if b == b'\'' && !in_dq {
            in_sq = !in_sq;
        } else if b == b'"' && !in_sq {
            in_dq = !in_dq;
        } else if b == b'#' && !in_sq && !in_dq {
            return &line[..i];
        }
    }
    line
}

fn discover_nginx_conf_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let main_conf = join_rooted(root, "etc/nginx/nginx.conf");
    if main_conf.is_file() {
        out.push(main_conf);
    }
    for rel in [
        "etc/nginx/conf.d",
        "etc/nginx/default.d",
        "etc/nginx/sites-enabled",
    ] {
        let dir = join_rooted(root, rel);
        if dir.is_dir() {
            collect_files_with_exts(&dir, &["conf"], 3, &mut out);
        }
    }
    out.sort();
    out.dedup();
    out
}

fn discover_django_web_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let opt = join_rooted(root, "opt");
    if let Ok(entries) = fs::read_dir(&opt) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if (name == "cyops" || name.starts_with("cyops-") || name.starts_with("cyops_"))
                && entry.path().is_dir()
            {
                collect_cyops_python_files(&entry.path(), 6, &mut out);
            }
        }
    }

    // Also support pointing `--root` directly at an unpacked `cyops-auth` directory
    // or a directory containing `server/csdassrv.py` / `handlerworkers`.
    if join_rooted(root, "server/csdassrv.py").is_file()
        || join_rooted(root, "handlerworkers").is_dir()
        || join_rooted(root, "usercustomize.py").is_file()
    {
        collect_cyops_python_files(root, 6, &mut out);
    }

    out.sort();
    out.dedup();
    out
}

/// Recursively collects `.py` files across `cyops*` trees while pruning bulky third-party
/// virtualenv packages inside `.env/lib/python*/site-packages/<3rd_party_pkg>/` except for
/// top-level `site-packages/*.py` startup hooks and `tornado/web.py`.
fn collect_cyops_python_files(dir: &Path, max_depth: usize, out: &mut Vec<PathBuf>) {
    if max_depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let dir_str = dir.to_string_lossy();
    let in_site_packages_root = dir_str.ends_with("/site-packages") || dir_str.ends_with("\\site-packages");

    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if ft.is_dir() {
            if in_site_packages_root {
                // Inside `site-packages/`, only descend into `tornado` or `fsr*` / `cyops*` / `handlerworkers*`
                if name == "tornado"
                    || name == "fsr"
                    || name.starts_with("cyops")
                    || name.starts_with("handler")
                {
                    collect_cyops_python_files(&path, max_depth - 1, out);
                }
            } else {
                collect_cyops_python_files(&path, max_depth - 1, out);
            }
        } else if ft.is_file() && name.ends_with(".py") {
            out.push(path);
        }
    }
}

/// Allowed factory imports inside `/opt/cyops-auth/server/csdassrv.py`.
const CSDASSRV_ALLOWED_IMPORTS: &[&str] = &[
    "tornado.ioloop",
    "tornado.web",
    "tornado.httpserver",
    "tornado",
    "ssl",
    "sys",
    "os",
    "OpenSSL",
    "subprocess",
    "signal",
    "threading",
    "time",
    "handlerworkers.configprops",
    "handlerworkers.fdnclient",
    "handlerworkers",
    "handlers",
    "utilities.util",
    "utilities.propsmgr",
    "utilities.cspropconstants",
    "utilities",
];

/// Allowed factory imports inside `/opt/cyops-auth/utilities/licensemanager.py`.
const LICENSEMANAGER_ALLOWED_IMPORTS: &[&str] = &[
    "json",
    "os",
    "sys",
    "argparse",
    "time",
    "traceback",
    "handlerworkers.license",
    "handlerworkers.fdnclient",
    "handlerworkers",
    "utilities.csconstants",
    "utilities.ha.common_utils",
    "utilities.license.constants",
    "utilities",
];

/// Allowed factory imports inside `/opt/cyops-auth/defaultappliance.py`.
const DEFAULTAPPLIANCE_ALLOWED_IMPORTS: &[&str] = &[
    "handlerworkers.appliancekeys",
    "handlerworkers.cluster",
    "handlerworkers.userinfo",
    "handlerworkers",
    "os",
    "os.path",
    "argparse",
    "utilities.util",
    "utilities",
    "sys",
    "random",
    "string",
    "OpenSSL",
    "cshmac.requests",
    "cshmac",
    "urllib3",
    "requests",
    "json",
];

/// Allowed factory imports inside `/opt/cyops-auth/utilities/dasmigrate.py`.
const DASMIGRATE_ALLOWED_IMPORTS: &[&str] = &[
    "sqlalchemy.orm",
    "sqlalchemy.ext.declarative",
    "sqlalchemy",
    "os",
    "sys",
    "datetime",
    "utilities.cssessionmanager",
    "utilities.csconstants",
    "utilities",
];

/// Allowed factory imports inside `/opt/cyops-auth/utilities/usermanager.py`.
const USERMANAGER_ALLOWED_IMPORTS: &[&str] = &[
    "os",
    "sys",
    "argparse",
    "fsr.commonlibs.utils",
    "fsr.commonlibs",
    "fsr",
    "handlerworkers.users",
    "handlerworkers",
    "utilities.csconstants",
    "utilities",
];

/// Allowed factory imports inside `/opt/cyops-auth/validationutils/custompwdvalidator.py`.
const CUSTOMPWDVALIDATOR_ALLOWED_IMPORTS: &[&str] = &[
    "re",
    "calendar",
    "datetime",
    "handlerworkers.configprops",
    "handlerworkers",
    "log.cslog",
    "log",
    "utilities.csbcrypt",
    "utilities",
    "validationutils.abstractpwdvalidator",
    "validationutils",
];

/// Allowed factory imports inside `/opt/cyops-auth/utilities/ha/cmd_executor.py`.
const HA_CMD_EXECUTOR_ALLOWED_IMPORTS: &[&str] = &[
    "sys",
    "subprocess",
    "argparse",
    "utilities.ha.conf",
    "utilities.ha.consts",
    "utilities.ha.common_utils",
    "utilities.util",
    "utilities",
];

/// Allowed factory imports inside `/opt/cyops-auth/utilities/ha/manager.py`.
const HA_MANAGER_ALLOWED_IMPORTS: &[&str] = &[
    "argparse",
    "sys",
    "socket",
    "json",
    "os",
    "signal",
    "utilities.ha.conf",
    "utilities.ha.handler",
    "utilities.ha.message_constants",
    "utilities.csconstants",
    "utilities.ha.common_utils",
    "handlerworkers.cluster",
    "handlerworkers",
    "utilities.ha.consts",
    "utilities.ha.postgres",
    "log.cslog",
    "log",
    "utilities.ha.stat",
    "utilities.ha.health",
    "fsr.commonlibs.utils",
    "fsr.commonlibs.consts",
    "fsr.commonlibs",
    "fsr",
    "utilities.ha.commands",
    "utilities.ha.commands.payload_builder",
    "utilities.ha.services",
    "utilities.ha.slots",
    "utilities",
];

/// Allowed factory imports inside `/opt/cyops-auth/utilities/ha/listener.py`.
const HA_LISTENER_ALLOWED_IMPORTS: &[&str] = &[
    "json",
    "time",
    "subprocess",
    "threading",
    "sys",
    "schedule",
    "re",
    "shlex",
    "sqlalchemy.exc",
    "sqlalchemy",
    "handlerworkers",
    "handlerworkers.cluster",
    "handlerworkers.appliancekeys",
    "handlerworkers.publisher",
    "utilities.csconstants",
    "log.cslog",
    "log",
    "utilities.ha.services",
    "utilities.ha",
    "utilities.ha.consts",
    "utilities.ha.supported_commands",
    "requests",
    "utilities.ha.common_utils",
    "utilities.ha.node",
    "utilities.ha.commands.files_handler",
    "utilities",
];

/// Inspects any Python source file for FortiSOAR DAS (`cyops-auth`) runtime monkey-patching,
/// Python startup license-only bypasses, Tornado `RequestHandler._execute` interception,
/// `sys.modules["handlerworkers.license"]` Cython `.so` shadowing, and forged `FSRVMPTM99999999` claims.
pub fn audit_python_das_license_monkeypatch(
    file_label: &str,
    fname_lower: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let is_top_level_site_packages_py = file_label.contains("/site-packages/")
        && !file_label
            .split("/site-packages/")
            .nth(1)
            .unwrap_or("")
            .contains('/')
        && fname_lower.ends_with(".py")
        && fname_lower != "_virtualenv.py"
        && fname_lower != "easy_install.py";
    let is_startup_hook_name = is_top_level_site_packages_py || fname_lower == "usercustomize.py";

    let mut matched_vectors: Vec<&'static str> = Vec::new();
    let mut first_hit_line = 1usize;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let code = strip_hash_comment(raw_line).trim();
        if code.is_empty() {
            continue;
        }

        // 1. Tornado `RequestHandler._execute` monkey-patch intercepting `/license` or `/auth/license`
        if (code.contains("RequestHandler._execute") && code.contains('='))
            || code.contains("def _guaranteed_execute(")
            || (code.contains("\"/auth/license\"") && code.contains("_SC_LICENSE_PAYLOAD"))
        {
            if matched_vectors.is_empty() {
                first_hit_line = line_no;
            }
            if !matched_vectors.contains(&"TORNADO_EXECUTE_LICENSE_INTERCEPT") {
                matched_vectors.push("TORNADO_EXECUTE_LICENSE_INTERCEPT");
            }
        }

        // 2. `sys.modules` Cython `.so` shadowing of `handlerworkers.license` or `handlerworkers.fdnclient`
        if (code.contains("sys.modules[\"handlerworkers.license\"]")
            || code.contains("sys.modules['handlerworkers.license']")
            || code.contains("sys.modules[\"handlerworkers.fdnclient\"]")
            || code.contains("sys.modules['handlerworkers.fdnclient']"))
            && code.contains('=')
        {
            if matched_vectors.is_empty() {
                first_hit_line = line_no;
            }
            if !matched_vectors.contains(&"SYS_MODULES_CYTHON_SO_SHADOWING") {
                matched_vectors.push("SYS_MODULES_CYTHON_SO_SHADOWING");
            }
        }

        // 3. `FakeLicenseManager` / `_FakeMod(ModuleType)` / `CSLicenseManager = FakeLicenseManager`
        if code.contains("class FakeLicenseManager")
            || code.contains("class _FakeMod(ModuleType)")
            || (code.contains("CSLicenseManager") && code.contains("FakeLicenseManager"))
            || code.contains("validate_license_fdn_part = lambda")
        {
            if matched_vectors.is_empty() {
                first_hit_line = line_no;
            }
            if !matched_vectors.contains(&"FAKE_CS_LICENSE_MANAGER_INJECTION") {
                matched_vectors.push("FAKE_CS_LICENSE_MANAGER_INJECTION");
            }
        }

        // 4. Forged FortiSOAR Multi-Tenant perpetual serial & hardware key constants
        if code.contains("FSRVMPTM99999999")
            || code.contains("FSR99999999")
            || code.contains("MOCK-HARDWARE-UUID-KEY")
            || code.contains("MOCK_CRYPTOGRAPHIC_LICENSE_DATA")
            || code.contains("_SC_LICENSE_PAYLOAD")
        {
            if matched_vectors.is_empty() {
                first_hit_line = line_no;
            }
            if !matched_vectors.contains(&"FORGED_FSR_MT_PERPETUAL_CLAIMS") {
                matched_vectors.push("FORGED_FSR_MT_PERPETUAL_CLAIMS");
            }
        }

        // 5. `ssl.SSLContext.load_cert_chain` monkey-patch fallback
        if (code.contains("SSLContext.load_cert_chain") && code.contains('='))
            || code.contains("def _safe_load_cert_chain(")
        {
            if matched_vectors.is_empty() {
                first_hit_line = line_no;
            }
            if !matched_vectors.contains(&"SSL_LOAD_CERT_CHAIN_MONKEYPATCH") {
                matched_vectors.push("SSL_LOAD_CERT_CHAIN_MONKEYPATCH");
            }
        }
    }

    if !matched_vectors.is_empty() {
        let code = if is_startup_hook_name {
            "CRITICAL_PYTHON_STARTUP_HOOK_LICENSE_BYPASS"
        } else {
            "CRITICAL_DAS_RUNTIME_MONKEYPATCH_BYPASS"
        };
        findings.push(
            Finding::new(
                EngineId::WebAuthBackdoor,
                code,
                Severity::Critical,
                format!("{}:{}", file_label, first_hit_line),
                format!(
                    "FortiSOAR DAS (`cyops-auth`) runtime license bypass & Cython `.so` shadowing detected in `{}` (vectors: {})",
                    file_label,
                    matched_vectors.join(", ")
                ),
            )
            .with_evidence("file", JsonValue::str(file_label))
            .with_evidence("first_detected_line", JsonValue::Uint(first_hit_line as u64))
            .with_evidence(
                "bypass_vectors",
                JsonValue::Array(
                    matched_vectors
                        .iter()
                        .map(|v| JsonValue::str(*v))
                        .collect(),
                ),
            ),
        );
    } else if is_startup_hook_name {
        // Any non-factory top-level startup `.py` hook inside `/opt/cyops*` `site-packages/` is flagged
        findings.push(
            Finding::new(
                EngineId::WebAuthBackdoor,
                "HIGH_PYTHON_STARTUP_HOOK_FILE",
                Severity::High,
                file_label.to_string(),
                format!(
                    "Non-factory Python pre-startup hook `{}` present in FortiSOAR environment (executed automatically before all services)",
                    file_label
                ),
            )
            .with_evidence("file", JsonValue::str(file_label)),
        );
    }
}

const EMBEDDED_BASELINE_7_6_JSON: &str = include_str!("../../baselines/fortisoar-7.6.x.json");
const EMBEDDED_BASELINE_7_4_JSON: &str = include_str!("../../baselines/fortisoar-7.4.x.json");

/// Version-tagged structural invariant baseline manifest for FortiSOAR `cyops-auth`.
#[derive(Debug, Clone)]
pub struct CyopsBaselineManifest {
    pub profile_id: String,
    pub version_family: String,
    pub reference_release: String,
    pub detected_target_version: String,
    pub source_label: String,
    pub version_drift_unmatched: bool,
    pub docstring_only_init_files: Vec<String>,
    pub required_cython_so_modules: Vec<String>,
    pub entrypoint_allowlists: Vec<(String, Vec<String>)>,
}

/// Detects the installed FortiSOAR version under `root` and loads the matching version-tagged
/// baseline manifest (`baselines/fortisoar-7.6.x.json`, `baselines/fortisoar-7.4.x.json`, or
/// custom path from `FSR_BASELINE_MANIFEST`).
pub fn select_and_load_cyops_baseline(root: &Path) -> CyopsBaselineManifest {
    let detected = detect_target_fortisoar_version(root);

    // 1. Explicit override via `FSR_BASELINE_MANIFEST` environment variable
    if let Ok(custom_path) = std::env::var("FSR_BASELINE_MANIFEST") {
        let p = PathBuf::from(&custom_path);
        if let Ok(raw) = fs::read_to_string(&p) {
            return parse_cyops_baseline_json(
                &raw,
                &detected.clone().unwrap_or_else(|| "custom-manifest".to_string()),
                &format!("file:{}", custom_path),
                false,
            );
        }
    }

    // 2. Choose family (`7.4` vs `7.6`) based on detected target version
    let det_str = detected
        .clone()
        .unwrap_or_else(|| "auto-default (7.6.x)".to_string());
    let is_7_4 = detected.as_deref().is_some_and(|v| v.starts_with("7.4"));
    let version_drift_unmatched = detected.as_deref().is_some_and(|v| {
        !v.starts_with("7.4") && !v.starts_with("7.5") && !v.starts_with("7.6")
    });

    let candidate_rel = if is_7_4 {
        "baselines/fortisoar-7.4.x.json"
    } else {
        "baselines/fortisoar-7.6.x.json"
    };

    // Check if an external `baselines/fortisoar-*.json` file exists in CWD (allowing hot-swapping baselines without recompiling)
    let ext_path = Path::new(candidate_rel);
    if let Ok(raw) = fs::read_to_string(ext_path) {
        return parse_cyops_baseline_json(
            &raw,
            &det_str,
            candidate_rel,
            version_drift_unmatched,
        );
    }

    let embedded_raw = if is_7_4 {
        EMBEDDED_BASELINE_7_4_JSON
    } else {
        EMBEDDED_BASELINE_7_6_JSON
    };
    parse_cyops_baseline_json(
        embedded_raw,
        &det_str,
        &format!("embedded:{}", candidate_rel),
        version_drift_unmatched,
    )
}

fn detect_target_fortisoar_version(root: &Path) -> Option<String> {
    for rel in [
        "etc/fortisoar-release",
        "opt/cyops/.version",
        "opt/cyops-auth/VERSION",
        "VERSION",
    ] {
        let p = join_rooted(root, rel);
        if let Ok(txt) = fs::read_to_string(&p) {
            let trimmed = txt.lines().next().unwrap_or("").trim();
            if !trimmed.is_empty() {
                return Some(trimmed.trim_start_matches('v').to_string());
            }
        }
    }
    for rel in ["opt/cyops-auth/utilities/das.ini", "utilities/das.ini"] {
        let p = join_rooted(root, rel);
        if let Ok(txt) = fs::read_to_string(&p) {
            for line in txt.lines() {
                if let Some((k, v)) = line.split_once('=') {
                    if k.trim().eq_ignore_ascii_case("version") {
                        let ver = v.trim().trim_start_matches('v');
                        if !ver.is_empty() {
                            return Some(ver.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

fn parse_cyops_baseline_json(
    raw: &str,
    detected_target_version: &str,
    source_label: &str,
    version_drift_unmatched: bool,
) -> CyopsBaselineManifest {
    let profile_id = extract_json_str_field(raw, "profile_id")
        .unwrap_or_else(|| "fortisoar-7.6.x".to_string());
    let version_family = extract_json_str_field(raw, "version_family")
        .unwrap_or_else(|| "7.6".to_string());
    let reference_release = extract_json_str_field(raw, "reference_release")
        .unwrap_or_else(|| "7.6.4-5623".to_string());

    let docstring_only_init_files = extract_json_str_array(raw, "docstring_only_init_files");
    let required_cython_so_modules = extract_json_str_array(raw, "required_cython_so_modules");

    let mut entrypoint_allowlists = Vec::new();
    for (ep, default_slice) in [
        ("server/csdassrv.py", CSDASSRV_ALLOWED_IMPORTS),
        ("utilities/licensemanager.py", LICENSEMANAGER_ALLOWED_IMPORTS),
        ("defaultappliance.py", DEFAULTAPPLIANCE_ALLOWED_IMPORTS),
        ("utilities/dasmigrate.py", DASMIGRATE_ALLOWED_IMPORTS),
        ("utilities/usermanager.py", USERMANAGER_ALLOWED_IMPORTS),
        (
            "validationutils/custompwdvalidator.py",
            CUSTOMPWDVALIDATOR_ALLOWED_IMPORTS,
        ),
        ("utilities/ha/cmd_executor.py", HA_CMD_EXECUTOR_ALLOWED_IMPORTS),
        ("utilities/ha/manager.py", HA_MANAGER_ALLOWED_IMPORTS),
        ("utilities/ha/listener.py", HA_LISTENER_ALLOWED_IMPORTS),
    ] {
        let parsed = extract_json_str_array(raw, ep);
        let list = if parsed.is_empty() {
            default_slice.iter().map(|s| (*s).to_string()).collect()
        } else {
            parsed
        };
        entrypoint_allowlists.push((ep.to_string(), list));
    }

    CyopsBaselineManifest {
        profile_id,
        version_family,
        reference_release,
        detected_target_version: detected_target_version.to_string(),
        source_label: source_label.to_string(),
        version_drift_unmatched,
        docstring_only_init_files,
        required_cython_so_modules,
        entrypoint_allowlists,
    }
}

fn extract_json_str_field(raw: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let idx = raw.find(&needle)?;
    let rest = &raw[idx + needle.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    if !after.starts_with('"') {
        return None;
    }
    let end = after[1..].find('"')?;
    Some(after[1..1 + end].to_string())
}

fn extract_json_str_array(raw: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{}\"", key);
    let Some(idx) = raw.find(&needle) else {
        return Vec::new();
    };
    let rest = &raw[idx + needle.len()..];
    let Some(open_br) = rest.find('[') else {
        return Vec::new();
    };
    let after_open = &rest[open_br + 1..];
    let Some(close_br) = after_open.find(']') else {
        return Vec::new();
    };
    extract_quoted_strings(&after_open[..close_br])
}

/// Audits `/opt/cyops-auth` (or a standalone `cyops-auth` root) and system-wide Python
/// `site-packages` against the selected [`CyopsBaselineManifest`].
fn audit_cyops_auth_and_startup_hooks(
    root: &Path,
    baseline: &CyopsBaselineManifest,
    findings: &mut Vec<Finding>,
) -> u64 {
    let mut checked_count = 0u64;

    // Locate candidate `cyops-auth` roots (`<root>/opt/cyops-auth` and/or `<root>` if standalone)
    let mut cyops_auth_roots = Vec::new();
    let opt_cyops_auth = join_rooted(root, "opt/cyops-auth");
    if opt_cyops_auth.is_dir() {
        cyops_auth_roots.push(opt_cyops_auth);
    }
    if join_rooted(root, "server/csdassrv.py").is_file()
        || (join_rooted(root, "handlerworkers").is_dir() && join_rooted(root, "handlers").is_dir())
    {
        cyops_auth_roots.push(root.to_path_buf());
    }

    for ca_root in &cyops_auth_roots {
        let mut rogue_script_in_server = false;
        // A. `/server/` directory strict file inventory (`__init__.py` and `csdassrv.py` ONLY)
        let server_dir = ca_root.join("server");
        if let Ok(entries) = fs::read_dir(&server_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let fname = entry.file_name().to_string_lossy().into_owned();
                checked_count += 1;
                if fname != "__init__.py" && fname != "csdassrv.py" {
                    rogue_script_in_server = true;
                    let rel_label = display_under_root(root, &path);
                    findings.push(
                        Finding::new(
                            EngineId::WebAuthBackdoor,
                            "CRITICAL_CYOPS_SERVER_ROGUE_SCRIPT_DROP",
                            Severity::Critical,
                            rel_label.clone(),
                            format!(
                                "Unauthorized file `{}` dropped inside `cyops-auth/server/` alongside `csdassrv.py` (baseline `{}` permits only `__init__.py` and `csdassrv.py`)",
                                rel_label, baseline.profile_id
                            ),
                        )
                        .with_evidence("file", JsonValue::str(&rel_label))
                        .with_evidence("baseline_profile", JsonValue::str(&baseline.profile_id))
                        .with_evidence("directory", JsonValue::str("cyops-auth/server")),
                    );
                    if ca_root == root {
                        if let Ok(content) = fs::read_to_string(&path) {
                            let fname_lower = fname.to_ascii_lowercase();
                            audit_python_das_license_monkeypatch(
                                &rel_label,
                                &fname_lower,
                                &content,
                                findings,
                            );
                        }
                    }
                }
            }
        }

        // B. `handlers/` and `handlerworkers/` top-level `.py` shadowing check
        for subdir in ["handlers", "handlerworkers"] {
            let dir = ca_root.join(subdir);
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }
                    let fname = entry.file_name().to_string_lossy().into_owned();
                    if fname.ends_with(".py") && fname != "__init__.py" {
                        checked_count += 1;
                        let rel_label = display_under_root(root, &path);
                        findings.push(
                            Finding::new(
                                EngineId::WebAuthBackdoor,
                                "CRITICAL_CYOPS_SERVER_ROGUE_SCRIPT_DROP",
                                Severity::Critical,
                                rel_label.clone(),
                                format!(
                                    "Rogue Python script `{}` placed in `cyops-auth/{}/` to shadow or hook compiled Cython `.so` modules",
                                    rel_label, subdir
                                ),
                            )
                            .with_evidence("file", JsonValue::str(&rel_label))
                            .with_evidence("baseline_profile", JsonValue::str(&baseline.profile_id))
                            .with_evidence("directory", JsonValue::str(subdir)),
                        );
                    }
                }
            }
        }

        // C. AST/Token Import Allowlist & Tamper Audit driven by `baseline.entrypoint_allowlists`
        let downgrade_for_version_drift =
            baseline.version_drift_unmatched && !rogue_script_in_server;
        for (rel_subpath, allowed_vec) in &baseline.entrypoint_allowlists {
            let fpath = ca_root.join(rel_subpath);
            if let Ok(content) = fs::read_to_string(&fpath) {
                checked_count += 1;
                let rel_label = display_under_root(root, &fpath);
                let allowed_refs: Vec<&str> = allowed_vec.iter().map(|s| s.as_str()).collect();
                audit_cyops_entrypoint_imports_with_baseline(
                    &rel_label,
                    &content,
                    &allowed_refs,
                    &baseline.profile_id,
                    downgrade_for_version_drift,
                    findings,
                );
                audit_cyops_utility_logic_tamper(&rel_label, rel_subpath, &content, findings);
            }
        }

        // D. Docstring-Only `__init__.py` Verification driven by `baseline.docstring_only_init_files`
        for init_rel in &baseline.docstring_only_init_files {
            let init_path = ca_root.join(init_rel);
            if let Ok(content) = fs::read_to_string(&init_path) {
                checked_count += 1;
                let rel_label = display_under_root(root, &init_path);
                audit_docstring_only_init_py(&rel_label, &content, findings);
            }
        }

        // F. `bin/fdnclient.jar` & `cyops-auth/bin/` Integrity Verification (Layer 6)
        checked_count += audit_cyops_bin_fdnclient_jar(root, ca_root, findings);

        // G. `utilities/das.ini` HMAC & Key Path Tampering Audit (Layer 7)
        checked_count += audit_cyops_das_ini(root, ca_root, findings);

        // H. `.env/bin/python*` Virtualenv Interpreter & `activate` Wrapper Hijack Audit (Layer 8)
        checked_count += audit_cyops_venv_interpreter_and_activate(root, ca_root, findings);

        // I. `sql/das_prod.sql` & `sql/migration/*.sql` Seed/Migration Tampering Audit (Layer 10)
        checked_count += audit_cyops_sql_seed_and_migrations(root, ca_root, findings);

        // J. Compiled Cython `.so` Binary Stub / Replacement Audit (Layer 11)
        checked_count += audit_cyops_cython_so_binaries(
            root,
            ca_root,
            &baseline.required_cython_so_modules,
            findings,
        );
    }

    // E. Scan `.pth` files and system-wide `/usr/lib*/python*/site-packages/*.py` startup hooks
    let mut pth_and_sys_hooks = Vec::new();
    for dir_rel in ["opt", "usr/lib", "usr/lib64"] {
        let base = join_rooted(root, dir_rel);
        if base.is_dir() {
            collect_pth_and_sys_startup_hooks(&base, 6, &mut pth_and_sys_hooks);
        }
    }
    for ca_root in &cyops_auth_roots {
        collect_pth_and_sys_startup_hooks(ca_root, 6, &mut pth_and_sys_hooks);
    }
    pth_and_sys_hooks.sort();
    pth_and_sys_hooks.dedup();

    for hook_path in pth_and_sys_hooks {
        let Ok(content) = fs::read_to_string(&hook_path) else {
            continue;
        };
        checked_count += 1;
        let rel_label = display_under_root(root, &hook_path);
        let fname = hook_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if fname.ends_with(".pth") {
            for (idx, raw_line) in content.lines().enumerate() {
                let line_no = idx + 1;
                let trimmed = raw_line.trim();
                // PEP / Python `site.py`: any line in a `.pth` file starting with `import ` or `import\t` is executed via `exec()`!
                if (trimmed.starts_with("import ") || trimmed.starts_with("import\t"))
                    && (trimmed.contains("sys.modules")
                        || trimmed.contains("handlerworkers")
                        || trimmed.contains("exec(")
                        || trimmed.contains("__import__")
                        || trimmed.contains("cyops")
                        || trimmed.contains("bypass")
                        || trimmed.contains("crack"))
                {
                    findings.push(
                        Finding::new(
                            EngineId::WebAuthBackdoor,
                            "CRITICAL_PYTHON_PTH_STARTUP_HOOK",
                            Severity::Critical,
                            format!("{}:{}", rel_label, line_no),
                            format!(
                                "Executable Python `.pth` startup hook `{}` in `{}` runs arbitrary code at interpreter initialization",
                                trimmed, rel_label
                            ),
                        )
                        .with_evidence("pth_file", JsonValue::str(&rel_label))
                        .with_evidence("executable_line", JsonValue::str(trimmed)),
                    );
                }
            }
        } else if fname.ends_with(".py")
            && (rel_label.starts_with("/usr/lib") || rel_label.starts_with("usr/lib"))
        {
            audit_python_das_license_monkeypatch(&rel_label, &fname, &content, findings);
        }
    }

    checked_count
}

/// Verifies that a core `cyops-auth` Python entrypoint (`server/csdassrv.py`, `utilities/licensemanager.py`,
/// `defaultappliance.py`) only imports factory-approved modules and does not execute dynamic code hooks.
fn audit_cyops_entrypoint_imports(
    file_label: &str,
    content: &str,
    allowed_imports: &[&str],
    findings: &mut Vec<Finding>,
) {
    audit_cyops_entrypoint_imports_with_baseline(
        file_label,
        content,
        allowed_imports,
        "fortisoar-7.6.x",
        false,
        findings,
    );
}

fn audit_cyops_entrypoint_imports_with_baseline(
    file_label: &str,
    content: &str,
    allowed_imports: &[&str],
    baseline_profile_id: &str,
    downgrade_for_version_drift: bool,
    findings: &mut Vec<Finding>,
) {
    let (rule_code, severity) = if downgrade_for_version_drift {
        (
            "MEDIUM_CYOPS_ENTRYPOINT_IMPORT_VERSION_DRIFT",
            Severity::Medium,
        )
    } else {
        (
            "CRITICAL_CYOPS_SERVER_UNAUTHORIZED_IMPORT_HOOK",
            Severity::Critical,
        )
    };

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let code = strip_hash_comment(raw_line).trim();
        if code.is_empty() {
            continue;
        }

        // Check for dynamic import / exec hooks injected into `csdassrv.py` / `licensemanager.py`
        if code.contains("__import__(")
            || code.contains("importlib.")
            || code.contains("exec(")
            || code.contains("eval(")
            || code.contains("compile(")
            || code.contains("execfile(")
        {
            findings.push(
                Finding::new(
                    EngineId::WebAuthBackdoor,
                    "CRITICAL_CYOPS_SERVER_UNAUTHORIZED_IMPORT_HOOK",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!(
                        "Dynamic code/import execution (`{}`) injected into unhashed FortiSOAR entrypoint `{}`",
                        code, file_label
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("baseline_profile", JsonValue::str(baseline_profile_id))
                .with_evidence("line", JsonValue::Uint(line_no as u64))
                .with_evidence("statement", JsonValue::str(code)),
            );
            continue;
        }

        // Parse `import <m1>, <m2>` or `from <m> import ...`
        if let Some(rest) = code.strip_prefix("import ") {
            for part in rest.split(',') {
                let mod_token = part
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_end_matches(';');
                if !mod_token.is_empty() && !is_allowed_cyops_import(mod_token, allowed_imports) {
                    findings.push(
                        Finding::new(
                            EngineId::WebAuthBackdoor,
                            rule_code,
                            severity,
                            format!("{}:{}", file_label, line_no),
                            format!(
                                "Non-baseline module `import {}` in FortiSOAR entrypoint `{}` (evaluated against baseline `{}`)",
                                mod_token, file_label, baseline_profile_id
                            ),
                        )
                        .with_evidence("file", JsonValue::str(file_label))
                        .with_evidence("baseline_profile", JsonValue::str(baseline_profile_id))
                        .with_evidence("line", JsonValue::Uint(line_no as u64))
                        .with_evidence("imported_module", JsonValue::str(mod_token))
                        .with_evidence("statement", JsonValue::str(code)),
                    );
                }
            }
        } else if let Some(rest) = code.strip_prefix("from ") {
            let mod_token = rest.split_whitespace().next().unwrap_or("");
            if !mod_token.is_empty() && !is_allowed_cyops_import(mod_token, allowed_imports) {
                findings.push(
                    Finding::new(
                        EngineId::WebAuthBackdoor,
                        rule_code,
                        severity,
                        format!("{}:{}", file_label, line_no),
                        format!(
                            "Non-baseline `from {} import ...` in FortiSOAR entrypoint `{}` (evaluated against baseline `{}`)",
                            mod_token, file_label, baseline_profile_id
                        ),
                    )
                    .with_evidence("file", JsonValue::str(file_label))
                    .with_evidence("baseline_profile", JsonValue::str(baseline_profile_id))
                    .with_evidence("line", JsonValue::Uint(line_no as u64))
                    .with_evidence("imported_module", JsonValue::str(mod_token))
                    .with_evidence("statement", JsonValue::str(code)),
                );
            }
        }
    }
}

fn is_allowed_cyops_import(module_name: &str, allowed_list: &[&str]) -> bool {
    allowed_list.iter().any(|&allowed| {
        module_name == allowed
            || module_name
                .strip_prefix(allowed)
                .is_some_and(|rem| rem.starts_with('.'))
    })
}

/// Verifies that a `cyops-auth` `__init__.py` file contains only the Fortinet copyright docstring
/// and zero executable statements.
fn audit_docstring_only_init_py(file_label: &str, content: &str, findings: &mut Vec<Finding>) {
    let mut in_triple_quote = false;
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let dq_count = trimmed.matches("\"\"\"").count() + trimmed.matches("'''").count();
        if in_triple_quote {
            if dq_count % 2 == 1 {
                in_triple_quote = false;
            }
            continue;
        }
        if (trimmed.starts_with("\"\"\"") || trimmed.starts_with("'''")) && dq_count >= 1 {
            if dq_count == 1 {
                in_triple_quote = true;
            }
            continue;
        }

        // Any statement outside the docstring in a `cyops-auth` `__init__.py` is unauthorized code injection
        findings.push(
            Finding::new(
                EngineId::WebAuthBackdoor,
                "HIGH_CYOPS_INIT_PY_CODE_INJECTION",
                Severity::High,
                format!("{}:{}", file_label, line_no),
                format!(
                    "Executable statement `{}` injected into docstring-only package initializer `{}`",
                    trimmed, file_label
                ),
            )
            .with_evidence("file", JsonValue::str(file_label))
            .with_evidence("line", JsonValue::Uint(line_no as u64))
            .with_evidence("statement", JsonValue::str(trimmed)),
        );
        break;
    }
}

fn collect_pth_and_sys_startup_hooks(dir: &Path, max_depth: usize, out: &mut Vec<PathBuf>) {
    if max_depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let dir_str = dir.to_string_lossy();
    let in_site_packages =
        dir_str.ends_with("/site-packages") || dir_str.ends_with("\\site-packages");
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if ft.is_dir() {
            if !in_site_packages {
                collect_pth_and_sys_startup_hooks(&path, max_depth - 1, out);
            }
        } else if ft.is_file() {
            let lower = name.to_ascii_lowercase();
            if lower.ends_with(".pth")
                || (in_site_packages
                    && lower.ends_with(".py")
                    && lower != "_virtualenv.py"
                    && lower != "easy_install.py")
                || lower == "usercustomize.py"
            {
                out.push(path);
            }
        }
    }
}

/// Inspects an HTTP response body (or saved JSON payload) from `/license` or `/auth/license/*`
/// for the exact structural fingerprint of `_SC_LICENSE_PAYLOAD` produced by the Python startup
/// / `csdassrv.py` Tornado `RequestHandler._execute` monkey-patch:
///   1. Simultaneous presence of camelCase (`eulaAccepted`, `licenseInstalled`, `nodeEntryFound`)
///      AND snake_case (`eula_accepted`, `is_eula_accepted`, `depl_status`) in the same JSON object,
///   2. Hardcoded forged serials/keys (`FSRVMPTM99999999`, `FSR99999999`, `MOCK-HARDWARE-UUID-KEY`,
///      `MOCK_CRYPTOGRAPHIC_LICENSE_DATA`),
///   3. Hardcoded permissive limits (`"users": 999` or `"users":999` alongside `"edition": "MT"`).
pub fn inspect_das_license_response_payload(
    source_label: &str,
    payload_text: &str,
    findings: &mut Vec<Finding>,
) -> bool {
    let mut indicators = Vec::new();

    if payload_text.contains("FSRVMPTM99999999") || payload_text.contains("FSR99999999") {
        indicators.push("FORGED_SERIAL_FSRVMPTM99999999");
    }
    if payload_text.contains("MOCK-HARDWARE-UUID-KEY")
        || payload_text.contains("MOCK_CRYPTOGRAPHIC_LICENSE_DATA")
    {
        indicators.push("MOCK_HARDWARE_UUID_KEY");
    }
    if payload_text.contains("\"eulaAccepted\"")
        && payload_text.contains("\"is_eula_accepted\"")
        && payload_text.contains("\"nodeEntryFound\"")
        && payload_text.contains("\"depl_status\"")
    {
        indicators.push("DUAL_CAMEL_AND_SNAKE_CASE_SC_LICENSE_SCHEMA");
    }
    if (payload_text.contains("\"users\": 999") || payload_text.contains("\"users\":999"))
        && payload_text.contains("\"Fortinet EULA Accepted\"")
    {
        indicators.push("HARDCODED_999_USERS_MT_PERPETUAL_PAYLOAD");
    }

    if !indicators.is_empty() {
        findings.push(
            Finding::new(
                EngineId::WebAuthBackdoor,
                "CRITICAL_LIVE_DAS_TORNADO_LICENSE_INTERCEPT_ACTIVE",
                Severity::Critical,
                source_label.to_string(),
                format!(
                    "Active FortiSOAR DAS `/auth/license` Tornado `_execute` monkey-patch detected in `{}` (indicators: {})",
                    source_label,
                    indicators.join(", ")
                ),
            )
            .with_evidence("source", JsonValue::str(source_label))
            .with_evidence(
                "indicators",
                JsonValue::Array(indicators.iter().map(|s| JsonValue::str(*s)).collect()),
            ),
        );
        true
    } else {
        false
    }
}

/// Evaluates an arbitrary text snippet (`cyops-auth` script, `csdassrv.py`, `/license` JSON response,
/// Nginx config, or Django `settings.py`) submitted via the Web Portal or CLI quick-inspector.
pub fn inspect_text_snippet_for_cracks(
    filename_hint: &str,
    content: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let fname_lower = filename_hint.trim().to_ascii_lowercase();

    // 1. Check for DAS `/license` JSON response fingerprint
    inspect_das_license_response_payload(filename_hint, content, &mut findings);

    // 2. Check for Python DAS / startup hook / Tornado / `sys.modules` monkey-patch
    audit_python_das_license_monkeypatch(filename_hint, &fname_lower, content, &mut findings);

    // 3. If it looks like `csdassrv.py` or contains `class CSDASSRV`, verify entrypoint imports
    if fname_lower.ends_with("csdassrv.py") || content.contains("class CSDASSRV") {
        audit_cyops_entrypoint_imports(
            filename_hint,
            content,
            CSDASSRV_ALLOWED_IMPORTS,
            &mut findings,
        );
    } else if fname_lower.ends_with("licensemanager.py")
        || content.contains("def validate_license_before_deployment")
    {
        audit_cyops_entrypoint_imports(
            filename_hint,
            content,
            LICENSEMANAGER_ALLOWED_IMPORTS,
            &mut findings,
        );
    } else if fname_lower.ends_with("__init__.py") {
        audit_docstring_only_init_py(filename_hint, content, &mut findings);
    }

    // 4. Check for Django / Nginx auth backdoors
    if content.contains("MIDDLEWARE") || content.contains("AUTHENTICATION_BACKENDS") {
        audit_django_settings_and_wsgi(filename_hint, content, &mut findings);
    }
    if content.contains("is_superuser") || content.contains("request.META") {
        audit_django_magic_header_and_bypass(filename_hint, content, &mut findings);
    }
    if content.contains("proxy_pass") || content.contains("mirror ") {
        audit_nginx_config_text(filename_hint, content, &mut findings);
    }
    if content.contains("[HMAC]") || content.contains("hmac_ready") {
        audit_das_ini_content(filename_hint, content, &mut findings);
    }

    findings
}

/// Layer 6: Verifies `/opt/cyops-auth/bin/fdnclient.jar` and `/opt/cyops-auth/bin/` directory integrity.
/// Factory `bin/` contains strictly `fdnclient.jar`, which must be a valid ZIP/JAR archive (`PK\x03\x04`)
/// free of `#!` wrapper scripts or forged license literals (`FSRVMPTM99999999`, `MOCK-HARDWARE-UUID-KEY`).
fn audit_cyops_bin_fdnclient_jar(
    root: &Path,
    ca_root: &Path,
    findings: &mut Vec<Finding>,
) -> u64 {
    let mut checked = 0u64;
    let bin_dir = ca_root.join("bin");
    let Ok(entries) = fs::read_dir(&bin_dir) else {
        return 0;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        checked += 1;
        let fname = entry.file_name().to_string_lossy().into_owned();
        let rel_label = display_under_root(root, &path);

        if fname != "fdnclient.jar" {
            findings.push(
                Finding::new(
                    EngineId::WebAuthBackdoor,
                    "CRITICAL_CYOPS_FDNCLIENT_JAR_TAMPERED",
                    Severity::Critical,
                    rel_label.clone(),
                    format!(
                        "Unauthorized binary/script `{}` dropped in `cyops-auth/bin/` alongside `fdnclient.jar`",
                        rel_label
                    ),
                )
                .with_evidence("file", JsonValue::str(&rel_label)),
            );
            continue;
        }

        if let Ok(bytes) = fs::read(&path) {
            let is_zip_jar = bytes.len() >= 4 && &bytes[0..4] == b"PK\x03\x04";
            let has_forged_marker = bytes
                .windows(16)
                .any(|w| w == b"FSRVMPTM99999999" || w == b"MOCK-HARDWARE-UU");

            if !is_zip_jar || has_forged_marker {
                let reason = if !is_zip_jar {
                    "missing_zip_jar_pk_magic_header_replaced_with_script_or_stub"
                } else {
                    "contains_forged_license_serial_marker_inside_jar"
                };
                findings.push(
                    Finding::new(
                        EngineId::WebAuthBackdoor,
                        "CRITICAL_CYOPS_FDNCLIENT_JAR_TAMPERED",
                        Severity::Critical,
                        rel_label.clone(),
                        format!(
                            "FortiSOAR FortiGuard client archive `{}` is tampered or replaced (`{}`)",
                            rel_label, reason
                        ),
                    )
                    .with_evidence("file", JsonValue::str(&rel_label))
                    .with_evidence("tamper_reason", JsonValue::str(reason)),
                );
            }
        }
    }

    checked
}

/// Layer 7: Audits `/opt/cyops-auth/utilities/das.ini` for inter-service HMAC authentication disablement
/// (`hmac_ready = False`) or key path redirection to volatile `/tmp` / `/dev/shm` directories.
fn audit_cyops_das_ini(root: &Path, ca_root: &Path, findings: &mut Vec<Finding>) -> u64 {
    let ini_path = ca_root.join("utilities/das.ini");
    let Ok(content) = fs::read_to_string(&ini_path) else {
        return 0;
    };
    let rel_label = display_under_root(root, &ini_path);
    audit_das_ini_content(&rel_label, &content, findings);
    1
}

fn audit_das_ini_content(file_label: &str, content: &str, findings: &mut Vec<Finding>) {
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_hash_comment(raw_line).trim();
        if line.is_empty() || line.starts_with('[') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        let val_lower = val.to_ascii_lowercase();

        if key == "hmac_ready"
            && (val_lower == "false" || val_lower == "0" || val_lower == "no" || val_lower == "off")
        {
            findings.push(
                Finding::new(
                    EngineId::WebAuthBackdoor,
                    "CRITICAL_CYOPS_DAS_INI_AUTH_BYPASS",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!(
                        "FortiSOAR inter-service HMAC authentication disabled (`hmac_ready = {}`) in `{}`",
                        val, file_label
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("line", JsonValue::Uint(line_no as u64))
                .with_evidence("directive", JsonValue::str(line)),
            );
        } else if (key.contains("key") || key.contains("cert") || key.contains("path"))
            && (val_lower.starts_with("/tmp/")
                || val_lower.starts_with("/var/tmp/")
                || val_lower.starts_with("/dev/shm/"))
        {
            findings.push(
                Finding::new(
                    EngineId::WebAuthBackdoor,
                    "CRITICAL_CYOPS_DAS_INI_AUTH_BYPASS",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!(
                        "FortiSOAR cryptographic key/certificate path (`{} = {}`) redirected to volatile directory in `{}`",
                        k.trim(),
                        val,
                        file_label
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("line", JsonValue::Uint(line_no as u64))
                .with_evidence("directive", JsonValue::str(line)),
            );
        }
    }
}

/// Layer 8: Audits `/opt/cyops-auth/.env/bin/python*` and `activate` / `pyvenv.cfg` for
/// interpreter wrapper script hijacking (`#!` script replacing the ELF binary) or `PYTHONSTARTUP` / `LD_PRELOAD` injection.
fn audit_cyops_venv_interpreter_and_activate(
    root: &Path,
    ca_root: &Path,
    findings: &mut Vec<Finding>,
) -> u64 {
    let mut checked = 0u64;
    for py_bin_rel in [
        ".env/bin/python",
        ".env/bin/python3",
        ".env/bin/python3.9",
    ] {
        let bin_path = ca_root.join(py_bin_rel);
        let Ok(bytes) = fs::read(&bin_path) else {
            continue;
        };
        checked += 1;
        // A factory virtualenv python binary is ALWAYS an ELF executable (`\x7fELF`), never a `#!` wrapper script
        if bytes.starts_with(b"#!")
            || (bytes.len() >= 4 && &bytes[0..4] != b"\x7fELF")
        {
            let rel_label = display_under_root(root, &bin_path);
            findings.push(
                Finding::new(
                    EngineId::WebAuthBackdoor,
                    "CRITICAL_CYOPS_VENV_INTERPRETER_HIJACK",
                    Severity::Critical,
                    rel_label.clone(),
                    format!(
                        "FortiSOAR virtualenv Python interpreter `{}` replaced with a non-ELF wrapper script or stub",
                        rel_label
                    ),
                )
                .with_evidence("file", JsonValue::str(&rel_label)),
            );
        }
    }

    for cfg_rel in [
        ".env/bin/activate",
        ".env/bin/activate.csh",
        ".env/bin/activate.fish",
        ".env/pyvenv.cfg",
    ] {
        let cfg_path = ca_root.join(cfg_rel);
        let Ok(content) = fs::read_to_string(&cfg_path) else {
            continue;
        };
        checked += 1;
        let rel_label = display_under_root(root, &cfg_path);
        for (idx, raw_line) in content.lines().enumerate() {
            let line_no = idx + 1;
            let trimmed = strip_hash_comment(raw_line).trim();
            if trimmed.contains("PYTHONSTARTUP")
                || trimmed.contains("LD_PRELOAD")
                || trimmed.contains("/dev/shm/")
                || trimmed.contains("FSRVMPTM99999999")
            {
                findings.push(
                    Finding::new(
                        EngineId::WebAuthBackdoor,
                        "CRITICAL_CYOPS_VENV_INTERPRETER_HIJACK",
                        Severity::Critical,
                        format!("{}:{}", rel_label, line_no),
                        format!(
                            "Unauthorized startup hook environment variable (`{}`) injected into `{}`",
                            trimmed, rel_label
                        ),
                    )
                    .with_evidence("file", JsonValue::str(&rel_label))
                    .with_evidence("line", JsonValue::Uint(line_no as u64))
                    .with_evidence("statement", JsonValue::str(trimmed)),
                );
            }
        }
    }

    checked
}

/// Layer 9: Audits `utilities/ha/listener.py`, `validationutils/custompwdvalidator.py`, and
/// `utilities/licensemanager.py` for logic-level bypasses (e.g., patching `check_if_supported_cmd`
/// to unconditionally return `True` for cluster RCE, or patching `validate_license_before_deployment`).
fn audit_cyops_utility_logic_tamper(
    file_label: &str,
    rel_subpath: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    if rel_subpath == "utilities/ha/listener.py"
        && !content.contains("LIST_OF_SUPPORTED_CMDS")
    {
        findings.push(
            Finding::new(
                EngineId::WebAuthBackdoor,
                "CRITICAL_CYOPS_UTILITY_SCRIPT_TAMPERED",
                Severity::Critical,
                file_label.to_string(),
                format!(
                    "Cluster command whitelist check (`LIST_OF_SUPPORTED_CMDS`) removed from `{}` allowing arbitrary cluster command execution",
                    file_label
                ),
            )
            .with_evidence("file", JsonValue::str(file_label)),
        );
    }

    if rel_subpath == "utilities/licensemanager.py"
        && (content.contains("return 0\n") || content.contains("return True"))
        && !content.contains("CSLicenseManager().validate_license_before_deployment()")
    {
        findings.push(
            Finding::new(
                EngineId::WebAuthBackdoor,
                "CRITICAL_CYOPS_UTILITY_SCRIPT_TAMPERED",
                Severity::Critical,
                file_label.to_string(),
                format!(
                    "Core license deployment call (`CSLicenseManager().validate_license_before_deployment()`) stripped or short-circuited in `{}`",
                    file_label
                ),
            )
            .with_evidence("file", JsonValue::str(file_label)),
        );
    }
}

/// Layer 10: Audits `/opt/cyops-auth/sql/das_prod.sql` and `/opt/cyops-auth/sql/migration/*.sql`
/// for unauthorized admin user insertions, forged license rows, or `COPY ... PROGRAM` execution.
fn audit_cyops_sql_seed_and_migrations(
    root: &Path,
    ca_root: &Path,
    findings: &mut Vec<Finding>,
) -> u64 {
    let mut checked = 0u64;
    let mut sql_files = Vec::new();
    let seed_sql = ca_root.join("sql/das_prod.sql");
    if seed_sql.is_file() {
        sql_files.push(seed_sql);
    }
    let mig_dir = ca_root.join("sql/migration");
    if let Ok(entries) = fs::read_dir(&mig_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() && p.extension().is_some_and(|e| e == "sql") {
                sql_files.push(p);
            }
        }
    }

    for sql_path in sql_files {
        let Ok(content) = fs::read_to_string(&sql_path) else {
            continue;
        };
        checked += 1;
        let rel_label = display_under_root(root, &sql_path);

        for (idx, raw_line) in content.lines().enumerate() {
            let line_no = idx + 1;
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with("--") || trimmed.starts_with("/*") {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase();

            // Factory `das_prod.sql` only inserts `csadmin` (215) and `6f3626c1-0da7-4b44-8d5e-43750f780a47` (216) into `users`.
            let is_rogue_user_insert = lower.starts_with("insert into users")
                && !trimmed.contains("'csadmin'")
                && !trimmed.contains("'6f3626c1-0da7-4b44-8d5e-43750f780a47'");

            let is_forged_lic_sql = trimmed.contains("FSRVMPTM99999999")
                || trimmed.contains("FSR99999999")
                || trimmed.contains("MOCK-HARDWARE-UUID-KEY")
                || lower.contains("insert into license")
                || (lower.contains("copy ") && lower.contains(" program "));

            if is_rogue_user_insert || is_forged_lic_sql {
                findings.push(
                    Finding::new(
                        EngineId::WebAuthBackdoor,
                        "CRITICAL_CYOPS_SQL_SEED_OR_MIGRATION_TAMPER",
                        Severity::Critical,
                        format!("{}:{}", rel_label, line_no),
                        format!(
                            "Unauthorized user/license SQL injection (`{}`) detected in FortiSOAR database seed/migration `{}`",
                            trimmed, rel_label
                        ),
                    )
                    .with_evidence("file", JsonValue::str(&rel_label))
                    .with_evidence("line", JsonValue::Uint(line_no as u64))
                    .with_evidence("sql_statement", JsonValue::str(trimmed)),
                );
            }
        }
    }

    checked
}

/// Layer 11: Verifies that critical compiled Cython `.so` modules inside `/opt/cyops-auth`
/// (`handlerworkers/license.so`, `handlerworkers/fdnclient.so`, `handlers/licensehandler.so`,
/// `utilities/license/entitlements.so`, `dashmac/hmacauthorizer.so`) have not been replaced
/// by non-ELF scripts, Cython-less stub libraries, or binaries containing forged license serials.
fn audit_cyops_cython_so_binaries(
    root: &Path,
    ca_root: &Path,
    required_so_modules: &[String],
    findings: &mut Vec<Finding>,
) -> u64 {
    let mut checked = 0u64;
    for so_rel in required_so_modules {
        let so_path = ca_root.join(so_rel);
        let Ok(bytes) = fs::read(&so_path) else {
            continue;
        };
        checked += 1;
        let rel_label = display_under_root(root, &so_path);

        let is_elf = bytes.len() >= 4 && &bytes[0..4] == b"\x7fELF";
        let has_forged_serial = bytes
            .windows(16)
            .any(|w| w == b"FSRVMPTM99999999" || w == b"MOCK-HARDWARE-UU");
        // Real Fortinet Cython `.so` files (>4KB) always contain `__pyx_` Cython runtime symbols
        let missing_cython_markers = bytes.len() >= 4096
            && !bytes.windows(6).any(|w| w == b"__pyx_");

        if !is_elf || has_forged_serial || missing_cython_markers {
            let reason = if !is_elf {
                "non_elf_file_replacing_cython_so"
            } else if has_forged_serial {
                "forged_license_serial_embedded_in_so"
            } else {
                "stub_shared_library_missing_cython_pyx_abi_markers"
            };
            findings.push(
                Finding::new(
                    EngineId::WebAuthBackdoor,
                    "CRITICAL_CYOPS_CYTHON_SO_BINARY_REPLACED",
                    Severity::Critical,
                    rel_label.clone(),
                    format!(
                        "Compiled FortiSOAR Cython module `{}` was replaced or patched (`{}`)",
                        rel_label, reason
                    ),
                )
                .with_evidence("file", JsonValue::str(&rel_label))
                .with_evidence("reason", JsonValue::str(reason)),
            );
        }
    }

    checked
}
