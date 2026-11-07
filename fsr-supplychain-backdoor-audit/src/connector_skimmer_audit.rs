//! Engine 1: SOAR Connector & Playbook AST/Token Credential-Skimmer & Obfuscation Scanner.
//!
//! Performs read-only lexical tokenization, connector manifest (`info.json`) domain binding,
//! and intra-procedural taint analysis across `/opt/cyops-integrations/integrations/connectors/**`,
//! `/opt/cyops-workflow/**`, and exported Playbook / Jinja2 templates to detect:
//!   a) Credential Skimming (`CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER`): Tainted `config`
//!      (vault-decrypted API keys/passwords) flowing into `os.system`, `subprocess`, `Popen`,
//!      `eval`, `exec`, `compile`, `marshal.loads`, `__import__`, `pickle.loads`, `pty.spawn`,
//!      unauthorized hardcoded external IPs/domains/webhooks, or `/tmp`, `/dev/shm`, `/var/log`
//!      drop files.
//!   b) Obfuscated SOAR Payloads & Jinja2 Sandbox Escapes (`CRITICAL_OBFUSCATED_SOAR_PAYLOAD`):
//!      `base64.b64decode`, `zlib.decompress`, `codecs.decode(..., 'rot_13')`, `bytes.fromhex`,
//!      or dense `\xNN` byte strings chained with `exec`, `eval`, `compile`, `getattr`, or
//!      Jinja2 `__subclasses__` / `__globals__` / `__builtins__` gadget chains.

use std::collections::BTreeSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use fsr_clone_cluster_audit::json_parser::{json_as_str, json_get, parse_json_str};
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};

/// Dangerous command/code execution sinks inside SOAR connectors.
const EXEC_SINKS: &[&str] = &[
    "os.system",
    "os.popen",
    "os.execv",
    "os.execve",
    "os.execvp",
    "subprocess.Popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "Popen",
    "eval",
    "exec",
    "compile",
    "marshal.loads",
    "__import__",
    "pickle.loads",
    "pty.spawn",
];

/// HTTP / network client calls capable of exfiltrating `config` secrets.
const NETWORK_SINKS: &[&str] = &[
    "requests.post",
    "requests.put",
    "requests.get",
    "requests.patch",
    "requests.request",
    "Session.post",
    "session.post",
    "urllib.request.urlopen",
    " urllib.request.Request",
    "urlopen",
    "httpx.post",
    "httpx.get",
    "aiohttp.ClientSession",
    "socket.create_connection",
];

/// Decoding / decompression primitives used to conceal supply-chain payloads.
const DECODE_PRIMITIVES: &[&str] = &[
    "b64decode",
    "base64.b64decode",
    "urlsafe_b64decode",
    "base64.urlsafe_b64decode",
    "zlib.decompress",
    "gzip.decompress",
    "bz2.decompress",
    "lzma.decompress",
    "bytes.fromhex",
    "bytearray.fromhex",
    "binascii.unhexlify",
];

/// Parsed connector `info.json` allowlist context.
#[derive(Debug, Clone, Default)]
pub struct ConnectorManifestContext {
    pub connector_name: String,
    pub publisher: String,
    pub version: String,
    pub allowed_domain_keywords: BTreeSet<String>,
}

/// Lexical token representation of a Python logical line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PyLexToken {
    Ident(String),
    DottedIdent(String),
    StringLit { value: String, hex_escapes: usize },
    Symbol(char),
}

/// Logical statement assembled from Python physical lines (respecting括号 continuation).
#[derive(Debug, Clone)]
struct PyStatement {
    line_no: usize,
    indent: usize,
    raw_text: String,
    tokens: Vec<PyLexToken>,
}

/// Output of Engine 1 (`connector_skimmer_audit`).
pub struct ConnectorSkimmerAuditResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 1 across FortiSOAR connector and workflow/playbook directories under `root`.
pub fn run_connector_skimmer_audit(
    root: &Path,
    extra_playbook_paths: &[PathBuf],
) -> ConnectorSkimmerAuditResult {
    let mut findings = Vec::new();
    let mut connectors_scanned = 0u64;
    let mut python_files_scanned = 0u64;
    let mut playbooks_scanned = 0u64;

    // 1. Discover connector directories (`info.json` roots) under `/opt/cyops-integrations` & `/opt/cyops*`
    let mut connector_roots = Vec::new();
    for rel in [
        "opt/cyops-integrations/integrations/connectors",
        "opt/cyops/integrations/connectors",
        "opt/cyops-integrations",
    ] {
        let base = join_rooted(root, rel);
        if base.is_dir() {
            discover_connector_dirs(&base, 5, &mut connector_roots);
        }
    }
    connector_roots.sort();
    connector_roots.dedup();

    let mut visited_py: BTreeSet<PathBuf> = BTreeSet::new();

    for conn_dir in &connector_roots {
        connectors_scanned += 1;
        let ctx = load_connector_manifest_context(conn_dir);
        let mut py_files = Vec::new();
        collect_files_with_exts(conn_dir, &["py"], 5, &mut py_files);
        py_files.sort();

        for py_path in py_files {
            if !visited_py.insert(py_path.clone()) {
                continue;
            }
            if let Ok(src) = fs::read_to_string(&py_path) {
                python_files_scanned += 1;
                let rel_label = display_under_root(root, &py_path);
                analyze_connector_python_source(&rel_label, &src, &ctx, &mut findings);
            }
        }
    }

    // 2. Scan workflow Python scripts & exported Playbooks / Jinja2 templates
    let mut template_and_workflow_files: Vec<PathBuf> = extra_playbook_paths.to_vec();
    for rel in ["opt/cyops-workflow", "opt/cyops-integrations"] {
        let base = join_rooted(root, rel);
        if base.is_dir() {
            collect_files_with_exts(
                &base,
                &["py", "json", "jinja", "jinja2", "j2", "yml", "yaml"],
                6,
                &mut template_and_workflow_files,
            );
        }
    }
    template_and_workflow_files.sort();
    template_and_workflow_files.dedup();

    let empty_ctx = ConnectorManifestContext::default();
    for path in template_and_workflow_files {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if ext == "py" {
            if visited_py.insert(path.clone()) {
                if let Ok(src) = fs::read_to_string(&path) {
                    python_files_scanned += 1;
                    let rel_label = display_under_root(root, &path);
                    analyze_connector_python_source(&rel_label, &src, &empty_ctx, &mut findings);
                }
            }
            continue;
        }

        // Skip `info.json` / `package.json` metadata files; inspect Playbook / workflow / Jinja2 files
        let fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if fname == "info.json" || fname == "package.json" || fname == "tsconfig.json" {
            continue;
        }
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if meta.len() > 4 * 1024 * 1024 {
            continue;
        }
        if let Ok(text) = fs::read_to_string(&path) {
            playbooks_scanned += 1;
            let rel_label = display_under_root(root, &path);
            analyze_playbook_or_jinja_template(&rel_label, &text, &mut findings);
        }
    }

    let summary = JsonValue::OrderedObject(vec![
        (
            "connectors_scanned".to_string(),
            JsonValue::Uint(connectors_scanned),
        ),
        (
            "python_files_scanned".to_string(),
            JsonValue::Uint(python_files_scanned),
        ),
        (
            "playbooks_and_templates_scanned".to_string(),
            JsonValue::Uint(playbooks_scanned),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    ConnectorSkimmerAuditResult { summary, findings }
}

/// Parses `info.json` inside a connector folder to bind its legitimate vendor/API domain keywords.
pub fn load_connector_manifest_context(conn_dir: &Path) -> ConnectorManifestContext {
    let mut ctx = ConnectorManifestContext::default();
    if let Some(dir_name) = conn_dir.file_name().and_then(|n| n.to_str()) {
        for part in dir_name.split(['-', '_']) {
            let clean = part.trim().to_ascii_lowercase();
            if clean.len() >= 4 && clean != "connector" && clean != "fortisoar" {
                ctx.allowed_domain_keywords.insert(clean);
            }
        }
    }

    let info_path = conn_dir.join("info.json");
    let Ok(info_text) = fs::read_to_string(&info_path) else {
        return ctx;
    };
    let Ok(doc) = parse_json_str(&info_text) else {
        return ctx;
    };

    if let Some(name) = json_get(&doc, "name").and_then(json_as_str) {
        ctx.connector_name = name.to_string();
        for tok in name.split(['-', '_', ' ']) {
            let low = tok.to_ascii_lowercase();
            if low.len() >= 4 {
                ctx.allowed_domain_keywords.insert(low);
            }
        }
    }
    if let Some(pub_str) = json_get(&doc, "publisher").and_then(json_as_str) {
        ctx.publisher = pub_str.to_string();
        let low = pub_str.to_ascii_lowercase();
        if low.len() >= 4 {
            ctx.allowed_domain_keywords.insert(low);
        }
    }
    if let Some(ver) = json_get(&doc, "version").and_then(json_as_str) {
        ctx.version = ver.to_string();
    }
    if let Some(help_url) = json_get(&doc, "help_online").and_then(json_as_str) {
        if let Some(host) = extract_url_host(help_url) {
            ctx.allowed_domain_keywords.insert(host);
        }
    }

    // Also harvest any default URL hosts declared inside `info.json`
    for word in info_text.split('"') {
        if (word.starts_with("https://") || word.starts_with("http://"))
            && !word.contains("docs.fortinet.com")
        {
            if let Some(host) = extract_url_host(word) {
                ctx.allowed_domain_keywords.insert(host);
            }
        }
    }

    ctx
}

/// Tokenizes and analyzes a Python connector source file for `config` credential skimming
/// and obfuscated payload execution.
pub fn analyze_connector_python_source(
    file_label: &str,
    source: &str,
    ctx: &ConnectorManifestContext,
    findings: &mut Vec<Finding>,
) {
    let statements = parse_python_statements(source);

    // Track current `def` scope indentation and tainted variables (`config`, decoded blobs)
    let mut current_fn_indent: Option<usize> = None;
    let mut current_fn_name = String::from("<module>");
    let mut tainted_config_vars: BTreeSet<String> = initial_config_taint_set();
    let mut decoded_payload_vars: BTreeSet<String> = BTreeSet::new();

    for stmt in &statements {
        // Reset function-local taint sets when indentation exits the previous `def` block
        if let Some(fn_ind) = current_fn_indent {
            if stmt.indent <= fn_ind && !is_def_statement(&stmt.tokens) {
                current_fn_indent = None;
                current_fn_name = "<module>".to_string();
                tainted_config_vars = initial_config_taint_set();
                decoded_payload_vars.clear();
            }
        }

        if let Some((fn_name, params)) = parse_def_signature(&stmt.tokens) {
            current_fn_indent = Some(stmt.indent);
            current_fn_name = fn_name;
            tainted_config_vars = initial_config_taint_set();
            decoded_payload_vars.clear();
            for p in params {
                let low = p.to_ascii_lowercase();
                if low == "config"
                    || low.contains("config")
                    || low.contains("cred")
                    || low.contains("secret")
                    || low.contains("password")
                    || low.contains("token")
                    || low.contains("api_key")
                {
                    tainted_config_vars.insert(p);
                }
            }
            continue;
        }

        let stmt_idents = collect_statement_identifiers(&stmt.tokens);
        let stmt_strings = collect_statement_strings(&stmt.tokens);
        let lhs_var = extract_assignment_lhs(&stmt.tokens);

        let references_tainted_config = stmt_idents
            .iter()
            .any(|id| is_identifier_in_set(id, &tainted_config_vars));

        let has_decode_call = stmt_idents.iter().any(|id| {
            DECODE_PRIMITIVES
                .iter()
                .any(|dp| id == dp || id.ends_with(&format!(".{}", dp)))
        }) || is_rot13_or_hex_codecs_call(&stmt_idents, &stmt_strings)
            || stmt
                .tokens
                .iter()
                .any(|t| matches!(t, PyLexToken::StringLit { hex_escapes, .. } if *hex_escapes >= 12));

        // Propagate taint across assignments (`secret_hdr = config.get('api_key')`, `blob = base64.b64decode(...)`)
        if let Some(ref lhs) = lhs_var {
            if references_tainted_config {
                tainted_config_vars.insert(lhs.clone());
            }
            if has_decode_call {
                decoded_payload_vars.insert(lhs.clone());
            }
        }

        let references_decoded_var = has_decode_call
            || stmt_idents
                .iter()
                .any(|id| is_identifier_in_set(id, &decoded_payload_vars));

        // --------------------------------------------------------------------
        // Check 1b: Obfuscated decode/decompress chained into `exec`/`eval`/`compile`/`getattr`/`__import__`
        // --------------------------------------------------------------------
        let dynamic_exec_sink = stmt_idents.iter().find(|id| {
            matches!(
                id.as_str(),
                "exec"
                    | "eval"
                    | "compile"
                    | "getattr"
                    | "__import__"
                    | "builtins.exec"
                    | "builtins.eval"
                    | "marshal.loads"
            )
        });

        if references_decoded_var {
            if let Some(sink) = dynamic_exec_sink {
                findings.push(
                    Finding::new(
                        EngineId::ConnectorSkimmerAudit,
                        "CRITICAL_OBFUSCATED_SOAR_PAYLOAD",
                        Severity::Critical,
                        format!("{}:{}", file_label, stmt.line_no),
                        format!(
                            "Obfuscated payload decode/decompression chained into `{}` inside function `{}` ({}:{})",
                            sink, current_fn_name, file_label, stmt.line_no
                        ),
                    )
                    .with_evidence("file", JsonValue::str(file_label))
                    .with_evidence("line", JsonValue::Uint(stmt.line_no as u64))
                    .with_evidence("function", JsonValue::str(&current_fn_name))
                    .with_evidence("dynamic_sink", JsonValue::str(sink.as_str()))
                    .with_evidence("statement_preview", JsonValue::str(truncate_line(&stmt.raw_text))),
                );
                continue;
            }
        }

        // --------------------------------------------------------------------
        // Check 1a-1: `config` / credentials passed to dangerous OS/code execution sink
        //             OR unconditional high-risk deserialization/shell spawn (`marshal.loads`, `pickle.loads`, `pty.spawn`)
        // --------------------------------------------------------------------
        if let Some(exec_sink) = stmt_idents
            .iter()
            .find(|id| EXEC_SINKS.contains(&id.as_str()))
        {
            let unconditional_backdoor_sink = matches!(
                exec_sink.as_str(),
                "marshal.loads" | "pickle.loads" | "pty.spawn"
            );
            if references_tainted_config || unconditional_backdoor_sink {
                findings.push(
                    Finding::new(
                        EngineId::ConnectorSkimmerAudit,
                        "CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER",
                        Severity::Critical,
                        format!("{}:{}", file_label, stmt.line_no),
                        format!(
                            "SOAR connector `{}` passes vault-decrypted `config`/state into dangerous execution sink `{}` in `{}` ({}:{})",
                            if ctx.connector_name.is_empty() { "unknown" } else { &ctx.connector_name },
                            exec_sink,
                            current_fn_name,
                            file_label,
                            stmt.line_no
                        ),
                    )
                    .with_evidence("file", JsonValue::str(file_label))
                    .with_evidence("line", JsonValue::Uint(stmt.line_no as u64))
                    .with_evidence("function", JsonValue::str(&current_fn_name))
                    .with_evidence("sink", JsonValue::str(exec_sink.as_str()))
                    .with_evidence("tainted_config_flow", JsonValue::Bool(references_tainted_config))
                    .with_evidence("statement_preview", JsonValue::str(truncate_line(&stmt.raw_text))),
                );
            }
        }

        // --------------------------------------------------------------------
        // Check 1a-2: `config` / credentials exfiltrated to hardcoded external IP / unauthorized domain / webhook
        // --------------------------------------------------------------------
        let has_net_call = stmt_idents.iter().any(|id| {
            NETWORK_SINKS
                .iter()
                .any(|ns| id == ns || id.ends_with(".post") || id.ends_with(".put") || id == "urlopen")
        });

        if references_tainted_config && (has_net_call || contains_url_literal(&stmt_strings)) {
            for lit in &stmt_strings {
                if let Some(exfil_reason) = classify_unauthorized_exfil_endpoint(lit, ctx) {
                    findings.push(
                        Finding::new(
                            EngineId::ConnectorSkimmerAudit,
                            "CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER",
                            Severity::Critical,
                            format!("{}:{}", file_label, stmt.line_no),
                            format!(
                                "Credential skimmer in `{}` (`{}`): vault `config` sent to unauthorized external target `{}` ({})",
                                file_label, current_fn_name, lit, exfil_reason
                            ),
                        )
                        .with_evidence("file", JsonValue::str(file_label))
                        .with_evidence("line", JsonValue::Uint(stmt.line_no as u64))
                        .with_evidence("function", JsonValue::str(&current_fn_name))
                        .with_evidence("exfil_endpoint", JsonValue::str(lit.as_str()))
                        .with_evidence("reason", JsonValue::str(exfil_reason))
                        .with_evidence("statement_preview", JsonValue::str(truncate_line(&stmt.raw_text))),
                    );
                }
            }
        }

        // --------------------------------------------------------------------
        // Check 1a-3: `config` / credentials written to `/tmp`, `/dev/shm`, `/var/tmp`, `/var/log`, or hidden dotfile
        // --------------------------------------------------------------------
        for lit in &stmt_strings {
            if is_suspicious_local_drop_path(lit)
                && (references_tainted_config
                    || stmt_idents.iter().any(|i| i == "open" || i.ends_with(".write_text")))
            {
                findings.push(
                    Finding::new(
                        EngineId::ConnectorSkimmerAudit,
                        "CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER",
                        Severity::Critical,
                        format!("{}:{}", file_label, stmt.line_no),
                        format!(
                            "Connector function `{}` stages credentials/data into covert local drop path `{}` ({}:{})",
                            current_fn_name, lit, file_label, stmt.line_no
                        ),
                    )
                    .with_evidence("file", JsonValue::str(file_label))
                    .with_evidence("line", JsonValue::Uint(stmt.line_no as u64))
                    .with_evidence("drop_path", JsonValue::str(lit.as_str()))
                    .with_evidence("tainted_config_flow", JsonValue::Bool(references_tainted_config)),
                );
            }
        }
    }
}

/// Scans Playbook JSON exports and Jinja2 templates for SSTI gadget chains and obfuscated payloads.
pub fn analyze_playbook_or_jinja_template(
    file_label: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let lower = raw_line.to_ascii_lowercase();

        // 1. Jinja2 SSTI / Python sandbox escape dunder traversal (`{{ ... __subclasses__ ... }}`)
        let has_jinja_dunder_escape = lower.contains("__subclasses__")
            || lower.contains("__globals__")
            || lower.contains("__builtins__")
            || (lower.contains("__mro__") && lower.contains("__class__"))
            || (lower.contains("lipsum") && lower.contains("popen"))
            || (lower.contains("cycler") && lower.contains("init"));

        if has_jinja_dunder_escape {
            findings.push(
                Finding::new(
                    EngineId::ConnectorSkimmerAudit,
                    "CRITICAL_OBFUSCATED_SOAR_PAYLOAD",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!(
                        "Jinja2 Python sandbox-escape / SSTI backdoor gadget (`__globals__`/`__subclasses__`) in Playbook template {}:{}",
                        file_label, line_no
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("line", JsonValue::Uint(line_no as u64))
                .with_evidence("snippet", JsonValue::str(truncate_line(raw_line))),
            );
            continue;
        }

        // 2. Obfuscated decode + exec/eval/getattr inside Playbook expressions
        let has_decode = lower.contains("b64decode")
            || lower.contains("zlib.decompress")
            || lower.contains("rot_13")
            || lower.contains("rot13")
            || lower.contains("fromhex");
        let has_exec = lower.contains("exec(")
            || lower.contains("eval(")
            || lower.contains("getattr(")
            || lower.contains("__import__(")
            || lower.contains("os.popen(");

        if has_decode && has_exec {
            findings.push(
                Finding::new(
                    EngineId::ConnectorSkimmerAudit,
                    "CRITICAL_OBFUSCATED_SOAR_PAYLOAD",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!(
                        "Obfuscated decode-and-execute expression in Playbook/template {}:{}",
                        file_label, line_no
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("line", JsonValue::Uint(line_no as u64))
                .with_evidence("snippet", JsonValue::str(truncate_line(raw_line))),
            );
        }
    }
}

fn initial_config_taint_set() -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    for v in [
        "config",
        "self.config",
        "connector_config",
        "credentials",
    ] {
        s.insert(v.to_string());
    }
    s
}

fn is_identifier_in_set(ident: &str, set: &BTreeSet<String>) -> bool {
    if set.contains(ident) {
        return true;
    }
    // Match `config.get`, `config[...]`, `self.config.get`
    if let Some((root_var, _rest)) = ident.split_once('.') {
        if set.contains(root_var) {
            return true;
        }
    }
    if ident.starts_with("self.config.") && set.contains("self.config") {
        return true;
    }
    false
}

fn is_rot13_or_hex_codecs_call(idents: &[String], strings: &[String]) -> bool {
    let has_codecs = idents
        .iter()
        .any(|i| i == "codecs.decode" || i.ends_with(".decode"));
    let has_cipher_enc = strings.iter().any(|s| {
        let l = s.to_ascii_lowercase();
        l == "rot_13" || l == "rot13" || l == "hex_codec"
    });
    has_codecs && has_cipher_enc
}

fn classify_unauthorized_exfil_endpoint(
    lit: &str,
    ctx: &ConnectorManifestContext,
) -> Option<&'static str> {
    let trimmed = lit.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return None;
    }
    let host = extract_url_host(trimmed)?;
    if host == "localhost" || host == "127.0.0.1" || host.ends_with(".example.com") {
        return None;
    }

    // 1. Known C2 / webhook drop services
    for bad in [
        "discord.com",
        "discordapp.com",
        "api.telegram.org",
        "webhook.site",
        "requestbin",
        "pipedream.net",
        "ngrok.io",
        "ngrok-free.app",
        "oastify.com",
        "interact.sh",
        "burpcollaborator.net",
        "pastebin.com",
        "transfer.sh",
    ] {
        if host == bad || host.ends_with(&format!(".{}", bad)) {
            return Some("known external webhook/exfiltration drop service");
        }
    }

    // 2. Hardcoded raw IPv4 literal URL (`https://185.x.x.x/...`)
    if host.parse::<Ipv4Addr>().is_ok() {
        return Some("hardcoded raw IPv4 address endpoint");
    }

    // 3. Domain mismatch against `info.json` declared vendor/connector domains
    if !ctx.allowed_domain_keywords.is_empty() {
        let matches_vendor = ctx
            .allowed_domain_keywords
            .iter()
            .any(|kw| host.contains(kw.as_str()))
            || host.ends_with(".fortinet.com")
            || host.ends_with(".fortiguard.net");
        if !matches_vendor {
            return Some("domain outside connector info.json vendor allowlist");
        }
    }

    None
}

fn is_suspicious_local_drop_path(lit: &str) -> bool {
    let s = lit.trim();
    if s.starts_with("/dev/shm/")
        || s.starts_with("/tmp/.")
        || s.starts_with("/var/tmp/.")
        || s.starts_with("/var/log/.")
    {
        return true;
    }
    if (s.starts_with("/tmp/") || s.starts_with("/var/tmp/"))
        && (s.ends_with(".txt")
            || s.ends_with(".json")
            || s.ends_with(".log")
            || s.ends_with(".dat")
            || s.contains("cred")
            || s.contains("dump")
            || s.contains("skim"))
    {
        return true;
    }
    false
}

fn contains_url_literal(strings: &[String]) -> bool {
    strings
        .iter()
        .any(|s| s.starts_with("http://") || s.starts_with("https://"))
}

fn extract_url_host(url: &str) -> Option<String> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = host_port.split(':').next()?.trim().to_ascii_lowercase();
    if host.is_empty() || host.contains('{') {
        None
    } else {
        Some(host)
    }
}

/// Groups physical Python lines into bracket-balanced logical statements and tokenizes each.
fn parse_python_statements(src: &str) -> Vec<PyStatement> {
    let mut out = Vec::new();
    let mut cur_buf = String::new();
    let mut start_line = 1usize;
    let mut start_indent = 0usize;
    let mut paren_depth = 0i32;

    for (idx, raw_line) in src.lines().enumerate() {
        let code_only = strip_python_comment(raw_line);
        if cur_buf.is_empty() {
            if code_only.trim().is_empty() {
                continue;
            }
            start_line = idx + 1;
            start_indent = count_indent(raw_line);
        } else {
            cur_buf.push(' ');
        }

        cur_buf.push_str(code_only.trim());
        paren_depth += net_bracket_delta(code_only);

        let explicit_cont = code_only.trim_end().ends_with('\\');
        if paren_depth <= 0 && !explicit_cont {
            paren_depth = 0;
            // Split semicolon-separated inline statements (`a = b64decode(...); exec(a)`)
            for sub in split_top_level_semicolons(&cur_buf) {
                let tokens = lex_python_statement(sub);
                if !tokens.is_empty() {
                    out.push(PyStatement {
                        line_no: start_line,
                        indent: start_indent,
                        raw_text: sub.trim().to_string(),
                        tokens,
                    });
                }
            }
            cur_buf.clear();
        }
    }

    if !cur_buf.trim().is_empty() {
        let tokens = lex_python_statement(&cur_buf);
        if !tokens.is_empty() {
            out.push(PyStatement {
                line_no: start_line,
                indent: start_indent,
                raw_text: cur_buf.trim().to_string(),
                tokens,
            });
        }
    }

    out
}

fn lex_python_statement(stmt: &str) -> Vec<PyLexToken> {
    let bytes = stmt.as_bytes();
    let mut i = 0usize;
    let mut raw_tokens: Vec<PyLexToken> = Vec::new();

    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() || b == b'\\' {
            i += 1;
            continue;
        }

        // Handle Python string prefixes (`b"..."`, `r'...'`, `f"..."`, `rb'...'`)
        if (b == b'b' || b == b'r' || b == b'f' || b == b'u' || b == b'B' || b == b'R' || b == b'F')
            && i + 1 < bytes.len()
        {
            if bytes[i + 1] == b'\'' || bytes[i + 1] == b'"' {
                i += 1;
                let (lit, hex_cnt, next_i) = read_py_string(stmt, i);
                raw_tokens.push(PyLexToken::StringLit {
                    value: lit,
                    hex_escapes: hex_cnt,
                });
                i = next_i;
                continue;
            }
            if i + 2 < bytes.len()
                && (bytes[i + 1] == b'b' || bytes[i + 1] == b'r' || bytes[i + 1] == b'f')
                && (bytes[i + 2] == b'\'' || bytes[i + 2] == b'"')
            {
                i += 2;
                let (lit, hex_cnt, next_i) = read_py_string(stmt, i);
                raw_tokens.push(PyLexToken::StringLit {
                    value: lit,
                    hex_escapes: hex_cnt,
                });
                i = next_i;
                continue;
            }
        }

        if b == b'\'' || b == b'"' {
            let (lit, hex_cnt, next_i) = read_py_string(stmt, i);
            raw_tokens.push(PyLexToken::StringLit {
                value: lit,
                hex_escapes: hex_cnt,
            });
            i = next_i;
            continue;
        }

        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            raw_tokens.push(PyLexToken::Ident(stmt[start..i].to_string()));
            continue;
        }

        if b.is_ascii_digit() {
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            continue;
        }

        raw_tokens.push(PyLexToken::Symbol(b as char));
        i += 1;
    }

    // Coalesce `Ident` + `.` + `Ident` chains (`os.system`, `base64.b64decode`, `self.config.get`)
    let mut merged = Vec::with_capacity(raw_tokens.len());
    let mut k = 0usize;
    while k < raw_tokens.len() {
        if let PyLexToken::Ident(first) = &raw_tokens[k] {
            let mut acc = first.clone();
            let mut consumed = 1usize;
            while k + consumed + 1 < raw_tokens.len() {
                if raw_tokens[k + consumed] == PyLexToken::Symbol('.') {
                    if let PyLexToken::Ident(seg) = &raw_tokens[k + consumed + 1] {
                        acc.push('.');
                        acc.push_str(seg);
                        consumed += 2;
                        continue;
                    }
                }
                break;
            }
            if consumed > 1 {
                merged.push(PyLexToken::DottedIdent(acc));
            } else {
                merged.push(PyLexToken::Ident(acc));
            }
            k += consumed;
        } else {
            merged.push(raw_tokens[k].clone());
            k += 1;
        }
    }

    merged
}

fn read_py_string(s: &str, quote_pos: usize) -> (String, usize, usize) {
    let bytes = s.as_bytes();
    let q = bytes[quote_pos];
    let triple = bytes.get(quote_pos..quote_pos + 3) == Some(&[q, q, q]);
    let mut i = if triple { quote_pos + 3 } else { quote_pos + 1 };
    let mut val = String::new();
    let mut hex_escapes = 0usize;

    while i < bytes.len() {
        if triple {
            if bytes.get(i..i + 3) == Some(&[q, q, q]) {
                return (val, hex_escapes, i + 3);
            }
        } else if bytes[i] == q {
            return (val, hex_escapes, i + 1);
        }

        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'x' {
                hex_escapes += 1;
            }
            val.push('\\');
            val.push(bytes[i + 1] as char);
            i += 2;
        } else {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
                i += 1;
            }
            if let Ok(ch_s) = std::str::from_utf8(&bytes[start..i]) {
                val.push_str(ch_s);
            }
        }
    }
    (val, hex_escapes, bytes.len())
}

fn is_def_statement(tokens: &[PyLexToken]) -> bool {
    matches!(tokens.first(), Some(PyLexToken::Ident(k)) if k == "def" || k == "async")
}

fn parse_def_signature(tokens: &[PyLexToken]) -> Option<(String, Vec<String>)> {
    let mut idx = 0usize;
    if matches!(tokens.get(idx), Some(PyLexToken::Ident(s)) if s == "async") {
        idx += 1;
    }
    if !matches!(tokens.get(idx), Some(PyLexToken::Ident(s)) if s == "def") {
        return None;
    }
    idx += 1;
    let fn_name = match tokens.get(idx)? {
        PyLexToken::Ident(n) => n.clone(),
        _ => return None,
    };
    idx += 1;
    if tokens.get(idx) != Some(&PyLexToken::Symbol('(')) {
        return None;
    }
    idx += 1;

    let mut params = Vec::new();
    let mut depth = 1i32;
    let mut expect_param = true;
    while idx < tokens.len() && depth > 0 {
        match &tokens[idx] {
            PyLexToken::Symbol('(') | PyLexToken::Symbol('[') => depth += 1,
            PyLexToken::Symbol(')') | PyLexToken::Symbol(']') => depth -= 1,
            PyLexToken::Symbol(',') if depth == 1 => expect_param = true,
            PyLexToken::Symbol('=') | PyLexToken::Symbol(':') if depth == 1 => expect_param = false,
            PyLexToken::Ident(p) if depth == 1 && expect_param && p != "self" && p != "cls" => {
                params.push(p.clone());
                expect_param = false;
            }
            _ => {}
        }
        idx += 1;
    }

    Some((fn_name, params))
}

fn extract_assignment_lhs(tokens: &[PyLexToken]) -> Option<String> {
    // Match `var = ...` (ensuring `=` is not `==`)
    if tokens.len() >= 3 {
        let lhs = match &tokens[0] {
            PyLexToken::Ident(s) | PyLexToken::DottedIdent(s) => s.clone(),
            _ => return None,
        };
        if tokens[1] == PyLexToken::Symbol('=') && tokens[2] != PyLexToken::Symbol('=') {
            return Some(lhs);
        }
    }
    None
}

fn collect_statement_identifiers(tokens: &[PyLexToken]) -> Vec<String> {
    let mut out = Vec::new();
    for t in tokens {
        match t {
            PyLexToken::Ident(s) | PyLexToken::DottedIdent(s) => out.push(s.clone()),
            _ => {}
        }
    }
    out
}

fn collect_statement_strings(tokens: &[PyLexToken]) -> Vec<String> {
    let mut out = Vec::new();
    for t in tokens {
        if let PyLexToken::StringLit { value, .. } = t {
            out.push(value.clone());
        }
    }
    out
}

fn strip_python_comment(line: &str) -> &str {
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

fn net_bracket_delta(line: &str) -> i32 {
    let bytes = line.as_bytes();
    let mut in_sq = false;
    let mut in_dq = false;
    let mut esc = false;
    let mut delta = 0i32;
    for &b in bytes {
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
        } else if !in_sq && !in_dq {
            match b {
                b'(' | b'[' | b'{' => delta += 1,
                b')' | b']' | b'}' => delta -= 1,
                _ => {}
            }
        }
    }
    delta
}

fn split_top_level_semicolons(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut in_sq = false;
    let mut in_dq = false;
    let mut esc = false;
    let mut depth = 0i32;

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
        } else if !in_sq && !in_dq {
            match b {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b';' if depth == 0 => {
                    out.push(&s[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
    }
    out.push(&s[start..]);
    out
}

fn count_indent(line: &str) -> usize {
    let mut cols = 0usize;
    for b in line.bytes() {
        match b {
            b' ' => cols += 1,
            b'\t' => cols += 4,
            _ => break,
        }
    }
    cols
}

fn truncate_line(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.chars().count() <= 160 {
        trimmed.to_string()
    } else {
        let mut out: String = trimmed.chars().take(160).collect();
        out.push_str("...");
        out
    }
}

fn discover_connector_dirs(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth == 0 {
        return;
    }
    if dir.join("info.json").is_file() {
        out.push(dir.to_path_buf());
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if let Ok(ft) = entry.file_type() {
            if ft.is_dir() && !ft.is_symlink() {
                discover_connector_dirs(&entry.path(), depth - 1, out);
            }
        }
    }
}

pub(crate) fn collect_files_with_exts(
    dir: &Path,
    exts: &[&str],
    depth: usize,
    out: &mut Vec<PathBuf>,
) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if ft.is_dir() {
            if name == "site-packages"
                || name == "dist-packages"
                || name == "__pycache__"
                || name == "node_modules"
            {
                continue;
            }
            collect_files_with_exts(&entry.path(), exts, depth - 1, out);
        } else if ft.is_file() {
            let ext = entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if exts.iter().any(|&want| want == ext) {
                out.push(entry.path());
            }
        }
    }
}

pub(crate) fn join_rooted(root: &Path, rel: &str) -> PathBuf {
    let clean = rel.trim_start_matches('/');
    if clean.is_empty() {
        root.to_path_buf()
    } else {
        root.join(clean)
    }
}

pub(crate) fn display_under_root(root: &Path, full: &Path) -> String {
    if root == Path::new("/") {
        return full.to_string_lossy().into_owned();
    }
    if let Ok(stripped) = full.strip_prefix(root) {
        format!("/{}", stripped.to_string_lossy())
    } else {
        full.to_string_lossy().into_owned()
    }
}
