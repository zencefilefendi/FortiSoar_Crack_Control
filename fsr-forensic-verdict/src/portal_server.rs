//! Pillar 3: Zero-Dependency Built-In Local Web Inspection Portal (`--serve <HOST:PORT>`).
//!
//! Provides an air-gapped, pure-Rust (`std::net::TcpListener`) local HTTP inspection portal
//! so enterprise security teams, CISOs, and SOC
//! engineers can verify any FortiSOAR / FortiGate directory, `.ova` image, or pasted
//! `cyops-auth` / `csdassrv.py` / `/auth/license` JSON snippet from a browser with
//! zero external dependencies.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fsr_deep_audit::schema::JsonValue;
use fsr_supplychain_backdoor_audit::web_auth_backdoor::inspect_text_snippet_for_cracks;

use crate::report_emitter::{
    render_denetim_kabul_tutanagi_html, summarize_instant_enterprise_checks,
};
use crate::{execute_forensic_verdict_command_center, ForensicVerdictConfig};

/// Builds an automatic [`ForensicVerdictConfig`] for `--quick-check` or the Web Portal
/// based on whether `target` is an `.ova` archive or a directory/root path.
pub fn build_quick_check_config(target: &Path) -> ForensicVerdictConfig {
    let mut cfg = ForensicVerdictConfig {
        attribute_cracker: true,
        ..ForensicVerdictConfig::default()
    };

    let lower_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if target.is_file() && (lower_name.ends_with(".ova") || lower_name.ends_with(".tar")) {
        cfg.audit_root_filesystem = false;
        cfg.ova_path = Some(target.to_path_buf());
    } else if target.is_file() {
        // Single script/file passed: scan its parent directory if it's inside `cyops-auth`, or its parent
        if let Some(parent) = target.parent() {
            let parent_with_parent = parent
                .parent()
                .filter(|gp| gp.join("server/csdassrv.py").is_file())
                .unwrap_or(parent);
            cfg.root_path = parent_with_parent.to_path_buf();
            cfg.audit_root_filesystem = true;
        }
    } else {
        cfg.root_path = target.to_path_buf();
        cfg.audit_root_filesystem = true;
    }

    cfg
}

/// Runs the local HTTP inspection portal on `bind_addr` (e.g. `127.0.0.1:8090`).
/// When `single_request` is `true`, serves one HTTP request and returns cleanly.
pub fn run_portal_server(
    bind_addr: &str,
    default_root: &Path,
    single_request: bool,
) -> Result<(), String> {
    let listener = TcpListener::bind(bind_addr)
        .map_err(|e| format!("Portal sunucusu `{}` adresine bağlanamadı: {}", bind_addr, e))?;

    for stream_res in listener.incoming() {
        let Ok(mut stream) = stream_res else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

        let raw_req = read_http_request(&mut stream);
        if raw_req.is_empty() {
            if single_request {
                break;
            }
            continue;
        }

        let (status_code, content_type, body) =
            handle_portal_http_request(&raw_req, default_root);
        let status_text = match status_code {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            _ => "Internal Server Error",
        };

        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
            status_code,
            status_text,
            content_type,
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();

        if single_request {
            break;
        }
    }

    Ok(())
}

fn read_http_request(stream: &mut impl Read) -> String {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];

    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if header_end.is_none() {
                    if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                        let hdr_end = pos + 4;
                        header_end = Some(hdr_end);
                        let hdr_str = String::from_utf8_lossy(&buf[..hdr_end]);
                        for line in hdr_str.lines() {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    content_length = v.trim().parse::<usize>().unwrap_or(0);
                                }
                            }
                        }
                    }
                }
                if let Some(hdr_end) = header_end {
                    if buf.len() >= hdr_end + content_length {
                        break;
                    }
                }
                if buf.len() >= 2 * 1024 * 1024 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    String::from_utf8_lossy(&buf).into_owned()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Pure function handling an HTTP request string for the Local Web Inspection Portal.
pub fn handle_portal_http_request(
    raw_request: &str,
    default_root: &Path,
) -> (u16, &'static str, String) {
    let (headers_part, body_part) = raw_request
        .split_once("\r\n\r\n")
        .or_else(|| raw_request.split_once("\n\n"))
        .unwrap_or((raw_request, ""));

    let first_line = headers_part.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let full_target = parts.next().unwrap_or("/");
    let (route_path, query_str) = full_target.split_once('?').unwrap_or((full_target, ""));

    match (method, route_path) {
        ("GET", "/") | ("GET", "/index.html") | ("GET", "/dashboard") => (
            200,
            "text/html; charset=utf-8",
            render_portal_home_html(default_root),
        ),
        ("GET", "/api/status") => {
            let resp = JsonValue::OrderedObject(vec![
                ("online".to_string(), JsonValue::Bool(true)),
                ("engines".to_string(), JsonValue::Uint(22)),
                ("cyops_layers".to_string(), JsonValue::Uint(11)),
                (
                    "default_root".to_string(),
                    JsonValue::str(default_root.to_string_lossy().into_owned()),
                ),
            ]);
            (200, "application/json; charset=utf-8", resp.to_json_string(true))
        }
        ("POST", "/api/inspect-snippet") => {
            let label = extract_json_string_field(body_part, "label")
                .unwrap_or_else(|| "uploaded_snippet.py".to_string());
            let content = extract_json_string_field(body_part, "content")
                .unwrap_or_else(|| body_part.to_string());
            let findings = inspect_text_snippet_for_cracks(&label, &content);
            let verdict = if findings.is_empty() {
                "CLEAN"
            } else {
                "COMPROMISED_OR_CRACKED"
            };
            let findings_json: Vec<JsonValue> = findings
                .iter()
                .enumerate()
                .map(|(idx, f)| f.to_json_with_id(&format!("FSR-SNIP-{:04}", idx + 1)))
                .collect();
            let resp = JsonValue::OrderedObject(vec![
                ("verdict".to_string(), JsonValue::str(verdict)),
                (
                    "finding_count".to_string(),
                    JsonValue::Uint(findings.len() as u64),
                ),
                ("findings".to_string(), JsonValue::Array(findings_json)),
            ]);
            (200, "application/json; charset=utf-8", resp.to_json_string(true))
        }
        ("POST", "/api/scan") => {
            let requested_path = extract_json_string_field(body_part, "path")
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| default_root.to_path_buf());

            // If user points directly to a single `.py` / `.json` / `.conf` file, also run snippet check
            let lower = requested_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if requested_path.is_file() && !lower.ends_with(".ova") && !lower.ends_with(".tar") {
                if let Ok(text) = fs::read_to_string(&requested_path) {
                    let snippet_findings = inspect_text_snippet_for_cracks(
                        &requested_path.to_string_lossy(),
                        &text,
                    );
                    if !snippet_findings.is_empty()
                        && !requested_path
                            .parent()
                            .is_some_and(|p| p.join("csdassrv.py").is_file())
                    {
                        let findings_json: Vec<JsonValue> = snippet_findings
                            .iter()
                            .enumerate()
                            .map(|(idx, f)| f.to_json_with_id(&format!("FSR-SNIP-{:04}", idx + 1)))
                            .collect();
                        let resp = JsonValue::OrderedObject(vec![
                            (
                                "status".to_string(),
                                JsonValue::str("COMPROMISED_OR_CRACKED"),
                            ),
                            ("composite_risk_score".to_string(), JsonValue::Uint(100)),
                            (
                                "total_findings".to_string(),
                                JsonValue::Uint(snippet_findings.len() as u64),
                            ),
                            (
                                "das_crack_status".to_string(),
                                JsonValue::str(
                                    "CRACK TESPİT EDİLDİ — Tekil dosya üzerinde `cyops-auth` / `csdassrv.py` / `/license` baypas imzası doğrulandı.",
                                ),
                            ),
                            (
                                "lic_status".to_string(),
                                JsonValue::str("İHLAL TESPİT EDİLDİ — Sahte lisans / Cython `.so` gölgeleme imzası mevcut."),
                            ),
                            (
                                "vault_status".to_string(),
                                JsonValue::str("TEHLİKEDE — Yetkisiz çalışma zamanı kodu tespit edildi."),
                            ),
                            ("findings".to_string(), JsonValue::Array(findings_json)),
                        ]);
                        return (
                            200,
                            "application/json; charset=utf-8",
                            resp.to_json_string(true),
                        );
                    }
                }
            }

            let cfg = build_quick_check_config(&requested_path);
            let bundle = execute_forensic_verdict_command_center(&cfg);
            let (das_status, lic_status, vault_status) =
                summarize_instant_enterprise_checks(&bundle);
            let findings_json: Vec<JsonValue> = bundle
                .merkle_envelope
                .sealed_findings
                .iter()
                .map(|sf| sf.finding_json.clone())
                .collect();

            let resp = JsonValue::OrderedObject(vec![
                (
                    "status".to_string(),
                    JsonValue::str(bundle.verdict_summary.status),
                ),
                (
                    "composite_risk_score".to_string(),
                    JsonValue::Uint(bundle.verdict_summary.composite_risk_score as u64),
                ),
                (
                    "total_findings".to_string(),
                    JsonValue::Uint(bundle.verdict_summary.total_findings as u64),
                ),
                (
                    "executive_conclusion_tr".to_string(),
                    JsonValue::str(&bundle.verdict_summary.executive_conclusion_tr),
                ),
                ("das_crack_status".to_string(), JsonValue::str(&das_status)),
                ("lic_status".to_string(), JsonValue::str(&lic_status)),
                ("vault_status".to_string(), JsonValue::str(&vault_status)),
                (
                    "merkle_root_hex".to_string(),
                    JsonValue::str(&bundle.merkle_envelope.merkle_root_hex),
                ),
                (
                    "target_mutated".to_string(),
                    JsonValue::Bool(bundle.non_mutation_attestation.target_mutated),
                ),
                ("findings".to_string(), JsonValue::Array(findings_json)),
            ]);
            (200, "application/json; charset=utf-8", resp.to_json_string(true))
        }
        ("GET", "/api/acceptance-report") => {
            let target_path = parse_query_param(query_str, "path")
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| default_root.to_path_buf());
            let cfg = build_quick_check_config(&target_path);
            let bundle = execute_forensic_verdict_command_center(&cfg);
            let html = render_denetim_kabul_tutanagi_html(&bundle);
            (200, "text/html; charset=utf-8", html)
        }
        _ => (
            404,
            "application/json; charset=utf-8",
            "{\"error\":\"not_found\"}".to_string(),
        ),
    }
}

fn parse_query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(percent_decode(v));
            }
        }
    }
    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Minimal zero-dependency JSON string field extractor (`"key": "value"`).
fn extract_json_string_field(json: &str, field: &str) -> Option<String> {
    let needle = format!("\"{}\"", field);
    let idx = json.find(&needle)?;
    let rest = &json[idx + needle.len()..];
    let colon_idx = rest.find(':')?;
    let after_colon = rest[colon_idx + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let bytes = after_colon.as_bytes();
    let mut out = String::new();
    let mut i = 1usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            return Some(out);
        }
        if b == b'\\' && i + 1 < bytes.len() {
            i += 1;
            match bytes[i] {
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                other => out.push(other as char),
            }
        } else {
            // Preserve UTF-8 characters properly
            let ch = after_colon[i..].chars().next()?;
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        i += 1;
    }
    None
}

fn render_portal_home_html(default_root: &Path) -> String {
    let default_root_str = default_root.to_string_lossy().replace('"', "&quot;");
    const DASHBOARD_TEMPLATE: &str = include_str!("../../dashboard/index.html");
    DASHBOARD_TEMPLATE.replace(
        "id=\"scan-path\" value=\"/\"",
        &format!("id=\"scan-path\" value=\"{}\"", default_root_str),
    )
}
