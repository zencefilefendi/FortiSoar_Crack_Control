//! Engine 5: Active TLS 1.2 & HTTP Management Interface Fingerprinter (`--scan-targets`).
//!
//! Connects to FortiGate VM and FortiSOAR management endpoints (`ip:port,...`),
//! executes a byte-level TLS 1.2 `ClientHello` handshake to extract the X.509 server
//! certificate (`Subject CN`, `SerialNumber`, `SPKI SHA-256`) plus minimal HTTP `GET /`
//! and `GET /api/3/info` requests to capture server banners (`Server: xxxxxxxx-xxxxx`
//! FortiOS `httpsd`, `nginx` FortiSOAR proxy, cookies, and API metadata), and feeds
//! normalized [`ClusterNodeRecord`] entries directly into `cluster_correlator`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fsr_deep_audit::crypto::sha256_hex;
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};
use fsr_net_crypto_audit::asn1_x509::parse_x509_der;
use fsr_net_crypto_audit::fdn_live_probe::{
    build_tls12_client_hello, parse_tls_handshake_messages, TlsServerHandshakeInfo,
};

use crate::cluster_correlator::ClusterNodeRecord;
use crate::fgvm_license_inspect::{analyze_fgvm_serial, extract_fgvm_tokens};
use crate::json_parser::{json_as_str, json_get, parse_json_str};

/// Parsed HTTP response headers & body snippet from `GET /` or `GET /api/3/info`.
#[derive(Debug, Clone, Default)]
pub struct HttpEndpointResponse {
    pub status_code: Option<u16>,
    pub server_header: Option<String>,
    pub etag_header: Option<String>,
    pub cookie_names: Vec<String>,
    pub body_preview: String,
    pub detected_platform: String,
    pub soar_instance_uuid: Option<String>,
    pub soar_version: Option<String>,
}

/// Transport seam enabling both live TCP/TLS/HTTP scanning and deterministic offline/loopback tests.
pub trait RemoteFingerprintTransport {
    fn resolve_target(&self, host_port: &str) -> Result<(SocketAddr, String), String>;
    fn fetch_tls12_handshake(
        &self,
        addr: SocketAddr,
        sni_host: &str,
    ) -> Result<TlsServerHandshakeInfo, String>;
    fn fetch_http_probe(
        &self,
        addr: SocketAddr,
        host_header: &str,
        path: &str,
    ) -> Result<HttpEndpointResponse, String>;
}

/// Production TCP socket transport for `--scan-targets`.
pub struct LiveTcpFingerprintTransport {
    pub timeout: Duration,
}

impl Default for LiveTcpFingerprintTransport {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(4),
        }
    }
}

impl RemoteFingerprintTransport for LiveTcpFingerprintTransport {
    fn resolve_target(&self, host_port: &str) -> Result<(SocketAddr, String), String> {
        let trimmed = host_port.trim();
        let host_only = extract_host_part(trimmed)?;
        let mut addrs = trimmed
            .to_socket_addrs()
            .map_err(|e| format!("failed to resolve `{}`: {}", trimmed, e))?;
        let sa = addrs
            .next()
            .ok_or_else(|| format!("no socket address resolved for `{}`", trimmed))?;
        Ok((sa, host_only))
    }

    fn fetch_tls12_handshake(
        &self,
        addr: SocketAddr,
        sni_host: &str,
    ) -> Result<TlsServerHandshakeInfo, String> {
        let mut stream = TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|e| format!("TCP connect {} failed: {}", addr, e))?;
        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

        let random = derive_probe_random(sni_host, addr.port());
        let ch = build_tls12_client_hello(sni_host, random);
        stream
            .write_all(&ch)
            .map_err(|e| format!("TLS ClientHello write failed: {}", e))?;

        let mut raw = Vec::with_capacity(8192);
        let mut chunk = [0u8; 4096];
        while raw.len() < 65_536 {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&chunk[..n]);
                    if let Ok(hs) = parse_tls_handshake_messages(&raw) {
                        if !hs.der_certificates.is_empty() {
                            return Ok(hs);
                        }
                    }
                    if raw.first() == Some(&21) {
                        return Err("TLS Alert returned by target".to_string());
                    }
                }
                Err(_) => break,
            }
        }
        parse_tls_handshake_messages(&raw)
    }

    fn fetch_http_probe(
        &self,
        addr: SocketAddr,
        host_header: &str,
        path: &str,
    ) -> Result<HttpEndpointResponse, String> {
        let mut stream = TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|e| format!("HTTP TCP connect {} failed: {}", addr, e))?;
        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: fsr-clone-cluster-audit/1.0\r\nAccept: application/json, text/html, */*\r\nConnection: close\r\n\r\n",
            path, host_header
        );
        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("HTTP request write failed: {}", e))?;

        let mut resp_bytes = Vec::with_capacity(4096);
        let mut buf = [0u8; 2048];
        while resp_bytes.len() < 16_384 {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => resp_bytes.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        if resp_bytes.is_empty() {
            return Err("empty HTTP response".to_string());
        }
        Ok(parse_raw_http_response(&resp_bytes))
    }
}

/// Output of Engine 5 (`remote_fingerprinter`).
pub struct RemoteFingerprintResult {
    pub collected_nodes: Vec<ClusterNodeRecord>,
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 5 across `--scan-targets` using live TCP sockets.
pub fn run_remote_fingerprinter(targets: &[String]) -> RemoteFingerprintResult {
    if targets.is_empty() {
        return RemoteFingerprintResult {
            collected_nodes: Vec::new(),
            summary: JsonValue::OrderedObject(vec![
                ("enabled".to_string(), JsonValue::Bool(false)),
                ("targets_requested".to_string(), JsonValue::Uint(0)),
            ]),
            findings: Vec::new(),
        };
    }

    run_remote_fingerprinter_with_transport(targets, &LiveTcpFingerprintTransport::default())
}

/// Runs Engine 5 with a pluggable [`RemoteFingerprintTransport`].
pub fn run_remote_fingerprinter_with_transport<T: RemoteFingerprintTransport>(
    targets: &[String],
    transport: &T,
) -> RemoteFingerprintResult {
    let mut findings = Vec::new();
    let mut collected_nodes = Vec::new();
    let mut target_reports = Vec::new();

    for raw_target in targets {
        let target = raw_target.trim();
        if target.is_empty() {
            continue;
        }

        let (sock_addr, host_str) = match transport.resolve_target(target) {
            Ok(pair) => pair,
            Err(err) => {
                target_reports.push(JsonValue::OrderedObject(vec![
                    ("target".to_string(), JsonValue::str(target)),
                    ("reachable".to_string(), JsonValue::Bool(false)),
                    ("error".to_string(), JsonValue::str(err)),
                ]));
                continue;
            }
        };

        let mut node = ClusterNodeRecord {
            source_label: format!("remote_probe://{}", target),
            ip_address: Some(sock_addr.ip().to_string()),
            port: Some(sock_addr.port()),
            hostname: if host_str != sock_addr.ip().to_string() {
                Some(host_str.clone())
            } else {
                None
            },
            ..Default::default()
        };

        // 1. TLS 1.2 Handshake + X.509 Certificate extraction
        let mut tls_json = JsonValue::Null;
        if let Ok(hs) = transport.fetch_tls12_handshake(sock_addr, &host_str) {
            if let Some(leaf_der) = hs.der_certificates.first() {
                if let Ok(cert) = parse_x509_der(leaf_der) {
                    let cn = cert
                        .subject_cn
                        .clone()
                        .unwrap_or_else(|| cert.subject_dn.clone());
                    node.tls_spki_sha256s.push(cert.spki_sha256.clone());
                    node.tls_cert_serials.push(cert.serial_hex.clone());
                    node.tls_subject_cns.push(cn.clone());
                    if node.hostname.is_none() && !cn.is_empty() {
                        node.hostname = Some(cn.clone());
                    }

                    // Extract and validate any `FGVM*` serial embedded in `Subject CN` or `Subject DN`
                    for fgvm_tok in extract_fgvm_tokens(&cert.subject_dn) {
                        let analysis = analyze_fgvm_serial(&fgvm_tok, target);
                        if analysis.model_spec.is_some_and(|m| m.is_eval_trial) {
                            findings.push(
                                Finding::new(
                                    EngineId::RemoteFingerprinter,
                                    "CRITICAL_FGVM_EVAL_TRIAL_IN_PRODUCTION",
                                    Severity::Critical,
                                    target,
                                    format!(
                                        "Remote FortiGate endpoint `{}` presents Evaluation/Trial certificate serial `{}` on active management interface",
                                        target, analysis.normalized_serial
                                    ),
                                )
                                .with_evidence("target", JsonValue::str(target))
                                .with_evidence("fgvm_serial", JsonValue::str(&analysis.normalized_serial))
                                .with_evidence("spki_sha256", JsonValue::str(&cert.spki_sha256)),
                            );
                        }
                        if let Some(reason) = &analysis.keygen_or_pirated_reason {
                            findings.push(
                                Finding::new(
                                    EngineId::RemoteFingerprinter,
                                    "CRITICAL_FGVM_PIRATED_OR_KEYGEN_SERIAL",
                                    Severity::Critical,
                                    target,
                                    format!(
                                        "Remote endpoint `{}` presents keygen/invalid FGVM serial `{}` in X.509 Subject: {}",
                                        target, analysis.normalized_serial, reason
                                    ),
                                )
                                .with_evidence("target", JsonValue::str(target))
                                .with_evidence("fgvm_serial", JsonValue::str(&analysis.normalized_serial))
                                .with_evidence("reason", JsonValue::str(reason.as_str())),
                            );
                        }
                        if !node.fgvm_serials.contains(&analysis.normalized_serial) {
                            node.fgvm_serials.push(analysis.normalized_serial);
                        }
                    }

                    tls_json = JsonValue::OrderedObject(vec![
                        ("subject_cn".to_string(), JsonValue::str(&cn)),
                        ("issuer_dn".to_string(), JsonValue::str(&cert.issuer_dn)),
                        ("serial_number_hex".to_string(), JsonValue::str(&cert.serial_hex)),
                        ("spki_sha256".to_string(), JsonValue::str(&cert.spki_sha256)),
                        ("not_before".to_string(), JsonValue::str(&cert.not_before)),
                        ("not_after".to_string(), JsonValue::str(&cert.not_after)),
                        (
                            "cipher_suite".to_string(),
                            JsonValue::str(format!("0x{:04x}", hs.cipher_suite)),
                        ),
                    ]);
                }
            }
        }

        // 2. HTTP `GET /api/3/info` and `GET /` server signature extraction
        let api_resp = transport.fetch_http_probe(sock_addr, &host_str, "/api/3/info").ok();
        let root_resp = transport.fetch_http_probe(sock_addr, &host_str, "/").ok();

        let chosen_http = api_resp
            .as_ref()
            .filter(|r| r.soar_instance_uuid.is_some() || r.status_code == Some(200))
            .or(root_resp.as_ref())
            .or(api_resp.as_ref());

        let mut http_json = JsonValue::Null;
        if let Some(hr) = chosen_http {
            node.server_signature = hr
                .server_header
                .clone()
                .or_else(|| Some(hr.detected_platform.clone()));

            // If `/api/3/info` exposed a deterministic FortiSOAR deployment/tenant UUID, record as birthmark seed
            if let Some(inst_uuid) = &hr.soar_instance_uuid {
                node.vault_seed_fingerprints
                    .push(("api_3_info_instance_uuid".to_string(), sha256_hex(inst_uuid.as_bytes())));
            }

            http_json = JsonValue::OrderedObject(vec![
                (
                    "status_code".to_string(),
                    match hr.status_code {
                        Some(c) => JsonValue::Uint(c as u64),
                        None => JsonValue::Null,
                    },
                ),
                (
                    "server_header".to_string(),
                    match &hr.server_header {
                        Some(s) => JsonValue::str(s.as_str()),
                        None => JsonValue::Null,
                    },
                ),
                (
                    "detected_platform".to_string(),
                    JsonValue::str(&hr.detected_platform),
                ),
                (
                    "cookie_names".to_string(),
                    JsonValue::Array(
                        hr.cookie_names
                            .iter()
                            .map(|c| JsonValue::str(c.as_str()))
                            .collect(),
                    ),
                ),
                (
                    "soar_version".to_string(),
                    match &hr.soar_version {
                        Some(v) => JsonValue::str(v.as_str()),
                        None => JsonValue::Null,
                    },
                ),
            ]);
        }

        target_reports.push(JsonValue::OrderedObject(vec![
            ("target".to_string(), JsonValue::str(target)),
            ("ip".to_string(), JsonValue::str(sock_addr.ip().to_string())),
            ("port".to_string(), JsonValue::Uint(sock_addr.port() as u64)),
            ("reachable".to_string(), JsonValue::Bool(true)),
            ("tls_x509".to_string(), tls_json),
            ("http_signature".to_string(), http_json),
        ]));

        collected_nodes.push(node);
    }

    let summary = JsonValue::OrderedObject(vec![
        ("enabled".to_string(), JsonValue::Bool(true)),
        (
            "targets_requested".to_string(),
            JsonValue::Uint(targets.len() as u64),
        ),
        (
            "targets_fingerprinted".to_string(),
            JsonValue::Uint(collected_nodes.len() as u64),
        ),
        ("targets".to_string(), JsonValue::Array(target_reports)),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    RemoteFingerprintResult {
        collected_nodes,
        summary,
        findings,
    }
}

/// Parses raw HTTP/1.x response bytes into structured appliance signature metadata.
pub fn parse_raw_http_response(raw: &[u8]) -> HttpEndpointResponse {
    let lossy = String::from_utf8_lossy(raw);
    let (head_str, body_str) = lossy
        .split_once("\r\n\r\n")
        .or_else(|| lossy.split_once("\n\n"))
        .unwrap_or((&lossy, ""));

    let mut lines = head_str.lines();
    let status_line = lines.next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok());

    let mut server_header = None;
    let mut etag_header = None;
    let mut cookie_names = Vec::new();

    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key_lower = k.trim().to_ascii_lowercase();
        let val = v.trim();
        if key_lower == "server" {
            server_header = Some(val.to_string());
        } else if key_lower == "etag" {
            etag_header = Some(val.to_string());
        } else if key_lower == "set-cookie" {
            if let Some(cname) = val.split('=').next() {
                let c = cname.trim().to_string();
                if !c.is_empty() && !cookie_names.contains(&c) {
                    cookie_names.push(c);
                }
            }
        }
    }

    let mut soar_instance_uuid = None;
    let mut soar_version = None;
    let trimmed_body = body_str.trim();
    if trimmed_body.starts_with('{') {
        if let Ok(json_body) = parse_json_str(trimmed_body) {
            soar_version = json_get(&json_body, "version")
                .or_else(|| json_get(&json_body, "release"))
                .and_then(json_as_str)
                .map(|s| s.to_string());
            soar_instance_uuid = json_get(&json_body, "instance_uuid")
                .or_else(|| json_get(&json_body, "system_uuid"))
                .or_else(|| json_get(&json_body, "id"))
                .and_then(json_as_str)
                .map(|s| s.to_string());
        }
    }

    let lower_body = trimmed_body.to_ascii_lowercase();
    let detected_platform = if server_header.as_deref() == Some("xxxxxxxx-xxxxx")
        || cookie_names.iter().any(|c| c.starts_with("APSCOOKIE"))
        || lower_body.contains("fgt_lang")
        || lower_body.contains("/remote/login")
    {
        "fortigate_fortios_httpsd".to_string()
    } else if soar_version.is_some()
        || lower_body.contains("fortisoar")
        || lower_body.contains("cyops")
        || server_header
            .as_deref()
            .is_some_and(|s| s.to_ascii_lowercase().contains("nginx"))
    {
        "fortisoar_nginx_cyops".to_string()
    } else {
        "generic_http_tls_appliance".to_string()
    };

    let preview_end = trimmed_body.len().min(160);
    let body_preview = trimmed_body[..preview_end].replace(['\r', '\n'], " ");

    HttpEndpointResponse {
        status_code,
        server_header,
        etag_header,
        cookie_names,
        body_preview,
        detected_platform,
        soar_instance_uuid,
        soar_version,
    }
}

fn extract_host_part(host_port: &str) -> Result<String, String> {
    if let Some(rest) = host_port.strip_prefix('[') {
        let Some((ipv6_host, _port_part)) = rest.split_once("]:") else {
            return Err(format!("expected `[ipv6]:port` in `{}`", host_port));
        };
        Ok(ipv6_host.to_string())
    } else {
        let Some((host, _port)) = host_port.rsplit_once(':') else {
            return Err(format!("expected `host:port` in `{}`", host_port));
        };
        if host.is_empty() {
            return Err(format!("empty host in `{}`", host_port));
        }
        Ok(host.to_string())
    }
}

fn derive_probe_random(host: &str, port: u16) -> [u8; 32] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let hex = sha256_hex(format!("fsr-remote-probe:{}:{}:{}", host, port, nanos).as_bytes());
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0x42);
    }
    out
}
