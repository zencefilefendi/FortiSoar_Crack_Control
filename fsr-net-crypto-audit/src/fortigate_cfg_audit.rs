//! Engine 5: FortiGate VM Configuration & `diagnose debug rating` FDS Emulator Auditor.
//!
//! Statically audits FortiOS configuration backups (`--fgt-config`) and runtime rating
//! dumps (`--fgt-rating`) for disabled FortiGuard Anycast, rogue `sdns-server-ip` / port
//! overrides, `central-management` `fmg`/`server-list` FDS license emulators, injected
//! `CA_Cert_*` certificates under `config vpn certificate ca`, and non-Fortinet rating IPs.

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};

use crate::asn1_x509::{extract_pem_certificates, parse_x509_der};
use crate::ca_trust_audit::is_authorized_fortinet_spki;
use crate::ip_asn::{classify_ip, IpOwnershipClass};

/// Output of Engine 5 (`fortigate_cfg_audit`).
pub struct FortigateCfgAuditResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 5 on optional FortiGate config backup and `diagnose debug rating` capture files.
pub fn run_fortigate_cfg_audit(
    fgt_config_path: Option<&Path>,
    fgt_rating_path: Option<&Path>,
    extra_fortinet_spkis: &[String],
) -> FortigateCfgAuditResult {
    let mut findings = Vec::new();
    let mut config_parsed = false;
    let mut rating_parsed = false;
    let mut ca_entries_inspected = 0u64;
    let mut rating_servers_inspected = 0u64;

    if let Some(cfg_path) = fgt_config_path {
        if let Ok(cfg_text) = fs::read_to_string(cfg_path) {
            config_parsed = true;
            ca_entries_inspected = audit_fortios_configuration(
                &cfg_path.to_string_lossy(),
                &cfg_text,
                extra_fortinet_spkis,
                &mut findings,
            );
        } else {
            findings.push(Finding::new(
                EngineId::FortigateCfgAudit,
                "HIGH_FGT_CONFIG_UNREADABLE",
                Severity::High,
                cfg_path.to_string_lossy(),
                format!("Unable to read supplied FortiGate config file {}", cfg_path.display()),
            ));
        }
    }

    if let Some(rat_path) = fgt_rating_path {
        if let Ok(rat_text) = fs::read_to_string(rat_path) {
            rating_parsed = true;
            rating_servers_inspected = audit_diagnose_debug_rating(
                &rat_path.to_string_lossy(),
                &rat_text,
                &mut findings,
            );
        } else {
            findings.push(Finding::new(
                EngineId::FortigateCfgAudit,
                "HIGH_FGT_RATING_UNREADABLE",
                Severity::High,
                rat_path.to_string_lossy(),
                format!("Unable to read supplied FortiGate rating file {}", rat_path.display()),
            ));
        }
    }

    let summary = JsonValue::OrderedObject(vec![
        (
            "fgt_config_supplied".to_string(),
            JsonValue::Bool(fgt_config_path.is_some()),
        ),
        ("fgt_config_parsed".to_string(), JsonValue::Bool(config_parsed)),
        (
            "vpn_ca_entries_inspected".to_string(),
            JsonValue::Uint(ca_entries_inspected),
        ),
        (
            "fgt_rating_supplied".to_string(),
            JsonValue::Bool(fgt_rating_path.is_some()),
        ),
        ("fgt_rating_parsed".to_string(), JsonValue::Bool(rating_parsed)),
        (
            "rating_servers_inspected".to_string(),
            JsonValue::Uint(rating_servers_inspected),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    FortigateCfgAuditResult { summary, findings }
}

// ============================================================================
// FortiOS Hierarchical Configuration Parser & Auditor
// ============================================================================

#[derive(Default)]
struct FortiguardBlock {
    anycast_disabled: bool,
    protocol: Option<String>,
    port: Option<u16>,
    sdns_ips: Vec<String>,
    ddns_ip: Option<String>,
    ovrd_auth_https_disabled: bool,
}

#[derive(Default)]
struct CentralMgmtServerEntry {
    id: String,
    server_type: String,
    server_address: String,
}

#[derive(Default)]
struct CentralMgmtBlock {
    mgmt_type: Option<String>,
    fmg: Option<String>,
    include_default_servers: Option<String>,
    server_list: Vec<CentralMgmtServerEntry>,
}

#[derive(Default)]
struct VpnCaEntry {
    name: String,
    source: Option<String>,
    pem_data: String,
}

pub fn audit_fortios_configuration(
    source_label: &str,
    cfg_text: &str,
    extra_fortinet_spkis: &[String],
    findings: &mut Vec<Finding>,
) -> u64 {
    let mut section_stack: Vec<String> = Vec::new();
    let mut edit_stack: Vec<String> = Vec::new();

    let mut fg_block = FortiguardBlock::default();
    let mut cm_block = CentralMgmtBlock::default();
    let mut cur_cm_srv: Option<CentralMgmtServerEntry> = None;

    let mut ca_entries: Vec<VpnCaEntry> = Vec::new();
    let mut cur_ca: Option<VpnCaEntry> = None;
    let mut collecting_multiline_pem = false;

    for raw_line in cfg_text.lines() {
        let trimmed = raw_line.trim();

        if collecting_multiline_pem {
            if let Some(ca) = cur_ca.as_mut() {
                ca.pem_data.push('\n');
                ca.pem_data.push_str(trimmed.trim_end_matches('"'));
            }
            if trimmed.contains("-----END CERTIFICATE-----") {
                collecting_multiline_pem = false;
            }
            continue;
        }

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("config ") {
            section_stack.push(rest.trim().to_string());
            continue;
        }
        if trimmed == "end" {
            let popped = section_stack.pop().unwrap_or_default();
            if popped == "server-list" {
                if let Some(srv) = cur_cm_srv.take() {
                    cm_block.server_list.push(srv);
                }
            } else if popped == "vpn certificate ca" {
                if let Some(ca) = cur_ca.take() {
                    ca_entries.push(ca);
                }
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("edit ") {
            let name = rest.trim().trim_matches('"').to_string();
            let path = section_stack.join(" > ");
            if path.ends_with("central-management > server-list") {
                cur_cm_srv = Some(CentralMgmtServerEntry {
                    id: name.clone(),
                    ..Default::default()
                });
            } else if path.ends_with("vpn certificate ca") {
                cur_ca = Some(VpnCaEntry {
                    name: name.clone(),
                    ..Default::default()
                });
            }
            edit_stack.push(name);
            continue;
        }
        if trimmed == "next" {
            let _ = edit_stack.pop();
            if let Some(srv) = cur_cm_srv.take() {
                cm_block.server_list.push(srv);
            }
            if let Some(ca) = cur_ca.take() {
                ca_entries.push(ca);
            }
            continue;
        }

        let Some(set_rest) = trimmed.strip_prefix("set ") else {
            continue;
        };
        let mut parts = set_rest.splitn(2, char::is_whitespace);
        let Some(key) = parts.next() else { continue };
        let val_raw = parts.next().unwrap_or("").trim();
        let val_clean = val_raw.trim_matches('"');

        let path = section_stack.join(" > ");

        if path == "system fortiguard" {
            match key {
                "fortiguard-anycast" if val_clean.eq_ignore_ascii_case("disable") => {
                    fg_block.anycast_disabled = true;
                }
                "protocol" => fg_block.protocol = Some(val_clean.to_string()),
                "port" => fg_block.port = val_clean.parse::<u16>().ok(),
                "sdns-server-ip" => {
                    for tok in val_raw.split_whitespace() {
                        let ip_t = tok.trim_matches('"');
                        if !ip_t.is_empty() {
                            fg_block.sdns_ips.push(ip_t.to_string());
                        }
                    }
                }
                "ddns-server-ip" => fg_block.ddns_ip = Some(val_clean.to_string()),
                "ovrd-auth-https" if val_clean.eq_ignore_ascii_case("disable") => {
                    fg_block.ovrd_auth_https_disabled = true;
                }
                _ => {}
            }
        } else if path == "system central-management" {
            match key {
                "type" => cm_block.mgmt_type = Some(val_clean.to_string()),
                "fmg" => cm_block.fmg = Some(val_clean.to_string()),
                "include-default-servers" => {
                    cm_block.include_default_servers = Some(val_clean.to_string())
                }
                _ => {}
            }
        } else if path == "system central-management > server-list" {
            if let Some(srv) = cur_cm_srv.as_mut() {
                match key {
                    "server-type" => srv.server_type = val_clean.to_string(),
                    "server-address" => srv.server_address = val_clean.to_string(),
                    _ => {}
                }
            }
        } else if path == "vpn certificate ca" {
            if let Some(ca) = cur_ca.as_mut() {
                match key {
                    "source" => ca.source = Some(val_clean.to_string()),
                    "ca" => {
                        ca.pem_data.push_str(val_raw.trim_start_matches('"').trim_end_matches('"'));
                        if !val_raw.contains("-----END CERTIFICATE-----") {
                            collecting_multiline_pem = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // --- Evaluate 5a: `config system fortiguard` ---
    if fg_block.anycast_disabled {
        let non_std_proto = fg_block
            .protocol
            .as_deref()
            .map(|p| p.eq_ignore_ascii_case("http") || p.eq_ignore_ascii_case("udp"))
            .unwrap_or(false);
        let non_std_port = fg_block
            .port
            .map(|p| !matches!(p, 443 | 53 | 8888))
            .unwrap_or(false);

        let sev = if non_std_proto || non_std_port || !fg_block.sdns_ips.is_empty() {
            Severity::Critical
        } else {
            Severity::High
        };
        findings.push(
            Finding::new(
                EngineId::FortigateCfgAudit,
                "CRITICAL_FGT_ANYCAST_DISABLED_OVERRIDE",
                sev,
                format!("{}::config system fortiguard", source_label),
                format!(
                    "`set fortiguard-anycast disable` active in FortiGate config (protocol={:?}, port={:?}, ovrd_auth_https_disabled={})",
                    fg_block.protocol, fg_block.port, fg_block.ovrd_auth_https_disabled
                ),
            )
            .with_evidence("anycast_disabled", JsonValue::Bool(true))
            .with_evidence(
                "protocol",
                fg_block
                    .protocol
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            )
            .with_evidence(
                "port",
                fg_block
                    .port
                    .map(|p| JsonValue::Uint(p as u64))
                    .unwrap_or(JsonValue::Null),
            ),
        );
    }

    for sdns in &fg_block.sdns_ips {
        let bad_sdns = match sdns.parse::<IpAddr>() {
            Ok(ip) => classify_ip(ip) != IpOwnershipClass::FortinetAs40934,
            Err(_) => true,
        };
        if bad_sdns {
            findings.push(
                Finding::new(
                    EngineId::FortigateCfgAudit,
                    "CRITICAL_FGT_ROGUE_SDNS_SERVER",
                    Severity::Critical,
                    format!("{}::sdns-server-ip={}", source_label, sdns),
                    format!(
                        "Custom `sdns-server-ip` `{}` points outside official Fortinet AS40934 space",
                        sdns
                    ),
                )
                .with_evidence("sdns_server_ip", JsonValue::str(sdns)),
            );
        }
    }

    if let Some(ddns) = &fg_block.ddns_ip {
        if let Ok(ip) = ddns.parse::<IpAddr>() {
            if ip != IpAddr::from([0, 0, 0, 0])
                && classify_ip(ip) != IpOwnershipClass::FortinetAs40934
            {
                findings.push(
                    Finding::new(
                        EngineId::FortigateCfgAudit,
                        "CRITICAL_FGT_ROGUE_DDNS_SERVER",
                        Severity::Critical,
                        format!("{}::ddns-server-ip={}", source_label, ddns),
                        format!("Custom `ddns-server-ip` `{}` points outside Fortinet AS40934", ddns),
                    )
                    .with_evidence("ddns_server_ip", JsonValue::str(ddns)),
                );
            }
        }
    }

    // --- Evaluate 5b: `config system central-management` ---
    if let Some(fmg_target) = &cm_block.fmg {
        for tok in fmg_target.split_whitespace() {
            let clean = tok.trim_matches('"');
            if clean.is_empty() || clean == "0.0.0.0" {
                continue;
            }
            let ownership = clean
                .parse::<IpAddr>()
                .map(|ip| classify_ip(ip).as_str())
                .unwrap_or("HOSTNAME_ENDPOINT");
            let sev = if ownership == "LOOPBACK" || cm_block.include_default_servers.as_deref() == Some("disable") {
                Severity::Critical
            } else {
                Severity::High
            };
            findings.push(
                Finding::new(
                    EngineId::FortigateCfgAudit,
                    "HIGH_FGT_CENTRAL_MGMT_FMG_ENDPOINT",
                    sev,
                    format!("{}::central-management::fmg={}", source_label, clean),
                    format!(
                        "Central-management `fmg` directed to `{}` ({}, include-default-servers={:?})",
                        clean, ownership, cm_block.include_default_servers
                    ),
                )
                .with_evidence("fmg_endpoint", JsonValue::str(clean))
                .with_evidence("endpoint_class", JsonValue::str(ownership)),
            );
        }
    }

    for srv in &cm_block.server_list {
        let addr_class = srv
            .server_address
            .parse::<IpAddr>()
            .map(classify_ip)
            .unwrap_or(IpOwnershipClass::ExternalNonFortinet);

        if addr_class != IpOwnershipClass::FortinetAs40934 {
            findings.push(
                Finding::new(
                    EngineId::FortigateCfgAudit,
                    "CRITICAL_FGT_CENTRAL_MGMT_FDS_EMULATOR",
                    Severity::Critical,
                    format!(
                        "{}::central-management::server-list[{}]={}",
                        source_label, srv.id, srv.server_address
                    ),
                    format!(
                        "Unauthorized `central-management` `server-list` entry #{}` redirects `{}` service to {} ({})",
                        srv.id,
                        srv.server_type,
                        srv.server_address,
                        addr_class.as_str()
                    ),
                )
                .with_evidence("entry_id", JsonValue::str(&srv.id))
                .with_evidence("server_type", JsonValue::str(&srv.server_type))
                .with_evidence("server_address", JsonValue::str(&srv.server_address))
                .with_evidence("ip_ownership", JsonValue::str(addr_class.as_str())),
            );
        }
    }

    // --- Evaluate 5c: `config vpn certificate ca` ---
    let ca_total = ca_entries.len() as u64;
    for ca in ca_entries {
        let is_factory = ca
            .source
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("factory") || s.eq_ignore_ascii_case("bundle"))
            .unwrap_or(false)
            && !ca.name.starts_with("CA_Cert_");

        let ders = extract_pem_certificates(&ca.pem_data);
        let parsed_cert = ders.first().and_then(|d| parse_x509_der(d).ok());

        let impersonates_fortinet = parsed_cert
            .as_ref()
            .map(|c| {
                c.mentions_fortinet_identity()
                    && !is_authorized_fortinet_spki(&c.spki_sha256, extra_fortinet_spkis)
            })
            .unwrap_or(false);

        if !is_factory || ca.name.starts_with("CA_Cert_") || impersonates_fortinet {
            let mut f = Finding::new(
                EngineId::FortigateCfgAudit,
                "CRITICAL_FGT_INJECTED_ROGUE_CA_CERT",
                Severity::Critical,
                format!("{}::vpn certificate ca::{}", source_label, ca.name),
                format!(
                    "Non-factory CA certificate `{}` (source={:?}) injected into FortiGate `config vpn certificate ca`",
                    ca.name, ca.source
                ),
            )
            .with_evidence("ca_entry_name", JsonValue::str(&ca.name))
            .with_evidence(
                "source_attribute",
                ca.source
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            );

            if let Some(cert) = parsed_cert {
                f.insert_evidence("subject", JsonValue::str(&cert.subject_dn));
                f.insert_evidence("issuer", JsonValue::str(&cert.issuer_dn));
                f.insert_evidence("spki_sha256", JsonValue::str(&cert.spki_sha256));
                f.insert_evidence("impersonates_fortinet", JsonValue::Bool(impersonates_fortinet));
            }
            findings.push(f);
        }
    }

    ca_total
}

// ============================================================================
// 5d. `diagnose debug rating` Runtime FDS Server List Auditor
// ============================================================================

pub fn audit_diagnose_debug_rating(
    source_label: &str,
    rating_text: &str,
    findings: &mut Vec<Finding>,
) -> u64 {
    let mut header_kv: BTreeMap<String, String> = BTreeMap::new();
    let mut servers_checked = 0u64;

    for raw_line in rating_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("-=-") || line.starts_with("IP ") {
            continue;
        }

        // Parse header lines `Key : Value` before server table
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().parse::<IpAddr>().is_err() {
                header_kv.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                continue;
            }
        }

        // Parse server row: `IP  Weight  RTT  Flags  TZ  FortiGuard-requests  Curr Lost  Total Lost`
        let cols: Vec<&str> = line.split_whitespace().collect();
        let Some(first_tok) = cols.first() else {
            continue;
        };
        let Ok(ip) = first_tok.parse::<IpAddr>() else {
            continue;
        };

        servers_checked += 1;
        let flags = cols.get(3).copied().unwrap_or("");
        let requests = cols.get(5).copied().unwrap_or("0");
        let ownership = classify_ip(ip);
        let has_default_flag = flags.contains('D');

        if ownership != IpOwnershipClass::FortinetAs40934 || !has_default_flag {
            let sev = if ownership != IpOwnershipClass::FortinetAs40934 {
                Severity::Critical
            } else {
                Severity::High
            };
            findings.push(
                Finding::new(
                    EngineId::FortigateCfgAudit,
                    "CRITICAL_FGT_RATING_ROGUE_FDS_SERVER",
                    sev,
                    format!("{}::rating_server={}", source_label, ip),
                    format!(
                        "`diagnose debug rating` lists non-default/non-Fortinet FDS server {} ({}, flags=`{}`, requests={})",
                        ip,
                        ownership.as_str(),
                        flags,
                        requests
                    ),
                )
                .with_evidence("server_ip", JsonValue::str(ip.to_string()))
                .with_evidence("ip_ownership", JsonValue::str(ownership.as_str()))
                .with_evidence("flags", JsonValue::str(flags))
                .with_evidence("has_default_d_flag", JsonValue::Bool(has_default_flag))
                .with_evidence("fortiguard_requests", JsonValue::str(requests)),
            );
        }
    }

    if let Some(anycast) = header_kv.get("anycast") {
        if anycast.eq_ignore_ascii_case("disable") {
            findings.push(
                Finding::new(
                    EngineId::FortigateCfgAudit,
                    "HIGH_FGT_RATING_ANYCAST_DISABLED",
                    Severity::High,
                    format!("{}::Anycast", source_label),
                    "`diagnose debug rating` reports `Anycast : Disable` at runtime".to_string(),
                )
                .with_evidence("anycast", JsonValue::str(anycast)),
            );
        }
    }

    servers_checked
}
