//! Engine 5: FortiGate Configuration Backdoor, Rogue Super-Admin & Exfiltration Auditor.
//!
//! Parses FortiOS hierarchical configuration backups (`--fgt-config <file>`) to detect
//! post-compromise and Golden-Image distributor backdoors:
//!   a) `config system admin`: Secondary/hidden `super_admin` accounts, unrestricted or
//!      foreign public `trusthost` CIDRs, and pre-planted `ssh-public-key1..3` keys
//!      (`HIGH_FGT_ROGUE_SUPER_ADMIN`),
//!   b) `config system auto-script`, `config system automation-action`, and
//!      `config system automation-stitch`: Automated configuration backup exfiltration
//!      (`execute backup`), `fnsysctl` shell escapes, and external webhook skimmers
//!      (`CRITICAL_FGT_AUTOMATION_EXFIL_BACKDOOR`),
//!   c) `config system api-user` and `config system snmp community`: Internet-exposed
//!      `super_admin` REST API tokens (missing or public `trusthost`) and unrestricted
//!      SNMP communities (`CRITICAL_FGT_EXPOSED_REST_API_ADMIN`).

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use fsr_deep_audit::crypto::sha256_hex;
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};
use fsr_net_crypto_audit::ip_asn::{classify_ipv4, IpOwnershipClass};

/// Output of Engine 5 (`fortigate_backdoor_audit`).
pub struct FortigateBackdoorAuditResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 5 when `--fgt-config <file>` is supplied.
pub fn run_fortigate_backdoor_audit(fgt_config_path: Option<&Path>) -> FortigateBackdoorAuditResult {
    let Some(cfg_path) = fgt_config_path else {
        return FortigateBackdoorAuditResult {
            summary: JsonValue::OrderedObject(vec![
                ("config_supplied".to_string(), JsonValue::Bool(false)),
                (
                    "status".to_string(),
                    JsonValue::str("skipped (pass --fgt-config <file> to audit FortiGate configuration backdoors)"),
                ),
            ]),
            findings: Vec::new(),
        };
    };

    let mut findings = Vec::new();
    let label = cfg_path.to_string_lossy().into_owned();
    let Ok(text) = fs::read_to_string(cfg_path) else {
        return FortigateBackdoorAuditResult {
            summary: JsonValue::OrderedObject(vec![
                ("config_supplied".to_string(), JsonValue::Bool(true)),
                ("error".to_string(), JsonValue::str("unable to read --fgt-config file")),
            ]),
            findings,
        };
    };

    let stats = audit_fortigate_backdoors_text(&label, &text, &mut findings);

    let summary = JsonValue::OrderedObject(vec![
        ("config_supplied".to_string(), JsonValue::Bool(true)),
        ("config_path".to_string(), JsonValue::str(&label)),
        (
            "admin_accounts_inspected".to_string(),
            JsonValue::Uint(stats.admins_checked),
        ),
        (
            "automation_rules_inspected".to_string(),
            JsonValue::Uint(stats.automations_checked),
        ),
        (
            "api_users_and_snmp_inspected".to_string(),
            JsonValue::Uint(stats.api_and_snmp_checked),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    FortigateBackdoorAuditResult { summary, findings }
}

#[derive(Default)]
pub struct FgtBackdoorStats {
    pub admins_checked: u64,
    pub automations_checked: u64,
    pub api_and_snmp_checked: u64,
}

#[derive(Default)]
struct AdminEntryState {
    name: String,
    accprofile: String,
    wildcard: bool,
    trusthosts: Vec<(Ipv4Addr, Ipv4Addr)>,
    ssh_keys: Vec<String>,
}

#[derive(Default)]
struct ApiUserEntryState {
    name: String,
    accprofile: String,
    trusthosts: Vec<(Ipv4Addr, Ipv4Addr)>,
}

#[derive(Default)]
struct SnmpCommunityState {
    id: String,
    name: String,
    host_ips: Vec<String>,
}

#[derive(Default)]
struct AutomationEntryState {
    kind: String, // "auto-script", "automation-action", "automation-stitch"
    name: String,
    action_type: String,
    uri_or_dest: String,
    script_body: String,
    bound_actions: Vec<String>,
}

/// Hierarchical state-machine parser for FortiOS backdoor sections.
pub fn audit_fortigate_backdoors_text(
    source_label: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) -> FgtBackdoorStats {
    let mut stats = FgtBackdoorStats::default();
    let statements = coalesce_fortios_multiline_statements(content);

    let mut config_stack: Vec<String> = Vec::new();
    let mut edit_stack: Vec<String> = Vec::new();

    let mut cur_admin: Option<AdminEntryState> = None;
    let mut cur_api_user: Option<ApiUserEntryState> = None;
    let mut cur_snmp: Option<SnmpCommunityState> = None;
    let mut cur_auto: Option<AutomationEntryState> = None;

    for stmt in statements {
        let trimmed = stmt.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("config ") {
            config_stack.push(rest.trim().to_ascii_lowercase());
            continue;
        }

        if trimmed == "end" {
            // Flush any open `edit` before popping `config`
            if config_stack.len() == 1 {
                if let Some(adm) = cur_admin.take() {
                    stats.admins_checked += 1;
                    evaluate_admin_entry(source_label, &adm, findings);
                }
                if let Some(api) = cur_api_user.take() {
                    stats.api_and_snmp_checked += 1;
                    evaluate_api_user_entry(source_label, &api, findings);
                }
                if let Some(snmp) = cur_snmp.take() {
                    stats.api_and_snmp_checked += 1;
                    evaluate_snmp_entry(source_label, &snmp, findings);
                }
                if let Some(auto) = cur_auto.take() {
                    stats.automations_checked += 1;
                    evaluate_automation_entry(source_label, &auto, findings);
                }
            }
            let _ = config_stack.pop();
            continue;
        }

        let top_cfg = config_stack.first().map(|s| s.as_str()).unwrap_or("");
        let sub_cfg = config_stack.get(1).map(|s| s.as_str()).unwrap_or("");

        if let Some(rest) = trimmed.strip_prefix("edit ") {
            let name = unquote(rest.trim());
            edit_stack.push(name.clone());

            if config_stack.len() == 1 {
                match top_cfg {
                    "system admin" => {
                        cur_admin = Some(AdminEntryState {
                            name,
                            ..Default::default()
                        });
                    }
                    "system api-user" => {
                        cur_api_user = Some(ApiUserEntryState {
                            name,
                            ..Default::default()
                        });
                    }
                    "system snmp community" => {
                        cur_snmp = Some(SnmpCommunityState {
                            id: name,
                            ..Default::default()
                        });
                    }
                    "system auto-script"
                    | "system automation-action"
                    | "system automation-stitch" => {
                        cur_auto = Some(AutomationEntryState {
                            kind: top_cfg.to_string(),
                            name,
                            ..Default::default()
                        });
                    }
                    _ => {}
                }
            }
            continue;
        }

        if trimmed == "next" {
            let _ = edit_stack.pop();
            if config_stack.len() == 1 {
                if let Some(adm) = cur_admin.take() {
                    stats.admins_checked += 1;
                    evaluate_admin_entry(source_label, &adm, findings);
                }
                if let Some(api) = cur_api_user.take() {
                    stats.api_and_snmp_checked += 1;
                    evaluate_api_user_entry(source_label, &api, findings);
                }
                if let Some(snmp) = cur_snmp.take() {
                    stats.api_and_snmp_checked += 1;
                    evaluate_snmp_entry(source_label, &snmp, findings);
                }
                if let Some(auto) = cur_auto.take() {
                    stats.automations_checked += 1;
                    evaluate_automation_entry(source_label, &auto, findings);
                }
            }
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("set ") {
            let mut parts = rest.splitn(2, char::is_whitespace);
            let Some(key) = parts.next() else {
                continue;
            };
            let val_raw = parts.next().unwrap_or("").trim();
            let key_low = key.to_ascii_lowercase();

            if top_cfg == "system admin" {
                if let Some(adm) = &mut cur_admin {
                    if key_low == "accprofile" {
                        adm.accprofile = unquote(val_raw);
                    } else if key_low == "wildcard" && unquote(val_raw) == "enable" {
                        adm.wildcard = true;
                    } else if key_low.starts_with("trusthost") {
                        if let Some(pair) = parse_fgt_ip_mask(val_raw) {
                            adm.trusthosts.push(pair);
                        }
                    } else if key_low.starts_with("ssh-public-key") {
                        let k = unquote(val_raw);
                        if !k.is_empty() {
                            adm.ssh_keys.push(k);
                        }
                    }
                }
            } else if top_cfg == "system api-user" {
                if let Some(api) = &mut cur_api_user {
                    if config_stack.len() == 1 && key_low == "accprofile" {
                        api.accprofile = unquote(val_raw);
                    } else if sub_cfg == "trusthost" && key_low == "ipv4-trusthost" {
                        if let Some(pair) = parse_fgt_ip_mask(val_raw) {
                            api.trusthosts.push(pair);
                        }
                    }
                }
            } else if top_cfg == "system snmp community" {
                if let Some(snmp) = &mut cur_snmp {
                    if config_stack.len() == 1 && key_low == "name" {
                        snmp.name = unquote(val_raw);
                    } else if sub_cfg == "hosts" && key_low == "ip" {
                        snmp.host_ips.push(unquote(val_raw));
                    }
                }
            } else if let Some(auto) = &mut cur_auto {
                if key_low == "action-type" {
                    auto.action_type = unquote(val_raw).to_ascii_lowercase();
                } else if matches!(key_low.as_str(), "uri" | "protocol" | "email-to") {
                    if !auto.uri_or_dest.is_empty() {
                        auto.uri_or_dest.push(' ');
                    }
                    auto.uri_or_dest.push_str(&unquote(val_raw));
                } else if key_low == "script" || key_low == "cli-script" || key_low == "http-body" {
                    if !auto.script_body.is_empty() {
                        auto.script_body.push('\n');
                    }
                    auto.script_body.push_str(&unquote(val_raw));
                } else if key_low == "action" || (sub_cfg == "actions" && key_low == "action") {
                    auto.bound_actions.push(unquote(val_raw));
                }
            }
        }
    }

    stats
}

fn evaluate_admin_entry(source_label: &str, adm: &AdminEntryState, findings: &mut Vec<Finding>) {
    let is_super = adm.accprofile.eq_ignore_ascii_case("super_admin")
        || adm.accprofile.eq_ignore_ascii_case("prof_admin")
        || (adm.name == "admin" && adm.accprofile.is_empty());

    if !is_super {
        return;
    }

    let has_zero_wildcard_trusthost = adm
        .trusthosts
        .iter()
        .any(|(ip, mask)| *ip == Ipv4Addr::UNSPECIFIED && *mask == Ipv4Addr::UNSPECIFIED);

    let foreign_public_trusthosts: Vec<String> = adm
        .trusthosts
        .iter()
        .filter(|(ip, mask)| {
            !(*ip == Ipv4Addr::UNSPECIFIED && *mask == Ipv4Addr::UNSPECIFIED)
                && matches!(
                    classify_ipv4(*ip),
                    IpOwnershipClass::ExternalNonFortinet
                )
        })
        .map(|(ip, mask)| format!("{}/{}", ip, mask))
        .collect();

    let non_default_name = adm.name != "admin";
    let unrestricted_trust = adm.trusthosts.is_empty() || has_zero_wildcard_trusthost;
    let has_ssh_key = !adm.ssh_keys.is_empty();

    // Flag secondary/hidden super_admin, embedded SSH keys on super_admin, wildcard super_admin,
    // or super_admin pinned to an external public IP (`trusthost1` belonging to OVA seller)
    if non_default_name || has_ssh_key || adm.wildcard || !foreign_public_trusthosts.is_empty() {
        let mut reasons = Vec::new();
        if non_default_name {
            reasons.push(format!("non-default super_admin account `{}`", adm.name));
        }
        if unrestricted_trust {
            reasons.push("no RFC1918 trusthost restriction (open to 0.0.0.0/0)".to_string());
        }
        if !foreign_public_trusthosts.is_empty() {
            reasons.push(format!(
                "pinned to external public trusthost(s) {:?}",
                foreign_public_trusthosts
            ));
        }
        if has_ssh_key {
            reasons.push(format!(
                "{} embedded ssh-public-key entry(ies)",
                adm.ssh_keys.len()
            ));
        }
        if adm.wildcard {
            reasons.push("wildcard remote admin enabled".to_string());
        }

        let ssh_hashes: Vec<JsonValue> = adm
            .ssh_keys
            .iter()
            .map(|k| JsonValue::str(sha256_hex(k.as_bytes())))
            .collect();

        findings.push(
            Finding::new(
                EngineId::FortigateBackdoorAudit,
                "HIGH_FGT_ROGUE_SUPER_ADMIN",
                Severity::High,
                format!("{}::system admin::{}", source_label, adm.name),
                format!(
                    "Suspicious FortiGate `super_admin` account `{}` in {}: {}",
                    adm.name,
                    source_label,
                    reasons.join("; ")
                ),
            )
            .with_evidence("admin_name", JsonValue::str(&adm.name))
            .with_evidence("accprofile", JsonValue::str(&adm.accprofile))
            .with_evidence("unrestricted_trusthost", JsonValue::Bool(unrestricted_trust))
            .with_evidence(
                "external_public_trusthosts",
                JsonValue::Array(
                    foreign_public_trusthosts
                        .iter()
                        .map(|s| JsonValue::str(s.as_str()))
                        .collect(),
                ),
            )
            .with_evidence("ssh_public_key_sha256s", JsonValue::Array(ssh_hashes)),
        );
    }
}

fn evaluate_automation_entry(
    source_label: &str,
    auto: &AutomationEntryState,
    findings: &mut Vec<Finding>,
) {
    let script_low = auto.script_body.to_ascii_lowercase();
    let dest_low = auto.uri_or_dest.to_ascii_lowercase();

    let has_exfil_cmd = script_low.contains("execute backup")
        || script_low.contains("exe backup")
        || script_low.contains("fnsysctl")
        || script_low.contains("tftp")
        || script_low.contains("ftp")
        || script_low.contains("scp")
        || script_low.contains("config system admin")
        || script_low.contains("set ssh-public-key");

    let has_external_webhook = auto.action_type == "webhook"
        || dest_low.contains("http://")
        || dest_low.contains("https://")
        || (!dest_low.is_empty() && auto.action_type == "email");

    if has_exfil_cmd || has_external_webhook {
        findings.push(
            Finding::new(
                EngineId::FortigateBackdoorAudit,
                "CRITICAL_FGT_AUTOMATION_EXFIL_BACKDOOR",
                Severity::Critical,
                format!("{}::{}::{}", source_label, auto.kind, auto.name),
                format!(
                    "FortiGate `{}` task `{}` performs automated config backup/CLI/webhook exfiltration (dest=`{}`, action_type=`{}`)",
                    auto.kind, auto.name, auto.uri_or_dest, auto.action_type
                ),
            )
            .with_evidence("section", JsonValue::str(&auto.kind))
            .with_evidence("task_name", JsonValue::str(&auto.name))
            .with_evidence("action_type", JsonValue::str(&auto.action_type))
            .with_evidence("destination", JsonValue::str(&auto.uri_or_dest))
            .with_evidence("script_preview", JsonValue::str(truncate_preview(&auto.script_body))),
        );
    }
}

fn evaluate_api_user_entry(
    source_label: &str,
    api: &ApiUserEntryState,
    findings: &mut Vec<Finding>,
) {
    let unrestricted = api.trusthosts.is_empty()
        || api
            .trusthosts
            .iter()
            .any(|(ip, mask)| *ip == Ipv4Addr::UNSPECIFIED && *mask == Ipv4Addr::UNSPECIFIED);

    let external_hosts: Vec<String> = api
        .trusthosts
        .iter()
        .filter(|(ip, mask)| {
            !(*ip == Ipv4Addr::UNSPECIFIED && *mask == Ipv4Addr::UNSPECIFIED)
                && classify_ipv4(*ip) == IpOwnershipClass::ExternalNonFortinet
        })
        .map(|(ip, mask)| format!("{}/{}", ip, mask))
        .collect();

    if unrestricted || !external_hosts.is_empty() {
        findings.push(
            Finding::new(
                EngineId::FortigateBackdoorAudit,
                "CRITICAL_FGT_EXPOSED_REST_API_ADMIN",
                Severity::Critical,
                format!("{}::system api-user::{}", source_label, api.name),
                format!(
                    "FortiGate REST `api-user` `{}` (profile=`{}`) exposed to external/unrestricted networks (unrestricted={}, external_trusthosts={:?})",
                    api.name, api.accprofile, unrestricted, external_hosts
                ),
            )
            .with_evidence("api_user", JsonValue::str(&api.name))
            .with_evidence("accprofile", JsonValue::str(&api.accprofile))
            .with_evidence("unrestricted_0_0_0_0", JsonValue::Bool(unrestricted))
            .with_evidence(
                "external_trusthosts",
                JsonValue::Array(external_hosts.iter().map(|s| JsonValue::str(s.as_str())).collect()),
            ),
        );
    }
}

fn evaluate_snmp_entry(
    source_label: &str,
    snmp: &SnmpCommunityState,
    findings: &mut Vec<Finding>,
) {
    let weak_name = matches!(
        snmp.name.to_ascii_lowercase().as_str(),
        "public" | "private" | "fortinet" | "admin" | "snmp"
    );
    let unrestricted_hosts = snmp.host_ips.is_empty()
        || snmp
            .host_ips
            .iter()
            .any(|h| h.starts_with("0.0.0.0"));

    if unrestricted_hosts || weak_name {
        findings.push(
            Finding::new(
                EngineId::FortigateBackdoorAudit,
                "CRITICAL_FGT_EXPOSED_REST_API_ADMIN",
                Severity::Critical,
                format!("{}::snmp community::{}", source_label, snmp.id),
                format!(
                    "FortiGate SNMP community `{}` (id={}) exposed with unrestricted host ACL or default community string",
                    snmp.name, snmp.id
                ),
            )
            .with_evidence("community_id", JsonValue::str(&snmp.id))
            .with_evidence("unrestricted_hosts", JsonValue::Bool(unrestricted_hosts))
            .with_evidence("weak_default_community", JsonValue::Bool(weak_name)),
        );
    }
}

/// Joins FortiOS multiline `"..."` values (such as `set script "..."`) into single logical lines.
fn coalesce_fortios_multiline_statements(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut esc = false;

    for raw_line in content.lines() {
        if !cur.is_empty() {
            cur.push('\n');
        }
        cur.push_str(raw_line);

        for b in raw_line.bytes() {
            if esc {
                esc = false;
                continue;
            }
            if b == b'\\' {
                esc = true;
                continue;
            }
            if b == b'"' {
                in_quotes = !in_quotes;
            }
        }

        if !in_quotes {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn parse_fgt_ip_mask(val: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let clean = unquote(val);
    if let Some((ip_s, plen_s)) = clean.split_once('/') {
        let ip: Ipv4Addr = ip_s.trim().parse().ok()?;
        if let Ok(plen) = plen_s.trim().parse::<u8>() {
            let mask_u32 = if plen == 0 {
                0
            } else {
                !0u32 << (32 - plen.min(32))
            };
            return Some((ip, Ipv4Addr::from(mask_u32)));
        }
        let mask: Ipv4Addr = plen_s.trim().parse().ok()?;
        return Some((ip, mask));
    }
    let parts: Vec<&str> = clean.split_whitespace().collect();
    if parts.len() >= 2 {
        let ip: Ipv4Addr = parts[0].parse().ok()?;
        let mask: Ipv4Addr = parts[1].parse().ok()?;
        return Some((ip, mask));
    }
    None
}

fn unquote(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

fn truncate_preview(s: &str) -> String {
    let flat = s.replace('\n', " \\n ");
    if flat.chars().count() <= 160 {
        flat
    } else {
        let mut out: String = flat.chars().take(160).collect();
        out.push_str("...");
        out
    }
}
