//! Module 2: Live Non-Destructive Network Isolation & Volatile Evidence Preservation
//! (`containment_commands.rs`).
//!
//! Dynamically derives `nftables`, `iptables`, FortiOS CLI quarantine scripts, and
//! volatile `/proc/<pid>/maps` preservation commands directly from the hostile IPs,
//! ports, Nginx `mirror` locations, PostgreSQL trust backdoors, FortiOS `auto-script`
//! targets, and compromised PIDs inside a `ForensicVerdictBundle` — **strictly without
//! rebooting the appliance, flushing kernel audit state, or terminating hooked processes**.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use fsr_clone_cluster_audit::birthmark_extractor::join_rooted;
use fsr_clone_cluster_audit::json_parser::{json_as_array, json_as_str, json_as_u64, json_get};
use fsr_deep_audit::schema::JsonValue;

/// Validated hostile network endpoint extracted dynamically from forensic findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostileNetworkEndpoint {
    pub ipv4: Ipv4Addr,
    pub ports: Vec<u16>,
    pub transport: &'static str, // "tcp", "udp", or "any"
    pub threat_role: &'static str,
    pub source_finding_codes: Vec<String>,
}

impl HostileNetworkEndpoint {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("ipv4".to_string(), JsonValue::str(self.ipv4.to_string())),
            (
                "ports".to_string(),
                JsonValue::Array(
                    self.ports
                        .iter()
                        .map(|&p| JsonValue::Uint(p as u64))
                        .collect(),
                ),
            ),
            ("transport".to_string(), JsonValue::str(self.transport)),
            ("threat_role".to_string(), JsonValue::str(self.threat_role)),
            (
                "source_finding_codes".to_string(),
                JsonValue::Array(
                    self.source_finding_codes
                        .iter()
                        .map(|c| JsonValue::str(c.as_str()))
                        .collect(),
                ),
            ),
        ])
    }
}

/// Complete output of Module 2 (`containment_commands`).
#[derive(Debug, Clone)]
pub struct ContainmentCommandSuite {
    pub containment_required: bool,
    pub zero_reboot_mandate_tr: String,
    pub compromised_pids: Vec<u32>,
    pub nginx_mirror_uris: Vec<String>,
    pub pg_external_trust_exposed: bool,
    pub fortios_autoscripts_to_disable: Vec<String>,
    pub fortios_rogue_admins_to_lock: Vec<String>,
    pub hostile_endpoints: Vec<HostileNetworkEndpoint>,
    pub volatile_evidence_preservation_commands: Vec<String>,
    pub nftables_quarantine_script: String,
    pub iptables_quarantine_script: String,
    pub fortios_cli_quarantine_script: String,
}

impl ContainmentCommandSuite {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            (
                "containment_required".to_string(),
                JsonValue::Bool(self.containment_required),
            ),
            (
                "zero_reboot_mandate_tr".to_string(),
                JsonValue::str(&self.zero_reboot_mandate_tr),
            ),
            (
                "compromised_pids".to_string(),
                JsonValue::Array(
                    self.compromised_pids
                        .iter()
                        .map(|&p| JsonValue::Uint(p as u64))
                        .collect(),
                ),
            ),
            (
                "nginx_mirror_uris".to_string(),
                JsonValue::Array(
                    self.nginx_mirror_uris
                        .iter()
                        .map(|u| JsonValue::str(u.as_str()))
                        .collect(),
                ),
            ),
            (
                "pg_external_trust_exposed".to_string(),
                JsonValue::Bool(self.pg_external_trust_exposed),
            ),
            (
                "fortios_autoscripts_to_disable".to_string(),
                JsonValue::Array(
                    self.fortios_autoscripts_to_disable
                        .iter()
                        .map(|s| JsonValue::str(s.as_str()))
                        .collect(),
                ),
            ),
            (
                "fortios_rogue_admins_to_lock".to_string(),
                JsonValue::Array(
                    self.fortios_rogue_admins_to_lock
                        .iter()
                        .map(|s| JsonValue::str(s.as_str()))
                        .collect(),
                ),
            ),
            (
                "hostile_endpoints".to_string(),
                JsonValue::Array(self.hostile_endpoints.iter().map(|e| e.to_json()).collect()),
            ),
            (
                "volatile_evidence_preservation_commands".to_string(),
                JsonValue::Array(
                    self.volatile_evidence_preservation_commands
                        .iter()
                        .map(|c| JsonValue::str(c.as_str()))
                        .collect(),
                ),
            ),
            (
                "nftables_quarantine_script".to_string(),
                JsonValue::str(&self.nftables_quarantine_script),
            ),
            (
                "iptables_quarantine_script".to_string(),
                JsonValue::str(&self.iptables_quarantine_script),
            ),
            (
                "fortios_cli_quarantine_script".to_string(),
                JsonValue::str(&self.fortios_cli_quarantine_script),
            ),
        ])
    }
}

#[derive(Default)]
struct EndpointAccumulator {
    ports: BTreeSet<u16>,
    has_udp: bool,
    has_tcp: bool,
    role_priority: u8,
    threat_role: &'static str,
    codes: BTreeSet<String>,
}

/// Synthesizes live forensic preservation & network quarantine command sets from a
/// parsed `ForensicVerdictBundle` JSON document and optional `--root` directory.
pub fn build_containment_command_suite(
    bundle_doc: &JsonValue,
    effective_root: Option<&Path>,
) -> ContainmentCommandSuite {
    let mut endpoints_map: BTreeMap<u32, EndpointAccumulator> = BTreeMap::new();
    let mut compromised_pids: BTreeSet<u32> = BTreeSet::new();
    let mut nginx_mirror_uris: BTreeSet<String> = BTreeSet::new();
    let mut pg_external_trust_exposed = false;
    let mut ebpf_pins_detected: BTreeSet<String> = BTreeSet::new();
    let mut fortios_autoscripts: BTreeSet<String> = BTreeSet::new();
    let mut fortios_rogue_admins: BTreeSet<String> = BTreeSet::new();
    let mut total_findings_seen = 0usize;

    if let Some(findings) = json_get(bundle_doc, "findings").and_then(json_as_array) {
        total_findings_seen = findings.len();
        for f in findings {
            let Some(code) = json_get(f, "code").and_then(json_as_str) else {
                continue;
            };
            let target = json_get(f, "target").and_then(json_as_str).unwrap_or("");
            let detail = json_get(f, "detail").and_then(json_as_str).unwrap_or("");
            let ev = json_get(f, "evidence");

            // 1. Extract compromised live PIDs for `/proc/<pid>/maps` & VMA preservation
            if matches!(
                code,
                "CRITICAL_ELF_TEXT_INLINE_PATCH"
                    | "CRITICAL_GOT_PLT_POINTER_HIJACK"
                    | "CRITICAL_DELETED_EXECUTABLE_MAPPING"
                    | "CRITICAL_EPHEMERAL_SHARED_OBJECT_INJECTION"
            ) {
                if let Some(ev_obj) = ev {
                    if let Some(pid_u) = json_get(ev_obj, "pid").and_then(json_as_u64) {
                        if let Ok(p) = u32::try_from(pid_u) {
                            compromised_pids.insert(p);
                        }
                    }
                }
                if let Some(p) = extract_proc_pid_from_text(target)
                    .or_else(|| extract_proc_pid_from_text(detail))
                {
                    compromised_pids.insert(p);
                }
            }

            // 2. Track PostgreSQL `0.0.0.0/0 trust` exposure
            if code == "CRITICAL_PG_HBA_TRUST_BACKDOOR" {
                pg_external_trust_exposed = true;
            }

            // 3. Track eBPF pins
            if matches!(
                code,
                "CRITICAL_EBPF_NET_HIJACK" | "CRITICAL_LIVE_EBPF_SOCKET_HOOK"
            ) && target.starts_with('/')
            {
                ebpf_pins_detected.insert(target.to_string());
            }

            // 4. Track Nginx `mirror` directives
            if code == "CRITICAL_NGINX_TRAFFIC_MIRROR_OR_BYPASS" {
                if let Some(ev_obj) = ev {
                    if let Some(m_uri) = json_get(ev_obj, "directive_argument")
                        .or_else(|| json_get(ev_obj, "mirror_uri"))
                        .and_then(json_as_str)
                    {
                        if let Some(clean_uri) = sanitize_identifier_or_uri(m_uri) {
                            nginx_mirror_uris.insert(clean_uri);
                        }
                    }
                }
                for tok in extract_mirror_uris_from_text(detail) {
                    nginx_mirror_uris.insert(tok);
                }
            }

            // 5. Track FortiOS `auto-script` & rogue `super_admin` / `api-user` identifiers
            if code == "CRITICAL_FGT_AUTOMATION_EXFIL_BACKDOOR" {
                if let Some(name) = extract_identifier_after_colon(target) {
                    fortios_autoscripts.insert(name);
                }
            }
            if matches!(
                code,
                "HIGH_FGT_ROGUE_SUPER_ADMIN" | "CRITICAL_FGT_EXPOSED_REST_API_ADMIN"
            ) {
                if let Some(name) = extract_identifier_after_colon(target) {
                    fortios_rogue_admins.insert(name);
                }
            }

            // 6. Dynamically extract hostile IPv4 + Port pairs according to finding class
            if let Some((role_prio, role_name, default_ports, is_udp)) =
                classify_network_finding_role(code)
            {
                let mut raw_strings = vec![target.to_string(), detail.to_string()];
                if let Some(ev_obj) = ev {
                    collect_json_strings(ev_obj, &mut raw_strings);
                }

                for text in &raw_strings {
                    for (ip, parsed_port, url_udp) in extract_ipv4_and_ports(text) {
                        if !is_quarantinable_hostile_ipv4(ip) {
                            continue;
                        }
                        let entry =
                            endpoints_map.entry(u32::from(ip)).or_insert_with(|| {
                                EndpointAccumulator {
                                    threat_role: role_name,
                                    role_priority: role_prio,
                                    ..Default::default()
                                }
                            });
                        if role_prio > entry.role_priority {
                            entry.role_priority = role_prio;
                            entry.threat_role = role_name;
                        }
                        if let Some(p) = parsed_port {
                            entry.ports.insert(p);
                        } else {
                            for &dp in default_ports {
                                entry.ports.insert(dp);
                            }
                        }
                        if is_udp || url_udp {
                            entry.has_udp = true;
                        } else {
                            entry.has_tcp = true;
                        }
                        entry.codes.insert(code.to_string());
                    }
                }
            }
        }
    }

    // 7. Resolve Nginx `mirror` upstream `proxy_pass` IPs from `<root>/etc/nginx/**` if present
    if !nginx_mirror_uris.is_empty() {
        if let Some(root) = effective_root {
            for (ip, port_opt) in resolve_nginx_mirror_upstreams(root) {
                if is_quarantinable_hostile_ipv4(ip) {
                    let entry = endpoints_map.entry(u32::from(ip)).or_insert_with(|| {
                        EndpointAccumulator {
                            threat_role: "NGINX_SHADOW_MIRROR_UPSTREAM",
                            role_priority: 95,
                            ..Default::default()
                        }
                    });
                    entry.has_tcp = true;
                    if let Some(p) = port_opt {
                        entry.ports.insert(p);
                    } else {
                        entry.ports.insert(80);
                        entry.ports.insert(443);
                    }
                    entry
                        .codes
                        .insert("CRITICAL_NGINX_TRAFFIC_MIRROR_OR_BYPASS".to_string());
                }
            }
        }
    }

    let mut hostile_endpoints = Vec::with_capacity(endpoints_map.len());
    for (ip_u32, acc) in endpoints_map {
        let ipv4 = Ipv4Addr::from(ip_u32);
        let transport = match (acc.has_tcp, acc.has_udp) {
            (true, false) => "tcp",
            (false, true) => "udp",
            _ => "any",
        };
        hostile_endpoints.push(HostileNetworkEndpoint {
            ipv4,
            ports: acc.ports.into_iter().collect(),
            transport,
            threat_role: acc.threat_role,
            source_finding_codes: acc.codes.into_iter().collect(),
        });
    }

    let containment_required = !hostile_endpoints.is_empty()
        || !compromised_pids.is_empty()
        || !nginx_mirror_uris.is_empty()
        || pg_external_trust_exposed
        || !fortios_autoscripts.is_empty()
        || !fortios_rogue_admins.is_empty()
        || total_findings_seen > 0;

    let pids_vec: Vec<u32> = compromised_pids.into_iter().collect();
    let mirrors_vec: Vec<String> = nginx_mirror_uris.into_iter().collect();
    let autoscripts_vec: Vec<String> = fortios_autoscripts.into_iter().collect();
    let admins_vec: Vec<String> = fortios_rogue_admins.into_iter().collect();
    let ebpf_vec: Vec<String> = ebpf_pins_detected.into_iter().collect();

    let zero_reboot_mandate_tr = "KRİTİK ADLİ TALİMAT: Cihazı KESİNLİKLE yeniden başlatmayın (`reboot`/`shutdown` YASAK) ve `uwsgi`, `celery`, `nginx`, `postgres` süreçlerini sonlandırmayın! Bellekteki yamalı `.text`/`.got.plt` sayfaları ve `/dev/shm` üzerindeki silinmiş (`deleted`) paylaşımlı kütüphaneler yalnızca süreçler çalışırken `/proc/<pid>/maps` ve `/proc/<pid>/mem` üzerinden yakalanabilir.".to_string();

    let volatile_cmds =
        build_volatile_preservation_commands(&pids_vec, &ebpf_vec, containment_required);
    let nft_script = build_nftables_script(
        &hostile_endpoints,
        pg_external_trust_exposed,
        &mirrors_vec,
        containment_required,
    );
    let ipt_script = build_iptables_script(
        &hostile_endpoints,
        pg_external_trust_exposed,
        containment_required,
    );
    let fortios_script = build_fortios_quarantine_script(
        &hostile_endpoints,
        &autoscripts_vec,
        &admins_vec,
        containment_required,
    );

    ContainmentCommandSuite {
        containment_required,
        zero_reboot_mandate_tr,
        compromised_pids: pids_vec,
        nginx_mirror_uris: mirrors_vec,
        pg_external_trust_exposed,
        fortios_autoscripts_to_disable: autoscripts_vec,
        fortios_rogue_admins_to_lock: admins_vec,
        hostile_endpoints,
        volatile_evidence_preservation_commands: volatile_cmds,
        nftables_quarantine_script: nft_script,
        iptables_quarantine_script: ipt_script,
        fortios_cli_quarantine_script: fortios_script,
    }
}

fn classify_network_finding_role(
    code: &str,
) -> Option<(u8, &'static str, &'static [u16], bool)> {
    match code {
        "CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER" => {
            Some((100, "SOAR_CREDENTIAL_SKIMMER_C2", &[443, 8443], false))
        }
        "CRITICAL_PG_COMMAND_EXECUTION_HOOK" => {
            Some((95, "POSTGRES_WAL_HOOK_C2", &[80, 443], false))
        }
        "CRITICAL_FGT_AUTOMATION_EXFIL_BACKDOOR" => {
            Some((95, "FORTIOS_CONFIG_EXFIL_SINK", &[69, 22, 443], true))
        }
        "CRITICAL_NGINX_TRAFFIC_MIRROR_OR_BYPASS" => {
            Some((90, "NGINX_SHADOW_MIRROR_TARGET", &[80, 443, 8080], false))
        }
        "CRITICAL_STATIC_DNS_FORTIGUARD_HIJACK" | "CRITICAL_LIVE_FAKE_FDN_RESPONDER" => {
            Some((85, "ROGUE_FDN_LICENSE_EMULATOR", &[443, 8890, 53], false))
        }
        "CRITICAL_FGT_CENTRAL_MGMT_FDS_EMULATOR" | "HIGH_FGT_CENTRAL_MGMT_FMG_ENDPOINT" => {
            Some((85, "ROGUE_FMG_FDS_UPDATE_EMULATOR", &[443, 541, 8890], false))
        }
        "CRITICAL_FGT_ROGUE_SDNS_SERVER" => Some((80, "ROGUE_SDNS_SERVER", &[53, 853], true)),
        "CRITICAL_ROUTE_HIJACK_FORTINET_ASN" => {
            Some((80, "AS40934_ROUTE_HIJACK_GATEWAY", &[443, 8890], false))
        }
        _ => None,
    }
}

/// Filters out loopback, unspecified, netmask octets (`255.*`), and official Fortinet AS40934
/// destination ranges (`173.243.128.0/19`, `96.45.32.0/19`, `208.91.112.0/21`) so we quarantine
/// ONLY the attacker's emulator/gateway/C2 IP — never legitimate Fortinet ranges or localhost!
fn is_quarantinable_hostile_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    if ip.is_loopback() || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
        return false;
    }
    if o[0] == 255 || o[3] == 0 || o[3] == 255 {
        // Excludes subnet network addresses (e.g. `173.243.128.0`) and netmasks (`255.255.224.0`)
        return false;
    }
    // Exclude official Fortinet AS40934 blocks
    let u = u32::from(ip);
    let in_as40934 = (u & 0xFFFF_E000) == u32::from(Ipv4Addr::new(173, 243, 128, 0))
        || (u & 0xFFFF_E000) == u32::from(Ipv4Addr::new(96, 45, 32, 0))
        || (u & 0xFFFF_F800) == u32::from(Ipv4Addr::new(208, 91, 112, 0));
    !in_as40934
}

fn collect_json_strings(val: &JsonValue, out: &mut Vec<String>) {
    match val {
        JsonValue::Str(s) => out.push(s.clone()),
        JsonValue::Array(arr) => {
            for item in arr {
                collect_json_strings(item, out);
            }
        }
        JsonValue::OrderedObject(fields) => {
            for (_, v) in fields {
                collect_json_strings(v, out);
            }
        }
        _ => {}
    }
}

/// Scans arbitrary text for `scheme://IP[:PORT]` URLs and standalone `A.B.C.D[:PORT]` tokens.
fn extract_ipv4_and_ports(text: &str) -> Vec<(Ipv4Addr, Option<u16>, bool)> {
    let mut results = Vec::new();
    let lower = text.to_ascii_lowercase();
    let mentions_tftp = lower.contains("tftp");

    for raw_tok in text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '\'' | '"' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '<' | '>'
            )
    }) {
        if raw_tok.is_empty() {
            continue;
        }
        let mut scheme_default_port: Option<u16> = None;
        let mut is_udp = mentions_tftp;

        let host_port_candidate = if let Some((scheme, rest)) = raw_tok.split_once("://") {
            match scheme.to_ascii_lowercase().as_str() {
                "https" => scheme_default_port = Some(443),
                "http" => scheme_default_port = Some(80),
                "tftp" => {
                    scheme_default_port = Some(69);
                    is_udp = true;
                }
                _ => {}
            }
            let authority = rest.split('/').next().unwrap_or(rest);
            authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority)
        } else {
            raw_tok.split('/').next().unwrap_or(raw_tok)
        };

        let trimmed = host_port_candidate.trim_matches('.');
        if let Some((ip_part, port_part)) = trimmed.split_once(':') {
            if let Ok(ip) = ip_part.parse::<Ipv4Addr>() {
                let port = port_part
                    .parse::<u16>()
                    .ok()
                    .filter(|&p| p > 0)
                    .or(scheme_default_port);
                results.push((ip, port, is_udp));
                continue;
            }
        }
        if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
            let fallback_port = if mentions_tftp {
                Some(69)
            } else {
                scheme_default_port
            };
            results.push((ip, fallback_port, is_udp));
        }
    }

    results
}

fn extract_proc_pid_from_text(s: &str) -> Option<u32> {
    let idx = s.find("/proc/")?;
    let after = &s[idx + "/proc/".len()..];
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<u32>().ok().filter(|&p| p > 1)
    }
}

fn extract_mirror_uris_from_text(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(idx) = rest.find("mirror ") {
        let after = rest[idx + "mirror ".len()..].trim_start();
        let tok: String = after
            .chars()
            .take_while(|c| {
                c.is_ascii_alphanumeric() || matches!(*c, '/' | '_' | '-' | '.')
            })
            .collect();
        if tok.starts_with('/') {
            out.push(tok);
        }
        rest = &after[1.min(after.len())..];
    }
    out
}

fn extract_identifier_after_colon(target: &str) -> Option<String> {
    let cand = target.rsplit_once(':').map(|(_, r)| r).unwrap_or(target);
    sanitize_identifier_or_uri(cand)
}

fn sanitize_identifier_or_uri(s: &str) -> Option<String> {
    let trimmed = s.trim().trim_matches(|c| c == '"' || c == '\'' || c == ';');
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    if trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'/' | b'.'))
    {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn resolve_nginx_mirror_upstreams(root: &Path) -> Vec<(Ipv4Addr, Option<u16>)> {
    let mut found = Vec::new();
    let nginx_dir = join_rooted(root, "etc/nginx");
    let mut conf_files = Vec::new();
    collect_nginx_confs(&nginx_dir, 3, &mut conf_files);
    for cf in conf_files {
        let Ok(text) = fs::read_to_string(&cf) else {
            continue;
        };
        for line in text.lines() {
            if line.contains("proxy_pass") {
                for (ip, port, _) in extract_ipv4_and_ports(line) {
                    if !ip.is_loopback() {
                        found.push((ip, port));
                    }
                }
            }
        }
    }
    found
}

fn collect_nginx_confs(dir: &Path, depth: usize, out: &mut Vec<std::path::PathBuf>) {
    if depth == 0 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_nginx_confs(&p, depth - 1, out);
        } else if p.extension().and_then(|x| x.to_str()) == Some("conf") {
            out.push(p);
        }
    }
}

fn build_volatile_preservation_commands(
    compromised_pids: &[u32],
    ebpf_pins: &[String],
    containment_required: bool,
) -> Vec<String> {
    if !containment_required {
        return Vec::new();
    }
    let mut cmds = vec![
        "# [ADIM 0] Harici yazılabilir adli kanıt dizini oluşturun (cihazın kendi diskine minimum yazma / tercihen harici IR USB/NFS):".to_string(),
        "export FSR_IR_VOLATILE=\"/mnt/ir_evidence/volatile_$(hostname)_$(date -u +%Y%m%dT%H%M%SZ)\" && mkdir -p \"${FSR_IR_VOLATILE}\"".to_string(),
        "# [ADIM 1] Ağ karantinası ÖNCESİ aktif soket, yönlendirme, Netfilter ve ARP durumunu dondurun:".to_string(),
        "ss -tupnae > \"${FSR_IR_VOLATILE}/ss_active_sockets.txt\" && ip route show table all > \"${FSR_IR_VOLATILE}/ip_routes_all.txt\" && ip rule show > \"${FSR_IR_VOLATILE}/ip_rules.txt\"".to_string(),
        "nft list ruleset > \"${FSR_IR_VOLATILE}/nft_ruleset_pre.txt\" 2>/dev/null; iptables-save > \"${FSR_IR_VOLATILE}/iptables_pre.txt\" 2>/dev/null".to_string(),
    ];

    for &pid in compromised_pids {
        cmds.push(format!(
            "# [ADIM 2 - PID {pid}] Bellekte yamalanmış sürecin VMA haritasını, açık dosya tanımlayıcılarını ve silinmiş `.so` imajlarını SÜRECİ ÖLDÜRMEDEN kopyalayın:"
        ));
        cmds.push(format!(
            "mkdir -p \"${{FSR_IR_VOLATILE}}/pid_{pid}\" && cat /proc/{pid}/maps > \"${{FSR_IR_VOLATILE}}/pid_{pid}/maps.txt\" && cat /proc/{pid}/smaps > \"${{FSR_IR_VOLATILE}}/pid_{pid}/smaps.txt\" && tr '\\0' '\\n' < /proc/{pid}/environ > \"${{FSR_IR_VOLATILE}}/pid_{pid}/environ.txt\""
        ));
        cmds.push(format!(
            "ls -la /proc/{pid}/fd /proc/{pid}/map_files > \"${{FSR_IR_VOLATILE}}/pid_{pid}/fd_and_map_files.txt\" 2>&1"
        ));
        cmds.push(format!(
            "command -v gcore >/dev/null 2>&1 && gcore -o \"${{FSR_IR_VOLATILE}}/pid_{pid}/core_live\" {pid}"
        ));
    }

    if !ebpf_pins.is_empty() {
        cmds.push(
            "# [ADIM 3 - eBPF] Çekirdekte pinlenmiş eBPF soket/cgroup kancalarının bytecode dökümünü alın:"
                .to_string(),
        );
        cmds.push(
            "bpftool prog show > \"${FSR_IR_VOLATILE}/bpftool_prog_show.txt\" 2>&1 && bpftool cgroup tree > \"${FSR_IR_VOLATILE}/bpftool_cgroup_tree.txt\" 2>&1"
                .to_string(),
        );
    }

    cmds.push(
        "sha256sum \"${FSR_IR_VOLATILE}\"/* \"${FSR_IR_VOLATILE}\"/pid_*/* 2>/dev/null > \"${FSR_IR_VOLATILE}/MANIFEST.sha256\""
            .to_string(),
    );
    cmds
}

fn build_nftables_script(
    endpoints: &[HostileNetworkEndpoint],
    pg_external_trust: bool,
    nginx_mirrors: &[String],
    containment_required: bool,
) -> String {
    if !containment_required {
        return "# Temiz sistem: uygulanacak nftables karantina kuralı yok.\n".to_string();
    }

    let mut s = String::with_capacity(2048);
    let _ = writeln!(
        s,
        "# Non-destructive atomic nftables quarantine (mevcut tabloları silmez, süreçleri ve /proc/<pid>/maps kanıtlarını korur)"
    );
    if !nginx_mirrors.is_empty() {
        let _ = writeln!(
            s,
            "# Tespit edilen Nginx gölge kopyalama (mirror) konumları: {}",
            nginx_mirrors.join(", ")
        );
    }
    let _ = writeln!(s, "nft -f - <<'EOF'");
    let _ = writeln!(s, "table inet fsr_ir_quarantine {{");

    if !endpoints.is_empty() {
        let ip_list: Vec<String> = endpoints.iter().map(|e| e.ipv4.to_string()).collect();
        let _ = writeln!(s, "    set hostile_ipv4 {{");
        let _ = writeln!(s, "        type ipv4_addr");
        let _ = writeln!(s, "        elements = {{ {} }}", ip_list.join(", "));
        let _ = writeln!(s, "    }}");
    }

    let _ = writeln!(s, "    chain ir_output {{");
    let _ = writeln!(
        s,
        "        type filter hook output priority -400; policy accept;"
    );
    let _ = writeln!(s, "        oif \"lo\" accept");

    for ep in endpoints {
        if !ep.ports.is_empty() {
            let ports_csv: Vec<String> = ep.ports.iter().map(|p| p.to_string()).collect();
            let proto = if ep.transport == "udp" { "udp" } else { "tcp" };
            let _ = writeln!(
                s,
                "        # {} ({})",
                ep.threat_role,
                ep.source_finding_codes.join(", ")
            );
            let _ = writeln!(
                s,
                "        ip daddr {} {} dport {{ {} }} counter log prefix \"FSR-IR-OUT-DROP: \" drop",
                ep.ipv4,
                proto,
                ports_csv.join(", ")
            );
        }
    }
    if !endpoints.is_empty() {
        let _ = writeln!(
            s,
            "        ip daddr @hostile_ipv4 counter log prefix \"FSR-IR-HOSTILE-DROP: \" drop"
        );
    }
    let _ = writeln!(s, "    }}");

    let _ = writeln!(s, "    chain ir_input {{");
    let _ = writeln!(
        s,
        "        type filter hook input priority -400; policy accept;"
    );
    let _ = writeln!(s, "        iif \"lo\" accept");
    if !endpoints.is_empty() {
        let _ = writeln!(
            s,
            "        ip saddr @hostile_ipv4 counter log prefix \"FSR-IR-IN-DROP: \" drop"
        );
    }
    if pg_external_trust {
        let _ = writeln!(
            s,
            "        # CRITICAL_PG_HBA_TRUST_BACKDOOR: Yerel uwsgi/celery loopback erişimini bozmadan dış PostgreSQL (5432) erişimini kes"
        );
        let _ = writeln!(
            s,
            "        tcp dport 5432 counter log prefix \"FSR-IR-PG5432-DROP: \" drop"
        );
    }
    let _ = writeln!(s, "    }}");
    let _ = writeln!(s, "}}");
    let _ = writeln!(s, "EOF");
    s
}

fn build_iptables_script(
    endpoints: &[HostileNetworkEndpoint],
    pg_external_trust: bool,
    containment_required: bool,
) -> String {
    if !containment_required {
        return "# Temiz sistem: uygulanacak iptables karantina kuralı yok.\n".to_string();
    }

    let mut s = String::with_capacity(1536);
    let _ = writeln!(
        s,
        "# Legacy iptables fallback karantina zinciri (mevcut kuralları flush ETMEZ)"
    );
    let _ = writeln!(
        s,
        "iptables -N FSR_IR_OUT 2>/dev/null || iptables -F FSR_IR_OUT"
    );
    let _ = writeln!(
        s,
        "iptables -N FSR_IR_IN 2>/dev/null || iptables -F FSR_IR_IN"
    );
    let _ = writeln!(s, "iptables -A FSR_IR_OUT -o lo -j ACCEPT");
    let _ = writeln!(s, "iptables -A FSR_IR_IN -i lo -j ACCEPT");

    for ep in endpoints {
        for &port in &ep.ports {
            let proto = if ep.transport == "udp" { "udp" } else { "tcp" };
            let _ = writeln!(
                s,
                "iptables -A FSR_IR_OUT -d {}/32 -p {} --dport {} -j DROP",
                ep.ipv4, proto, port
            );
        }
        let _ = writeln!(
            s,
            "iptables -A FSR_IR_OUT -d {}/32 -j DROP # {}",
            ep.ipv4, ep.threat_role
        );
        let _ = writeln!(s, "iptables -A FSR_IR_IN -s {}/32 -j DROP", ep.ipv4);
    }

    if pg_external_trust {
        let _ = writeln!(
            s,
            "iptables -A FSR_IR_IN ! -i lo -p tcp --dport 5432 -j DROP # CRITICAL_PG_HBA_TRUST_BACKDOOR"
        );
    }

    let _ = writeln!(
        s,
        "iptables -C OUTPUT -j FSR_IR_OUT 2>/dev/null || iptables -I OUTPUT 1 -j FSR_IR_OUT"
    );
    let _ = writeln!(
        s,
        "iptables -C INPUT -j FSR_IR_IN 2>/dev/null || iptables -I INPUT 1 -j FSR_IR_IN"
    );
    s
}

fn build_fortios_quarantine_script(
    endpoints: &[HostileNetworkEndpoint],
    autoscripts: &[String],
    rogue_admins: &[String],
    containment_required: bool,
) -> String {
    if !containment_required {
        return "# Temiz sistem: uygulanacak FortiOS CLI karantina komutu yok.\n".to_string();
    }

    let mut s = String::with_capacity(2048);
    let _ = writeln!(
        s,
        "# FortiOS Sınır Güvenlik Duvarı & Cihaz Karantina Komut Seti (Reboot Gerektirmez)"
    );

    if !endpoints.is_empty() {
        let _ = writeln!(s, "config firewall address");
        let mut obj_names = Vec::new();
        for ep in endpoints {
            let obj_name = format!("FSR_IR_BLOCK_{}", ep.ipv4.to_string().replace('.', "_"));
            let _ = writeln!(s, "    edit \"{}\"", obj_name);
            let _ = writeln!(s, "        set subnet {} 255.255.255.255", ep.ipv4);
            let _ = writeln!(s, "        set comment \"FSR-IR: {}\"", ep.threat_role);
            let _ = writeln!(s, "    next");
            obj_names.push(format!("\"{}\"", obj_name));
        }
        let _ = writeln!(s, "end");

        let _ = writeln!(s, "config firewall addrgrp");
        let _ = writeln!(s, "    edit \"FSR_IR_HOSTILE_GROUP\"");
        let _ = writeln!(s, "        set member {}", obj_names.join(" "));
        let _ = writeln!(s, "    next");
        let _ = writeln!(s, "end");

        let _ = writeln!(s, "# Kırık SOAR cihazından sahte FDN / C2 / Mirror IP grubuna giden tüm trafiği en üst sırada blokla:");
        let _ = writeln!(s, "config firewall policy");
        let _ = writeln!(s, "    edit 0");
        let _ = writeln!(s, "        set name \"FSR_IR_EMERGENCY_CONTAINMENT\"");
        let _ = writeln!(s, "        set srcintf \"any\"");
        let _ = writeln!(s, "        set dstintf \"any\"");
        let _ = writeln!(s, "        set srcaddr \"all\"");
        let _ = writeln!(s, "        set dstaddr \"FSR_IR_HOSTILE_GROUP\"");
        let _ = writeln!(s, "        set action deny");
        let _ = writeln!(s, "        set schedule \"always\"");
        let _ = writeln!(s, "        set service \"ALL\"");
        let _ = writeln!(s, "        set logtraffic all");
        let _ = writeln!(s, "    next");
        let _ = writeln!(s, "end");
    }

    if !autoscripts.is_empty() {
        let _ = writeln!(
            s,
            "# Tespit edilen arka kapı FortiOS `auto-script` görevlerini durdur ve sil:"
        );
        for script_name in autoscripts {
            let _ = writeln!(s, "execute auto-script stop {}", script_name);
        }
        let _ = writeln!(s, "config system auto-script");
        for script_name in autoscripts {
            let _ = writeln!(s, "    delete \"{}\"", script_name);
        }
        let _ = writeln!(s, "end");
    }

    if !rogue_admins.is_empty() {
        let _ = writeln!(
            s,
            "# Tespit edilen yetkisiz / `0.0.0.0/0` açık yönetici ve REST API hesaplarını loopback'e kilitle:"
        );
        for admin_name in rogue_admins {
            let _ = writeln!(
                s,
                "# İnceleme sonrası silin: config system admin / api-user -> edit \"{}\" -> set trusthost1 127.0.0.1 255.255.255.255",
                admin_name
            );
        }
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsr_clone_cluster_audit::json_parser::parse_json_str;

    #[test]
    fn dynamically_derives_nftables_iptables_and_fortios_rules_excluding_fortinet_asn() {
        let bundle = r#"{
          "schema_version": "1.0.0",
          "findings": [
            {
              "code": "CRITICAL_ELF_TEXT_INLINE_PATCH",
              "target": "/proc/4242/mem",
              "detail": "Inline patch in uwsgi",
              "evidence": {"pid": 4242}
            },
            {
              "code": "CRITICAL_ROUTE_HIJACK_FORTINET_ASN",
              "target": "/proc/net/route",
              "detail": "Fortinet AS40934 subnet 173.243.128.0/19 routed via 10.254.254.1",
              "evidence": {"destination": "173.243.128.0", "gateway": "10.254.254.1"}
            },
            {
              "code": "CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER",
              "target": "/opt/cyops-integrations/integrations/connectors/s1/operations.py",
              "detail": "Exfiltrates config to https://198.51.100.88:8443/qa_sink",
              "evidence": {"sink": "https://198.51.100.88:8443/qa_sink"}
            },
            {
              "code": "CRITICAL_PG_HBA_TRUST_BACKDOOR",
              "target": "/var/lib/pgsql/16/data/pg_hba.conf",
              "detail": "0.0.0.0/0 trust"
            },
            {
              "code": "CRITICAL_FGT_AUTOMATION_EXFIL_BACKDOOR",
              "target": "fgt.conf:auto-script:qa_backup_exfil",
              "detail": "execute backup full-config tftp qa.conf 198.51.100.220"
            }
          ]
        }"#;
        let doc = parse_json_str(bundle).unwrap();
        let suite = build_containment_command_suite(&doc, None);

        assert!(suite.containment_required);
        assert_eq!(suite.compromised_pids, vec![4242]);
        assert!(suite.pg_external_trust_exposed);
        assert_eq!(
            suite.fortios_autoscripts_to_disable,
            vec!["qa_backup_exfil".to_string()]
        );

        let ips: Vec<String> = suite
            .hostile_endpoints
            .iter()
            .map(|e| e.ipv4.to_string())
            .collect();
        assert!(ips.contains(&"10.254.254.1".to_string()));
        assert!(ips.contains(&"198.51.100.88".to_string()));
        assert!(ips.contains(&"198.51.100.220".to_string()));
        // Official Fortinet AS40934 (`173.243.128.0`) and `0.0.0.0` MUST NOT be treated as attacker IPs!
        assert!(!ips.iter().any(|ip| ip.starts_with("173.243.")));
        assert!(!ips.contains(&"0.0.0.0".to_string()));

        assert!(suite.nftables_quarantine_script.contains("198.51.100.88"));
        assert!(suite.nftables_quarantine_script.contains("8443"));
        assert!(suite.nftables_quarantine_script.contains("tcp dport 5432"));
        assert!(suite.iptables_quarantine_script.contains("198.51.100.88/32"));
        assert!(suite
            .fortios_cli_quarantine_script
            .contains("FSR_IR_BLOCK_198_51_100_88"));
        assert!(suite
            .fortios_cli_quarantine_script
            .contains("delete \"qa_backup_exfil\""));
        assert!(suite
            .volatile_evidence_preservation_commands
            .iter()
            .any(|c| c.contains("/proc/4242/maps")));
    }
}
