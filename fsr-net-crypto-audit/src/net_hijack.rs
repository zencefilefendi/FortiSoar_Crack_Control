//! Engine 1: Kernel Network Redirection, Netfilter DNAT/fwmark & eBPF Socket Hook Detector.
//!
//! Detects static/dynamic DNS hijacking of Fortinet/FortiGuard/FortiCloud domains,
//! IP routing & policy routing overrides targeting Fortinet AS40934 blocks, Netfilter
//! `OUTPUT`/`PREROUTING` `DNAT`/`REDIRECT`/`fwmark` interception rules, and kernel eBPF
//! socket-redirection hooks (`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`, `BPF_PROG_TYPE_SOCK_OPS`).

use std::collections::BTreeSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use fsr_deep_audit::crypto::hex_encode;
use fsr_deep_audit::hw_integrity::{join_rooted, raw_syscall_read_file};
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};

use crate::ip_asn::{
    cidr_overlaps_fortinet_as40934, classify_ip, is_fortinet_domain, parse_ipv4_cidr,
};

/// Linux `enum bpf_prog_type` constants (`include/uapi/linux/bpf.h`).
pub const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 12;
pub const BPF_PROG_TYPE_SOCK_OPS: u32 = 13;
pub const BPF_PROG_TYPE_SK_SKB: u32 = 14;
pub const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
pub const BPF_PROG_TYPE_SK_MSG: u32 = 20;
pub const BPF_PROG_TYPE_SK_LOOKUP: u32 = 30;

/// Output of Engine 1 (`net_hijack`).
pub struct NetHijackResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 1 against filesystem `root`, optionally performing live Netfilter/eBPF kernel queries.
pub fn run_net_hijack_audit(root: &Path, live_mode: bool) -> NetHijackResult {
    let mut findings = Vec::new();

    let dns_files_scanned = scan_dns_configurations(root, &mut findings);
    let routes_scanned = scan_ip_routing_and_policy_tables(root, live_mode, &mut findings);
    let netfilter_sources = scan_netfilter_rules(root, live_mode, &mut findings);
    let ebpf_artifacts = scan_ebpf_socket_hooks(root, live_mode, &mut findings);

    let summary = JsonValue::OrderedObject(vec![
        ("live_kernel_probing".to_string(), JsonValue::Bool(live_mode)),
        (
            "dns_config_files_inspected".to_string(),
            JsonValue::Uint(dns_files_scanned),
        ),
        (
            "kernel_routes_inspected".to_string(),
            JsonValue::Uint(routes_scanned),
        ),
        (
            "netfilter_sources_inspected".to_string(),
            JsonValue::Array(netfilter_sources.into_iter().map(JsonValue::Str).collect()),
        ),
        (
            "ebpf_objects_inspected".to_string(),
            JsonValue::Uint(ebpf_artifacts),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    NetHijackResult { summary, findings }
}

// ============================================================================
// 1A. Static & Dynamic DNS Hijack Checks
// ============================================================================

fn scan_dns_configurations(root: &Path, findings: &mut Vec<Finding>) -> u64 {
    let mut count = 0u64;

    // 1. `/etc/hosts` static overrides
    let hosts_path = join_rooted(root, "etc/hosts");
    if let Some(text) = read_text(&hosts_path) {
        count += 1;
        for (lineno, raw_line) in text.lines().enumerate() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut tokens = line.split_whitespace();
            let Some(ip_str) = tokens.next() else {
                continue;
            };
            for host in tokens {
                if is_fortinet_domain(host) {
                    let ip_class = ip_str
                        .parse::<IpAddr>()
                        .map(|ip| classify_ip(ip).as_str())
                        .unwrap_or("UNPARSED_IP");
                    findings.push(
                        Finding::new(
                            EngineId::NetHijack,
                            "CRITICAL_STATIC_DNS_FORTIGUARD_HIJACK",
                            Severity::Critical,
                            format!("/etc/hosts:{}", lineno + 1),
                            format!(
                                "Static /etc/hosts override redirects `{}` to {} ({})",
                                host, ip_str, ip_class
                            ),
                        )
                        .with_evidence("domain", JsonValue::str(host))
                        .with_evidence("mapped_ip", JsonValue::str(ip_str))
                        .with_evidence("ip_ownership", JsonValue::str(ip_class))
                        .with_evidence("line_number", JsonValue::Uint((lineno + 1) as u64)),
                    );
                }
            }
        }
    }

    // 2. `/etc/resolv.conf`, NetworkManager, dnsmasq, named/BIND, systemd-resolved
    let mut config_files: Vec<(String, PathBuf)> = Vec::new();
    let direct_files = [
        "etc/resolv.conf",
        "etc/dnsmasq.conf",
        "etc/named.conf",
        "etc/systemd/resolved.conf",
    ];
    for rel in &direct_files {
        let full = join_rooted(root, rel);
        if full.is_file() {
            config_files.push((format!("/{}", rel), full));
        }
    }

    let scan_dirs = [
        "etc/dnsmasq.d",
        "etc/NetworkManager/system-connections",
        "etc/NetworkManager/conf.d",
        "etc/NetworkManager/dnsmasq.d",
        "etc/named",
        "var/named",
        "etc/systemd/resolved.conf.d",
        "etc/systemd/network",
    ];
    for dir_rel in &scan_dirs {
        collect_files_shallow_or_recursive(root, &join_rooted(root, dir_rel), 2, &mut config_files);
    }
    config_files.sort_by(|a, b| a.0.cmp(&b.0));

    for (logical_path, full_path) in config_files {
        let Some(text) = read_text(&full_path) else {
            continue;
        };
        count += 1;

        for (lineno, raw_line) in text.lines().enumerate() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            let hits_forti = lower.contains("fortinet.com")
                || lower.contains("fortinet.net")
                || lower.contains("fortiguard.net")
                || lower.contains("fortiguard.com")
                || lower.contains("forticloud.com");

            if !hits_forti {
                continue;
            }

            // Catch dnsmasq `address=/fortiguard.net/1.2.3.4`, `server=/fortinet.com/...`,
            // `host-record=...`, BIND `zone "fortiguard.net"`, systemd-resolved `Domains=~fortiguard.net`,
            // and NetworkManager `dns-search=~fortiguard.net`
            let is_directive = lower.starts_with("address=")
                || lower.starts_with("server=")
                || lower.starts_with("host-record=")
                || lower.starts_with("cname=")
                || lower.starts_with("local=")
                || lower.contains("zone ")
                || lower.starts_with("domains=")
                || lower.starts_with("dns-search=");

            if is_directive || logical_path.contains("var/named") {
                findings.push(
                    Finding::new(
                        EngineId::NetHijack,
                        "CRITICAL_LOCAL_DNS_DAEMON_HIJACK",
                        Severity::Critical,
                        format!("{}:{}", logical_path, lineno + 1),
                        format!(
                            "Local DNS/resolver rule in {} intercepts Fortinet/FortiGuard domain: `{}`",
                            logical_path, line
                        ),
                    )
                    .with_evidence("config_file", JsonValue::str(&logical_path))
                    .with_evidence("line_number", JsonValue::Uint((lineno + 1) as u64))
                    .with_evidence("directive", JsonValue::str(line)),
                );
            }
        }
    }

    count
}

// ============================================================================
// 1B. Kernel IP Routing (`/proc/net/route`), `rt_tables` & Policy Routing
// ============================================================================

fn scan_ip_routing_and_policy_tables(
    root: &Path,
    live_mode: bool,
    findings: &mut Vec<Finding>,
) -> u64 {
    let mut routes_checked = 0u64;

    // 1. Parse `/proc/net/route` (Linux little-endian 32-bit hex IPv4 fields)
    let proc_route = join_rooted(root, "proc/net/route");
    if let Some(route_text) = read_text(&proc_route) {
        for line in route_text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 8 {
                continue;
            }
            let iface = cols[0];
            let Ok(dest_le) = u32::from_str_radix(cols[1], 16) else {
                continue;
            };
            let Ok(gw_le) = u32::from_str_radix(cols[2], 16) else {
                continue;
            };
            let Ok(mask_le) = u32::from_str_radix(cols[7], 16) else {
                continue;
            };

            routes_checked += 1;
            let dest_ip = Ipv4Addr::from(dest_le.swap_bytes());
            let gw_ip = Ipv4Addr::from(gw_le.swap_bytes());
            let mask_be = mask_le.swap_bytes();
            let plen = mask_be.leading_ones() as u8;

            if let Some(asn_label) = cidr_overlaps_fortinet_as40934(dest_ip, plen) {
                findings.push(
                    Finding::new(
                        EngineId::NetHijack,
                        "CRITICAL_ROUTE_HIJACK_FORTINET_ASN",
                        Severity::Critical,
                        format!("/proc/net/route -> {}/{}", dest_ip, plen),
                        format!(
                            "Specific kernel route `{}/{}` via gateway {} dev `{}` hijacks traffic to {}",
                            dest_ip, plen, gw_ip, iface, asn_label
                        ),
                    )
                    .with_evidence("destination_cidr", JsonValue::str(format!("{}/{}", dest_ip, plen)))
                    .with_evidence("gateway", JsonValue::str(gw_ip.to_string()))
                    .with_evidence("interface", JsonValue::str(iface))
                    .with_evidence("matched_fortinet_asn", JsonValue::str(asn_label)),
                );
            }
        }
    }

    // 2. Inspect `/etc/iproute2/rt_tables` for custom policy routing tables
    for rt_rel in ["etc/iproute2/rt_tables", "usr/share/iproute2/rt_tables"] {
        let rt_path = join_rooted(root, rt_rel);
        let Some(text) = read_text(&rt_path) else {
            continue;
        };
        for (lineno, raw_line) in text.lines().enumerate() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (Some(id_s), Some(tbl_name)) = (parts.next(), parts.next()) else {
                continue;
            };
            let Ok(tbl_id) = id_s.parse::<u32>() else {
                continue;
            };
            let is_standard = matches!(
                (tbl_id, tbl_name),
                (0, "unspec") | (253, "default") | (254, "main") | (255, "local")
            );
            if !is_standard {
                findings.push(
                    Finding::new(
                        EngineId::NetHijack,
                        "HIGH_CUSTOM_POLICY_ROUTING_TABLE",
                        Severity::High,
                        format!("/{}:{}", rt_rel, lineno + 1),
                        format!(
                            "Custom iproute2 policy routing table `{}` (id {}) defined in /{}",
                            tbl_name, tbl_id, rt_rel
                        ),
                    )
                    .with_evidence("table_id", JsonValue::Uint(tbl_id as u64))
                    .with_evidence("table_name", JsonValue::str(tbl_name)),
                );
            }
        }
    }

    // 3. Static RHEL network-scripts (`route-*`, `rule-*`) and optional live `ip rule show`
    let net_scripts = join_rooted(root, "etc/sysconfig/network-scripts");
    let mut rule_blobs: Vec<(String, String)> = Vec::new();
    if let Ok(entries) = fs::read_dir(&net_scripts) {
        for e in entries.flatten() {
            if let Some(name) = e.file_name().to_str() {
                if name.starts_with("route-") || name.starts_with("rule-") {
                    if let Some(t) = read_text(&e.path()) {
                        rule_blobs.push((
                            format!("/etc/sysconfig/network-scripts/{}", name),
                            t,
                        ));
                    }
                }
            }
        }
    }

    if live_mode && root == Path::new("/") {
        if let Some(out) = run_readonly_cmd("ip", &["rule", "show"]) {
            rule_blobs.push(("live:ip_rule_show".to_string(), out));
        }
        if let Some(out) = run_readonly_cmd("ip", &["route", "show", "table", "all"]) {
            rule_blobs.push(("live:ip_route_table_all".to_string(), out));
        }
    }

    for (source, content) in rule_blobs {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let has_fwmark = trimmed.contains("fwmark")
                || trimmed.contains("lookup ")
                    && !trimmed.contains("lookup main")
                    && !trimmed.contains("lookup local")
                    && !trimmed.contains("lookup default");

            let mut matched_asn: Option<&'static str> = None;
            for tok in trimmed.split_whitespace() {
                if let Some((ip, plen)) = parse_ipv4_cidr(tok) {
                    if let Some(lbl) = cidr_overlaps_fortinet_as40934(ip, plen) {
                        matched_asn = Some(lbl);
                        break;
                    }
                }
            }

            if let Some(asn) = matched_asn {
                findings.push(
                    Finding::new(
                        EngineId::NetHijack,
                        "CRITICAL_POLICY_ROUTE_FORTINET_HIJACK",
                        Severity::Critical,
                        &source,
                        format!(
                            "Policy route/rule in {} intercepts {}: `{}`",
                            source, asn, trimmed
                        ),
                    )
                    .with_evidence("rule", JsonValue::str(trimmed))
                    .with_evidence("matched_fortinet_asn", JsonValue::str(asn)),
                );
            } else if has_fwmark && trimmed.contains("fwmark") {
                findings.push(
                    Finding::new(
                        EngineId::NetHijack,
                        "HIGH_FWMARK_POLICY_ROUTING_RULE",
                        Severity::High,
                        &source,
                        format!("Packet-mark (`fwmark`) policy routing rule active in {}: `{}`", source, trimmed),
                    )
                    .with_evidence("rule", JsonValue::str(trimmed)),
                );
            }
        }
    }

    routes_checked
}

// ============================================================================
// 1C. Netfilter (`iptables` / `nftables`) DNAT, REDIRECT & fwmark Inspection
// ============================================================================

fn scan_netfilter_rules(root: &Path, live_mode: bool, findings: &mut Vec<Finding>) -> Vec<String> {
    let mut sources_checked = Vec::new();
    let mut rule_sets: Vec<(String, String)> = Vec::new();

    let static_candidates = [
        "etc/sysconfig/iptables",
        "etc/sysconfig/nftables.conf",
        "etc/nftables/main.nft",
        "etc/firewalld/direct.xml",
    ];
    for rel in &static_candidates {
        let full = join_rooted(root, rel);
        if let Some(text) = read_text(&full) {
            let label = format!("/{}", rel);
            sources_checked.push(label.clone());
            rule_sets.push((label, text));
        }
    }

    let nft_dir = join_rooted(root, "etc/nftables");
    if let Ok(entries) = fs::read_dir(&nft_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("nft") {
                let rel = p.strip_prefix(root).unwrap_or(&p);
                let label = format!("/{}", rel.to_string_lossy().trim_start_matches('/'));
                if !sources_checked.contains(&label) {
                    if let Some(text) = read_text(&p) {
                        sources_checked.push(label.clone());
                        rule_sets.push((label, text));
                    }
                }
            }
        }
    }

    if live_mode && root == Path::new("/") {
        if let Some(ipt) = run_readonly_cmd("iptables-save", &[]) {
            sources_checked.push("live:iptables-save".to_string());
            rule_sets.push(("live:iptables-save".to_string(), ipt));
        }
        if let Some(nft) = run_readonly_cmd("nft", &["list", "ruleset"]) {
            sources_checked.push("live:nft_list_ruleset".to_string());
            rule_sets.push(("live:nft_list_ruleset".to_string(), nft));
        }
    }

    for (source, text) in &rule_sets {
        for (lineno, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let lower = line.to_ascii_lowercase();

            let is_nat_or_mark_action = lower.contains("-j dnat")
                || lower.contains("-j redirect")
                || lower.contains("-j tproxy")
                || lower.contains("-j mark")
                || lower.contains("dnat to")
                || lower.contains("redirect to")
                || lower.contains("tproxy to")
                || lower.contains("meta mark set");

            if !is_nat_or_mark_action {
                continue;
            }

            let mut fortinet_cidr_hit: Option<&'static str> = None;
            for tok in line.split(|c: char| c.is_whitespace() || c == ',' || c == '{' || c == '}') {
                if let Some((ip, plen)) = parse_ipv4_cidr(tok) {
                    if let Some(lbl) = cidr_overlaps_fortinet_as40934(ip, plen) {
                        fortinet_cidr_hit = Some(lbl);
                        break;
                    }
                }
            }

            let is_output_interception = (lower.contains("output") || lower.contains("prerouting"))
                && (lower.contains("443")
                    || lower.contains("8888")
                    || lower.contains("8890")
                    || lower.contains("53"));

            if fortinet_cidr_hit.is_some() || is_output_interception {
                let reason = fortinet_cidr_hit.unwrap_or("OUTPUT/PREROUTING port 53/443/8888/8890 interception");
                findings.push(
                    Finding::new(
                        EngineId::NetHijack,
                        "CRITICAL_NETFILTER_DNAT_OR_FWMARK_HIJACK",
                        Severity::Critical,
                        format!("{}:{}", source, lineno + 1),
                        format!(
                            "Netfilter DNAT/REDIRECT/fwmark rule in {} intercepts FortiGuard/TLS traffic ({}): `{}`",
                            source, reason, line
                        ),
                    )
                    .with_evidence("source", JsonValue::str(source))
                    .with_evidence("line_number", JsonValue::Uint((lineno + 1) as u64))
                    .with_evidence("rule", JsonValue::str(line))
                    .with_evidence("match_reason", JsonValue::str(reason)),
                );
            }
        }
    }

    sources_checked
}

// ============================================================================
// 1D. Kernel eBPF Cgroup / Socket Hook Scanner (`CRITICAL_EBPF_NET_HIJACK`)
// ============================================================================

fn scan_ebpf_socket_hooks(root: &Path, live_mode: bool, findings: &mut Vec<Finding>) -> u64 {
    let mut inspected = 0u64;
    let mut reported_prog_ids = BTreeSet::new();

    // 1. Pinned eBPF filesystem objects under `/sys/fs/bpf`
    let bpf_fs = join_rooted(root, "sys/fs/bpf");
    let mut pinned_files = Vec::new();
    collect_files_shallow_or_recursive(root, &bpf_fs, 4, &mut pinned_files);
    for (logical, _full) in pinned_files {
        inspected += 1;
        findings.push(
            Finding::new(
                EngineId::NetHijack,
                "CRITICAL_EBPF_NET_HIJACK",
                Severity::Critical,
                &logical,
                format!(
                    "Pinned eBPF object present in bpffs at {} on FortiSOAR appliance (socket/cgroup hook persistence)",
                    logical
                ),
            )
            .with_evidence("pinned_path", JsonValue::str(&logical)),
        );
    }

    // 2. Scan `/proc/<pid>/fdinfo/*` for open `bpf-prog` socket/cgroup hooks
    let proc_dir = join_rooted(root, "proc");
    if let Ok(pids) = fs::read_dir(&proc_dir) {
        for pid_ent in pids.flatten() {
            let Some(pid_str) = pid_ent.file_name().to_str().map(|s| s.to_string()) else {
                continue;
            };
            if !pid_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let fdinfo_dir = pid_ent.path().join("fdinfo");
            let Ok(fds) = fs::read_dir(&fdinfo_dir) else {
                continue;
            };
            let comm = read_text(&pid_ent.path().join("comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            for fd_ent in fds.flatten() {
                let Some(info_text) = read_text(&fd_ent.path()) else {
                    continue;
                };
                if !info_text.contains("prog_type:") {
                    continue;
                }
                inspected += 1;

                let mut prog_type: Option<u32> = None;
                let mut prog_id: u32 = 0;
                let mut prog_tag = String::new();

                for line in info_text.lines() {
                    if let Some(v) = line.strip_prefix("prog_type:") {
                        prog_type = v.trim().parse::<u32>().ok();
                    } else if let Some(v) = line.strip_prefix("prog_id:") {
                        prog_id = v.trim().parse::<u32>().unwrap_or(0);
                    } else if let Some(v) = line.strip_prefix("prog_tag:") {
                        prog_tag = v.trim().to_string();
                    }
                }

                if let Some(pt) = prog_type {
                    if let Some(pt_name) = socket_hijack_bpf_type_name(pt) {
                        if prog_id == 0 || reported_prog_ids.insert(prog_id) {
                            let fd_name = fd_ent.file_name().to_string_lossy().into_owned();
                            findings.push(
                                Finding::new(
                                    EngineId::NetHijack,
                                    "CRITICAL_EBPF_NET_HIJACK",
                                    Severity::Critical,
                                    format!("/proc/{}/fdinfo/{}", pid_str, fd_name),
                                    format!(
                                        "Active eBPF socket-redirection program `{}` (prog_id={}, tag={}) held by process {} (pid {})",
                                        pt_name, prog_id, prog_tag, comm, pid_str
                                    ),
                                )
                                .with_evidence("pid", JsonValue::str(&pid_str))
                                .with_evidence("process_comm", JsonValue::str(&comm))
                                .with_evidence("prog_id", JsonValue::Uint(prog_id as u64))
                                .with_evidence("prog_type_id", JsonValue::Uint(pt as u64))
                                .with_evidence("prog_type_name", JsonValue::str(pt_name))
                                .with_evidence("prog_tag", JsonValue::str(&prog_tag)),
                            );
                        }
                    }
                }
            }
        }
    }

    // 3. Scan `/proc/kallsyms` for JIT-compiled `[bpf]` socket/connect hook symbols
    let kallsyms_path = join_rooted(root, "proc/kallsyms");
    if let Some(ks_text) = read_text(&kallsyms_path) {
        for line in ks_text.lines() {
            if !line.contains("[bpf]") && !line.contains("bpf_prog_") {
                continue;
            }
            let cols: Vec<&str> = line.split_whitespace().collect();
            let Some(&sym_name) = cols.get(2) else {
                continue;
            };
            inspected += 1;
            let lower = sym_name.to_ascii_lowercase();
            let suspicious_sym = lower.contains("connect4")
                || lower.contains("connect6")
                || lower.contains("sock_addr")
                || lower.contains("sock_ops")
                || lower.contains("forti")
                || lower.contains("fdn")
                || lower.contains("redir")
                || lower.contains("hijack")
                || lower.contains("spoof");

            if suspicious_sym {
                findings.push(
                    Finding::new(
                        EngineId::NetHijack,
                        "CRITICAL_EBPF_NET_HIJACK",
                        Severity::Critical,
                        format!("/proc/kallsyms::{}", sym_name),
                        format!(
                            "JIT-compiled kernel eBPF socket hook symbol `{}` detected in /proc/kallsyms",
                            sym_name
                        ),
                    )
                    .with_evidence("kallsyms_symbol", JsonValue::str(sym_name))
                    .with_evidence("kernel_addr", JsonValue::str(*cols.first().unwrap_or(&"0"))),
                );
            }
        }
    }

    // 4. Live Linux x86_64 raw `__NR_bpf = 321` enumeration to catch detached cgroup hooks
    if live_mode && root == Path::new("/") {
        inspected += enumerate_live_ebpf_progs_x86_64(&mut reported_prog_ids, findings);
    }

    inspected
}

pub fn socket_hijack_bpf_type_name(prog_type: u32) -> Option<&'static str> {
    match prog_type {
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR => Some("BPF_PROG_TYPE_CGROUP_SOCK_ADDR (connect4/connect6)"),
        BPF_PROG_TYPE_SOCK_OPS => Some("BPF_PROG_TYPE_SOCK_OPS"),
        BPF_PROG_TYPE_SK_SKB => Some("BPF_PROG_TYPE_SK_SKB"),
        BPF_PROG_TYPE_SK_MSG => Some("BPF_PROG_TYPE_SK_MSG"),
        BPF_PROG_TYPE_SK_LOOKUP => Some("BPF_PROG_TYPE_SK_LOOKUP"),
        BPF_PROG_TYPE_CGROUP_SOCK => Some("BPF_PROG_TYPE_CGROUP_SOCK"),
        _ => None,
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn enumerate_live_ebpf_progs_x86_64(
    reported_prog_ids: &mut BTreeSet<u32>,
    findings: &mut Vec<Finding>,
) -> u64 {
    use core::arch::asm;
    use fsr_deep_audit::hw_integrity::SYS_CLOSE;

    const SYS_BPF: isize = 321;
    const BPF_PROG_GET_NEXT_ID: i32 = 11;
    const BPF_PROG_GET_FD_BY_ID: i32 = 13;
    const BPF_OBJ_GET_INFO_BY_FD: i32 = 15;

    #[inline]
    unsafe fn raw_bpf(cmd: i32, attr_ptr: *mut u8, attr_sz: usize) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") SYS_BPF => ret,
                in("rdi") cmd as isize,
                in("rsi") attr_ptr as usize,
                in("rdx") attr_sz,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }

    #[inline]
    unsafe fn raw_close(fd: i32) {
        let _ret: isize;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") SYS_CLOSE as isize => _ret,
                in("rdi") fd as isize,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
    }

    let mut count = 0u64;
    let mut cur_id: u32 = 0;

    for _ in 0..4096 {
        let mut attr = [0u8; 128];
        attr[0..4].copy_from_slice(&cur_id.to_ne_bytes());
        let rc = unsafe { raw_bpf(BPF_PROG_GET_NEXT_ID, attr.as_mut_ptr(), 16) };
        if rc < 0 {
            break;
        }
        let next_id = u32::from_ne_bytes([attr[4], attr[5], attr[6], attr[7]]);
        if next_id <= cur_id {
            break;
        }
        cur_id = next_id;
        count += 1;

        let mut fd_attr = [0u8; 128];
        fd_attr[0..4].copy_from_slice(&cur_id.to_ne_bytes());
        let prog_fd = unsafe { raw_bpf(BPF_PROG_GET_FD_BY_ID, fd_attr.as_mut_ptr(), 16) };
        if prog_fd < 0 {
            continue;
        }

        let mut info_buf = [0u8; 232];
        let mut info_attr = [0u8; 128];
        info_attr[0..4].copy_from_slice(&(prog_fd as u32).to_ne_bytes());
        info_attr[4..8].copy_from_slice(&(info_buf.len() as u32).to_ne_bytes());
        info_attr[8..16].copy_from_slice(&(info_buf.as_mut_ptr() as u64).to_ne_bytes());

        let info_rc = unsafe { raw_bpf(BPF_OBJ_GET_INFO_BY_FD, info_attr.as_mut_ptr(), 16) };
        unsafe { raw_close(prog_fd as i32) };

        if info_rc < 0 {
            continue;
        }

        // `struct bpf_prog_info`: [0..4] type, [4..8] id, [8..16] tag, [64..80] name
        let prog_type = u32::from_ne_bytes([info_buf[0], info_buf[1], info_buf[2], info_buf[3]]);
        let prog_id = u32::from_ne_bytes([info_buf[4], info_buf[5], info_buf[6], info_buf[7]]);
        let tag_hex = hex_encode(&info_buf[8..16]);
        let name_slice = &info_buf[64..80];
        let name_end = name_slice
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_slice.len());
        let prog_name = String::from_utf8_lossy(&name_slice[..name_end]).into_owned();

        if let Some(pt_name) = socket_hijack_bpf_type_name(prog_type) {
            if reported_prog_ids.insert(prog_id) {
                findings.push(
                    Finding::new(
                        EngineId::NetHijack,
                        "CRITICAL_EBPF_NET_HIJACK",
                        Severity::Critical,
                        format!("kernel:bpf_prog_id:{}", prog_id),
                        format!(
                            "Detached/kernel-resident eBPF socket hook `{}` (name=`{}`, id={}, tag={}) discovered via raw __NR_bpf(321)",
                            pt_name, prog_name, prog_id, tag_hex
                        ),
                    )
                    .with_evidence("prog_id", JsonValue::Uint(prog_id as u64))
                    .with_evidence("prog_type_id", JsonValue::Uint(prog_type as u64))
                    .with_evidence("prog_type_name", JsonValue::str(pt_name))
                    .with_evidence("prog_name", JsonValue::str(prog_name))
                    .with_evidence("prog_tag", JsonValue::str(tag_hex)),
                );
            }
        }
    }

    count
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn enumerate_live_ebpf_progs_x86_64(
    _reported_prog_ids: &mut BTreeSet<u32>,
    _findings: &mut Vec<Finding>,
) -> u64 {
    let _ = hex_encode(&[]);
    0
}

fn collect_files_shallow_or_recursive(
    root: &Path,
    dir: &Path,
    max_depth: usize,
    out: &mut Vec<(String, PathBuf)>,
) {
    if max_depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();

    for p in paths {
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect_files_shallow_or_recursive(root, &p, max_depth - 1, out);
        } else if meta.is_file() {
            let rel = p.strip_prefix(root).unwrap_or(&p);
            let logical = format!("/{}", rel.to_string_lossy().trim_start_matches('/'));
            out.push((logical, p));
        }
    }
}

fn read_text(path: &Path) -> Option<String> {
    let bytes = match raw_syscall_read_file(path) {
        Ok(b) => b,
        Err(_) => fs::read(path).ok()?,
    };
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn run_readonly_cmd(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}
