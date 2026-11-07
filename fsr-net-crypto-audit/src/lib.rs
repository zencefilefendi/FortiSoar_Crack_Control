//! `fsr-net-crypto-audit` (Phase 2): Network Redirection, eBPF Socket Hook, X.509 CA Trust Store,
//! `libssl`/`libcrypto` Verification Bypass, Active FDN Split-Horizon DNS/TLS Probe, and
//! FortiGate VM FDS License Emulator Forensic Auditor.

pub mod asn1_x509;
pub mod ca_trust_audit;
pub mod fdn_live_probe;
pub mod fortigate_cfg_audit;
pub mod ip_asn;
pub mod net_hijack;
pub mod ssl_bypass_check;

use std::path::PathBuf;

use fsr_deep_audit::schema::{build_canonical_report_json, Finding, JsonValue, ScanContext};
use fsr_deep_audit::{collect_scan_context, execute_full_audit, EngineSelection};

use crate::ca_trust_audit::run_ca_trust_audit;
use crate::fdn_live_probe::run_fdn_live_probe_audit;
use crate::fortigate_cfg_audit::run_fortigate_cfg_audit;
use crate::net_hijack::run_net_hijack_audit;
use crate::ssl_bypass_check::run_ssl_bypass_audit;

/// Selection and runtime configuration for the 5 Phase-2 engines.
#[derive(Debug, Clone)]
pub struct NetCryptoAuditConfig {
    pub root_path: PathBuf,
    pub live_mode: bool,
    pub fgt_config_path: Option<PathBuf>,
    pub fgt_rating_path: Option<PathBuf>,
    pub extra_fortinet_spkis: Vec<String>,
    pub enable_net_hijack: bool,
    pub enable_ca_trust: bool,
    pub enable_ssl_bypass: bool,
    pub enable_fdn_probe: bool,
    pub enable_fgt_cfg: bool,
    pub include_phase1_engines: bool,
}

impl Default for NetCryptoAuditConfig {
    fn default() -> Self {
        Self {
            root_path: PathBuf::from("/"),
            live_mode: false,
            fgt_config_path: None,
            fgt_rating_path: None,
            extra_fortinet_spkis: Vec::new(),
            enable_net_hijack: true,
            enable_ca_trust: true,
            enable_ssl_bypass: true,
            enable_fdn_probe: true,
            enable_fgt_cfg: true,
            include_phase1_engines: false,
        }
    }
}

/// Complete Phase-2 forensic report fully compatible with Phase-1 JSON/NDJSON schema (`1.0.0`).
#[derive(Debug, Clone)]
pub struct NetCryptoAuditReport {
    pub context: ScanContext,
    pub engines: Vec<(String, JsonValue)>,
    pub findings: Vec<Finding>,
}

impl NetCryptoAuditReport {
    pub fn into_canonical_json(self) -> JsonValue {
        build_canonical_report_json(
            "fsr-net-crypto-audit",
            env!("CARGO_PKG_VERSION"),
            &self.context,
            self.engines,
            self.findings,
        )
    }
}

/// Executes all configured Phase-2 engines (and optional Phase-1 engines) deterministically.
pub fn execute_net_crypto_audit(cfg: &NetCryptoAuditConfig) -> NetCryptoAuditReport {
    let context = collect_scan_context(&cfg.root_path);
    let mut engines = Vec::new();
    let mut findings = Vec::new();

    if cfg.include_phase1_engines {
        let p1 = execute_full_audit(&cfg.root_path, EngineSelection::default());
        engines.push(("hw_integrity".to_string(), p1.hw_summary));
        engines.push(("elf_vma_diff".to_string(), p1.elf_summary));
        engines.push(("pyc_inspector".to_string(), p1.pyc_summary));
        engines.push(("rpm_forensics".to_string(), p1.rpm_summary));
        findings.extend(p1.findings);
    }

    if cfg.enable_net_hijack {
        let res = run_net_hijack_audit(&cfg.root_path, cfg.live_mode);
        engines.push(("net_hijack".to_string(), res.summary));
        findings.extend(res.findings);
    } else {
        engines.push(("net_hijack".to_string(), disabled_summary()));
    }

    if cfg.enable_ca_trust {
        let res = run_ca_trust_audit(&cfg.root_path, &cfg.extra_fortinet_spkis);
        engines.push(("ca_trust_audit".to_string(), res.summary));
        findings.extend(res.findings);
    } else {
        engines.push(("ca_trust_audit".to_string(), disabled_summary()));
    }

    if cfg.enable_ssl_bypass {
        let res = run_ssl_bypass_audit(&cfg.root_path);
        engines.push(("ssl_bypass_check".to_string(), res.summary));
        findings.extend(res.findings);
    } else {
        engines.push(("ssl_bypass_check".to_string(), disabled_summary()));
    }

    if cfg.enable_fdn_probe {
        let res = run_fdn_live_probe_audit(cfg.live_mode, &cfg.extra_fortinet_spkis);
        engines.push(("fdn_live_probe".to_string(), res.summary));
        findings.extend(res.findings);
    } else {
        engines.push(("fdn_live_probe".to_string(), disabled_summary()));
    }

    if cfg.enable_fgt_cfg {
        let res = run_fortigate_cfg_audit(
            cfg.fgt_config_path.as_deref(),
            cfg.fgt_rating_path.as_deref(),
            &cfg.extra_fortinet_spkis,
        );
        engines.push(("fortigate_cfg_audit".to_string(), res.summary));
        findings.extend(res.findings);
    } else {
        engines.push(("fortigate_cfg_audit".to_string(), disabled_summary()));
    }

    NetCryptoAuditReport {
        context,
        engines,
        findings,
    }
}

fn disabled_summary() -> JsonValue {
    JsonValue::OrderedObject(vec![("enabled".to_string(), JsonValue::Bool(false))])
}
