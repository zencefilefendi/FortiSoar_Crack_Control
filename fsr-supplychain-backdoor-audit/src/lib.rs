//! `fsr-supplychain-backdoor-audit` (Phase 4): Read-Only Supply-Chain Backdoor Hunter for
//! FortiSOAR & FortiGate Appliances.
//!
//! Orchestrates 5 zero-external-crate detection engines emitting `schema_version: "1.0.0"`
//! deterministic JSON/NDJSON reports:
//!   1. `connector_skimmer_audit`: SOAR Connector & Playbook AST/token credential skimmer & obfuscation scanner
//!   2. `web_auth_backdoor`: Nginx `mirror`/Lua/proxy & Django middleware/magic-header auth-bypass analyzer
//!   3. `postgres_persistence`: PostgreSQL preload `.so`, command hook, `pg_hba.conf` trust & trigger auditor
//!   4. `os_persistence_audit`: Systemd generator/cron, PAM (`pam_unix.so` ELF64 prologue) & SSH/UID=0 hunter
//!   5. `fortigate_backdoor_audit`: FortiGate rogue `super_admin`, `automation-stitch` exfil & REST API auditor

pub mod connector_skimmer_audit;
pub mod fortigate_backdoor_audit;
pub mod os_persistence_audit;
pub mod postgres_persistence;
pub mod web_auth_backdoor;

use std::path::PathBuf;

use fsr_clone_cluster_audit::{execute_clone_cluster_audit, CloneClusterAuditConfig};
use fsr_deep_audit::schema::{build_canonical_report_json, Finding, JsonValue, ScanContext};
use fsr_deep_audit::{collect_scan_context, execute_full_audit, EngineSelection};
use fsr_net_crypto_audit::{execute_net_crypto_audit, NetCryptoAuditConfig};

use crate::connector_skimmer_audit::run_connector_skimmer_audit;
use crate::fortigate_backdoor_audit::run_fortigate_backdoor_audit;
use crate::os_persistence_audit::run_os_persistence_audit;
use crate::postgres_persistence::run_postgres_persistence_audit;
use crate::web_auth_backdoor::run_web_auth_backdoor_audit;

/// Read-only runtime configuration for Phase-4 supply-chain & backdoor engines.
#[derive(Debug, Clone)]
pub struct SupplyChainAuditConfig {
    pub root_path: PathBuf,
    pub fgt_config_path: Option<PathBuf>,
    pub extra_playbook_paths: Vec<PathBuf>,
    pub extra_sql_dumps: Vec<PathBuf>,
    pub enable_connector_skimmer: bool,
    pub enable_web_auth_backdoor: bool,
    pub enable_postgres_persistence: bool,
    pub enable_os_persistence: bool,
    pub enable_fortigate_backdoor: bool,
    pub include_all_phases: bool,
}

impl Default for SupplyChainAuditConfig {
    fn default() -> Self {
        Self {
            root_path: PathBuf::from("/"),
            fgt_config_path: None,
            extra_playbook_paths: Vec::new(),
            extra_sql_dumps: Vec::new(),
            enable_connector_skimmer: true,
            enable_web_auth_backdoor: true,
            enable_postgres_persistence: true,
            enable_os_persistence: true,
            enable_fortigate_backdoor: true,
            include_all_phases: false,
        }
    }
}

/// Complete Phase-4 forensic report sharing the deterministic `1.0.0` JSON/NDJSON schema.
#[derive(Debug, Clone)]
pub struct SupplyChainAuditReport {
    pub context: ScanContext,
    pub engines: Vec<(String, JsonValue)>,
    pub findings: Vec<Finding>,
}

impl SupplyChainAuditReport {
    pub fn into_canonical_json(self) -> JsonValue {
        build_canonical_report_json(
            "fsr-supplychain-backdoor-audit",
            env!("CARGO_PKG_VERSION"),
            &self.context,
            self.engines,
            self.findings,
        )
    }
}

/// Executes all enabled Phase-4 read-only supply-chain backdoor engines (and optional Phases 1-3).
pub fn execute_supplychain_backdoor_audit(cfg: &SupplyChainAuditConfig) -> SupplyChainAuditReport {
    let context = collect_scan_context(&cfg.root_path);
    let mut engines = Vec::new();
    let mut findings = Vec::new();

    if cfg.include_all_phases {
        let p1 = execute_full_audit(&cfg.root_path, EngineSelection::default());
        engines.push(("hw_integrity".to_string(), p1.hw_summary));
        engines.push(("elf_vma_diff".to_string(), p1.elf_summary));
        engines.push(("pyc_inspector".to_string(), p1.pyc_summary));
        engines.push(("rpm_forensics".to_string(), p1.rpm_summary));
        findings.extend(p1.findings);

        let p2 = execute_net_crypto_audit(&NetCryptoAuditConfig {
            root_path: cfg.root_path.clone(),
            live_mode: false,
            fgt_config_path: cfg.fgt_config_path.clone(),
            ..Default::default()
        });
        engines.extend(p2.engines);
        findings.extend(p2.findings);

        let p3 = execute_clone_cluster_audit(&CloneClusterAuditConfig {
            root_path: cfg.root_path.clone(),
            fgt_config_path: cfg.fgt_config_path.clone(),
            ..Default::default()
        });
        engines.extend(p3.engines);
        findings.extend(p3.findings);
    }

    if cfg.enable_connector_skimmer {
        let res = run_connector_skimmer_audit(&cfg.root_path, &cfg.extra_playbook_paths);
        engines.push(("connector_skimmer_audit".to_string(), res.summary));
        findings.extend(res.findings);
    } else {
        engines.push(("connector_skimmer_audit".to_string(), disabled_summary()));
    }

    if cfg.enable_web_auth_backdoor {
        let res = run_web_auth_backdoor_audit(&cfg.root_path);
        engines.push(("web_auth_backdoor".to_string(), res.summary));
        findings.extend(res.findings);
    } else {
        engines.push(("web_auth_backdoor".to_string(), disabled_summary()));
    }

    if cfg.enable_postgres_persistence {
        let res = run_postgres_persistence_audit(&cfg.root_path, &cfg.extra_sql_dumps);
        engines.push(("postgres_persistence".to_string(), res.summary));
        findings.extend(res.findings);
    } else {
        engines.push(("postgres_persistence".to_string(), disabled_summary()));
    }

    if cfg.enable_os_persistence {
        let res = run_os_persistence_audit(&cfg.root_path);
        engines.push(("os_persistence_audit".to_string(), res.summary));
        findings.extend(res.findings);
    } else {
        engines.push(("os_persistence_audit".to_string(), disabled_summary()));
    }

    if cfg.enable_fortigate_backdoor {
        let res = run_fortigate_backdoor_audit(cfg.fgt_config_path.as_deref());
        engines.push(("fortigate_backdoor_audit".to_string(), res.summary));
        findings.extend(res.findings);
    } else {
        engines.push(("fortigate_backdoor_audit".to_string(), disabled_summary()));
    }

    SupplyChainAuditReport {
        context,
        engines,
        findings,
    }
}

fn disabled_summary() -> JsonValue {
    JsonValue::OrderedObject(vec![("enabled".to_string(), JsonValue::Bool(false))])
}
