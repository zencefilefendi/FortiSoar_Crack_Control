//! `fsr-clone-cluster-audit` (Phase 3): Golden Image Clone Detection, Database & Superblock
//! Birthmarks, Time-Freeze / Trial Abuse Auditing, FGVM License Blob Inspection, O(N) Multi-Node
//! Cluster Correlation, and Active TLS/HTTP Management Interface Fingerprinting.

pub mod birthmark_extractor;
pub mod cluster_correlator;
pub mod fgvm_license_inspect;
pub mod json_parser;
pub mod remote_fingerprinter;
pub mod time_freeze_audit;

use std::path::PathBuf;

use fsr_deep_audit::schema::{build_canonical_report_json, Finding, JsonValue, ScanContext};
use fsr_deep_audit::{collect_scan_context, execute_full_audit, EngineSelection};
use fsr_net_crypto_audit::{execute_net_crypto_audit, NetCryptoAuditConfig};

use crate::birthmark_extractor::{run_birthmark_extractor, DeviceBirthmarks};
use crate::cluster_correlator::{
    build_local_cluster_node, correlate_cluster_nodes, load_cluster_input_records,
    ClusterNodeRecord,
};
use crate::fgvm_license_inspect::run_fgvm_license_inspect;
use crate::remote_fingerprinter::run_remote_fingerprinter;
use crate::time_freeze_audit::run_time_freeze_audit;

/// Runtime configuration for Phase-3 Stage A (single-node birthmark/time/license) and
/// Stage B (multi-node cluster correlation & active TLS/HTTP fingerprinting).
#[derive(Debug, Clone)]
pub struct CloneClusterAuditConfig {
    pub root_path: PathBuf,
    /// Whether `--root` local extraction should execute (true by default for appliance audits;
    /// can be false when running pure central telemetry correlation on an analyst workstation).
    pub audit_local_root: bool,
    pub org_label: Option<String>,
    pub reference_now_unix: Option<i64>,
    pub fgt_license_files: Vec<PathBuf>,
    pub fgt_config_path: Option<PathBuf>,
    pub fgt_hw_status_path: Option<PathBuf>,
    pub cluster_input_path: Option<PathBuf>,
    pub scan_targets: Vec<String>,
    pub enable_birthmark: bool,
    pub enable_time_freeze: bool,
    pub enable_fgvm_license: bool,
    pub enable_cluster_correlator: bool,
    pub enable_remote_fingerprinter: bool,
    pub include_all_phases: bool,
}

impl Default for CloneClusterAuditConfig {
    fn default() -> Self {
        Self {
            root_path: PathBuf::from("/"),
            audit_local_root: true,
            org_label: None,
            reference_now_unix: None,
            fgt_license_files: Vec::new(),
            fgt_config_path: None,
            fgt_hw_status_path: None,
            cluster_input_path: None,
            scan_targets: Vec::new(),
            enable_birthmark: true,
            enable_time_freeze: true,
            enable_fgvm_license: true,
            enable_cluster_correlator: true,
            enable_remote_fingerprinter: true,
            include_all_phases: false,
        }
    }
}

/// Complete Phase-3 forensic report sharing the deterministic `1.0.0` JSON/NDJSON schema.
#[derive(Debug, Clone)]
pub struct CloneClusterAuditReport {
    pub context: ScanContext,
    pub birthmarks: Option<DeviceBirthmarks>,
    pub engines: Vec<(String, JsonValue)>,
    pub findings: Vec<Finding>,
}

impl CloneClusterAuditReport {
    pub fn into_canonical_json(self) -> JsonValue {
        build_canonical_report_json(
            "fsr-clone-cluster-audit",
            env!("CARGO_PKG_VERSION"),
            &self.context,
            self.engines,
            self.findings,
        )
    }
}

/// Executes Phase-3 Stage A & Stage B engines deterministically.
pub fn execute_clone_cluster_audit(cfg: &CloneClusterAuditConfig) -> CloneClusterAuditReport {
    let context = collect_scan_context(&cfg.root_path);
    let mut engines = Vec::new();
    let mut findings = Vec::new();

    if cfg.include_all_phases && cfg.audit_local_root {
        let p1 = execute_full_audit(&cfg.root_path, EngineSelection::default());
        engines.push(("hw_integrity".to_string(), p1.hw_summary));
        engines.push(("elf_vma_diff".to_string(), p1.elf_summary));
        engines.push(("pyc_inspector".to_string(), p1.pyc_summary));
        engines.push(("rpm_forensics".to_string(), p1.rpm_summary));
        findings.extend(p1.findings);

        let p2_cfg = NetCryptoAuditConfig {
            root_path: cfg.root_path.clone(),
            live_mode: false,
            fgt_config_path: cfg.fgt_config_path.clone(),
            fgt_rating_path: None,
            include_phase1_engines: false,
            ..Default::default()
        };
        let p2 = execute_net_crypto_audit(&p2_cfg);
        engines.extend(p2.engines);
        findings.extend(p2.findings);
    }

    // ------------------------------------------------------------------------
    // Stage A: Single-Node Birthmark Extraction, Time-Freeze, and FGVM License
    // ------------------------------------------------------------------------
    let mut extracted_birthmarks: Option<DeviceBirthmarks> = None;
    let mut local_fgvm_serials: Vec<String> = Vec::new();
    let mut local_lic_spkis: Vec<String> = Vec::new();

    if cfg.audit_local_root && cfg.enable_birthmark {
        let bm_res = run_birthmark_extractor(&cfg.root_path);
        extracted_birthmarks = Some(bm_res.birthmarks);
        engines.push(("birthmark_extractor".to_string(), bm_res.summary));
        findings.extend(bm_res.findings);
    } else {
        engines.push((
            "birthmark_extractor".to_string(),
            disabled_or_skipped_summary(cfg.enable_birthmark, "skipped_cluster_only_mode"),
        ));
    }

    if cfg.audit_local_root && cfg.enable_time_freeze {
        let empty_bm = DeviceBirthmarks::default();
        let bm_ref = extracted_birthmarks.as_ref().unwrap_or(&empty_bm);
        let mut extra_certs: Vec<&std::path::Path> = Vec::new();
        if let Some(p) = cfg.fgt_config_path.as_deref() {
            extra_certs.push(p);
        }
        for lp in &cfg.fgt_license_files {
            extra_certs.push(lp.as_path());
        }
        let tf_res = run_time_freeze_audit(
            &cfg.root_path,
            bm_ref,
            cfg.reference_now_unix,
            &extra_certs,
        );
        engines.push(("time_freeze_audit".to_string(), tf_res.summary));
        findings.extend(tf_res.findings);
    } else {
        engines.push((
            "time_freeze_audit".to_string(),
            disabled_or_skipped_summary(cfg.enable_time_freeze, "skipped_cluster_only_mode"),
        ));
    }

    let has_explicit_fgt_inputs = !cfg.fgt_license_files.is_empty()
        || cfg.fgt_config_path.is_some()
        || cfg.fgt_hw_status_path.is_some();

    if cfg.enable_fgvm_license && (cfg.audit_local_root || has_explicit_fgt_inputs) {
        let lic_res = run_fgvm_license_inspect(
            &cfg.root_path,
            &cfg.fgt_license_files,
            cfg.fgt_config_path.as_deref(),
            cfg.fgt_hw_status_path.as_deref(),
        );
        local_fgvm_serials = lic_res.discovered_serials;
        local_lic_spkis = lic_res.license_cert_spkis;
        engines.push(("fgvm_license_inspect".to_string(), lic_res.summary));
        findings.extend(lic_res.findings);
    } else {
        engines.push((
            "fgvm_license_inspect".to_string(),
            disabled_or_skipped_summary(cfg.enable_fgvm_license, "skipped_cluster_only_mode"),
        ));
    }

    // ------------------------------------------------------------------------
    // Stage B: Active TLS/HTTP Fingerprinting + Multi-Node Clone Clustering
    // ------------------------------------------------------------------------
    let mut cluster_corpus: Vec<ClusterNodeRecord> = Vec::new();
    let mut parse_warnings: Vec<String> = Vec::new();

    if cfg.enable_remote_fingerprinter {
        let rem_res = run_remote_fingerprinter(&cfg.scan_targets);
        cluster_corpus.extend(rem_res.collected_nodes);
        engines.push(("remote_fingerprinter".to_string(), rem_res.summary));
        findings.extend(rem_res.findings);
    } else {
        engines.push((
            "remote_fingerprinter".to_string(),
            disabled_or_skipped_summary(false, "disabled"),
        ));
    }

    if cfg.enable_cluster_correlator {
        if let Some(cluster_path) = &cfg.cluster_input_path {
            match load_cluster_input_records(cluster_path) {
                Ok((loaded_nodes, warns)) => {
                    cluster_corpus.extend(loaded_nodes);
                    parse_warnings.extend(warns);
                }
                Err(err) => {
                    parse_warnings.push(err);
                }
            }
        }

        // Include the local `--root` node's birthmark when correlating against a cluster corpus
        if let Some(bm) = &extracted_birthmarks {
            if !cluster_corpus.is_empty() {
                cluster_corpus.push(build_local_cluster_node(
                    &format!("local_root:{}", cfg.root_path.display()),
                    bm,
                    &local_fgvm_serials,
                    &local_lic_spkis,
                    cfg.org_label.as_deref(),
                ));
            }
        }

        if cluster_corpus.is_empty() && cfg.cluster_input_path.is_none() && cfg.scan_targets.is_empty()
        {
            engines.push((
                "cluster_correlator".to_string(),
                JsonValue::OrderedObject(vec![
                    ("enabled".to_string(), JsonValue::Bool(true)),
                    (
                        "status".to_string(),
                        JsonValue::str(
                            "standby_single_node_mode (pass --cluster-input or --scan-targets for multi-node clone clustering)",
                        ),
                    ),
                ]),
            ));
        } else {
            let corr = correlate_cluster_nodes(&cluster_corpus, &parse_warnings);
            engines.push(("cluster_correlator".to_string(), corr.summary));
            findings.extend(corr.findings);
        }
    } else {
        engines.push((
            "cluster_correlator".to_string(),
            disabled_or_skipped_summary(false, "disabled"),
        ));
    }

    CloneClusterAuditReport {
        context,
        birthmarks: extracted_birthmarks,
        engines,
        findings,
    }
}

fn disabled_or_skipped_summary(enabled: bool, reason: &str) -> JsonValue {
    JsonValue::OrderedObject(vec![
        ("enabled".to_string(), JsonValue::Bool(enabled)),
        ("status".to_string(), JsonValue::str(reason)),
    ])
}
