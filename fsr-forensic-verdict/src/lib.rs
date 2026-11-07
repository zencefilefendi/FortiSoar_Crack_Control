//! `fsr-forensic-verdict` (Phase 5–8 — Unified DFIR Command Center):
//!
//! Orchestrates all 19 read-only detection engines across Phases 1–4 (`fsr-deep-audit`,
//! `fsr-net-crypto-audit`, `fsr-clone-cluster-audit`, `fsr-supplychain-backdoor-audit`)
//! plus optional Phase-8 Zero-Mount OVA/VMDK Inspection & Crack-Kit Threat Attribution
//! (`fsr-ova-attribution`), proves zero target mutation via pre/post SHA-256 & mount/io
//! attestation, seals all findings in an RFC 6962 Binary Merkle Tree, synthesizes causal
//! legal/technical breach verdicts, emits Canonical JSON/NDJSON, Expert Markdown, and
//! Offline Print-Ready HTML dossiers, and verifies standalone evidence bundles offline.

pub mod bundle_verifier;
pub mod merkle_evidence;
pub mod portal_server;
pub mod readonly_attestation;
pub mod report_emitter;
pub mod verdict_classifier;

pub use fsr_ova_attribution;
pub use fsr_remediation_advisor;
pub use fsr_supplychain_backdoor_audit;

use std::path::{Path, PathBuf};

use fsr_clone_cluster_audit::birthmark_extractor::DeviceBirthmarks;
use fsr_clone_cluster_audit::{execute_clone_cluster_audit, CloneClusterAuditConfig};
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};
use fsr_deep_audit::{collect_scan_context, execute_full_audit, EngineSelection};
use fsr_net_crypto_audit::{execute_net_crypto_audit, NetCryptoAuditConfig};
use fsr_ova_attribution::cracker_attribution::run_cracker_attribution_engine;
use fsr_ova_attribution::ova_stream_inspector::inspect_ova_file;
use fsr_remediation_advisor::self_integrity::verify_current_process_self_integrity;
use fsr_supplychain_backdoor_audit::{
    execute_supplychain_backdoor_audit, SupplyChainAuditConfig,
};

use crate::merkle_evidence::MerkleTreeEnvelope;
use crate::readonly_attestation::{capture_pre_audit_state, verify_post_audit_state};
use crate::report_emitter::ForensicVerdictBundle;
use crate::verdict_classifier::classify_forensic_verdicts;

/// Unified runtime configuration for orchestrating all forensic phases & sealing.
#[derive(Debug, Clone)]
pub struct ForensicVerdictConfig {
    pub root_path: PathBuf,
    pub audit_root_filesystem: bool,
    pub live_mode: bool,
    pub org_label: Option<String>,
    pub reference_now_unix: Option<i64>,
    pub fgt_config_path: Option<PathBuf>,
    pub fgt_rating_path: Option<PathBuf>,
    pub fgt_hw_status_path: Option<PathBuf>,
    pub fgt_license_files: Vec<PathBuf>,
    pub extra_fortinet_spkis: Vec<String>,
    pub cluster_input_path: Option<PathBuf>,
    pub scan_targets: Vec<String>,
    pub extra_playbook_paths: Vec<PathBuf>,
    pub extra_sql_dumps: Vec<PathBuf>,
    pub expected_self_sha256: Option<String>,
    pub ova_path: Option<PathBuf>,
    pub attribute_cracker: bool,
    pub baseline_manifest_path: Option<PathBuf>,
}

impl Default for ForensicVerdictConfig {
    fn default() -> Self {
        Self {
            root_path: PathBuf::from("/"),
            audit_root_filesystem: true,
            live_mode: false,
            org_label: None,
            reference_now_unix: None,
            fgt_config_path: None,
            fgt_rating_path: None,
            fgt_hw_status_path: None,
            fgt_license_files: Vec::new(),
            extra_fortinet_spkis: Vec::new(),
            cluster_input_path: None,
            scan_targets: Vec::new(),
            extra_playbook_paths: Vec::new(),
            extra_sql_dumps: Vec::new(),
            expected_self_sha256: None,
            ova_path: None,
            attribute_cracker: false,
            baseline_manifest_path: None,
        }
    }
}

fn format_panic_payload(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown engine panic".to_string()
    }
}

/// Executes an arbitrary forensic engine closure inside a `std::panic::catch_unwind` fault boundary.
/// If the closure panics on malformed/corrupted input, converts the panic into a structured
/// `"engine_fault_isolated"` engine summary and a `LOW_ENGINE_EXECUTION_FAULT_ISOLATED` finding
/// so that no single corrupted file can abort the forensic audit.
#[allow(clippy::result_large_err)]
pub fn execute_isolated_engine_task<T, F>(
    engine_name: &str,
    engine_id: EngineId,
    target_path: &str,
    task: F,
) -> Result<T, (JsonValue, Finding)>
where
    F: FnOnce() -> T,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(task)) {
        Ok(val) => Ok(val),
        Err(payload) => {
            let panic_msg = format_panic_payload(&*payload);
            let summary = JsonValue::OrderedObject(vec![
                ("status".to_string(), JsonValue::str("engine_fault_isolated")),
                ("fault_reason".to_string(), JsonValue::str(&panic_msg)),
            ]);
            let finding = Finding::new(
                engine_id,
                "LOW_ENGINE_EXECUTION_FAULT_ISOLATED",
                Severity::Low,
                target_path,
                format!(
                    "Forensic engine `{}` encountered an unexpected runtime fault ({}) and was safely isolated via catch_unwind without aborting the remaining audit phases.",
                    engine_name, panic_msg
                ),
            )
            .with_evidence("engine_name", JsonValue::str(engine_name))
            .with_evidence("fault_reason", JsonValue::str(&panic_msg));
            Err((summary, finding))
        }
    }
}

/// Orchestrates auditor self-integrity verification, pre-audit attestation, all 19 detection
/// engines (Phases 1–4) + optional Phase-8 OVA/Crack-Kit engines, post-audit non-mutation
/// verification, RFC 6962 Merkle sealing, and causal verdict synthesis.
pub fn execute_forensic_verdict_command_center(
    cfg: &ForensicVerdictConfig,
) -> ForensicVerdictBundle {
    if let Some(ref baseline_p) = cfg.baseline_manifest_path {
        std::env::set_var("FSR_BASELINE_MANIFEST", baseline_p);
    }
    // 0. Auditor Self-Integrity Check (`/proc/self/exe` SHA-256 + `LD_PRELOAD`/`LD_LIBRARY_PATH` armor)
    let check_host_preload =
        cfg.audit_root_filesystem && (cfg.live_mode || cfg.root_path == Path::new("/"));
    let self_integrity = verify_current_process_self_integrity(
        cfg.expected_self_sha256.as_deref(),
        check_host_preload,
    );

    let mut extra_evidence = Vec::new();
    if let Some(p) = &cfg.fgt_config_path {
        extra_evidence.push(p.clone());
    }
    if let Some(p) = &cfg.fgt_rating_path {
        extra_evidence.push(p.clone());
    }
    if let Some(p) = &cfg.fgt_hw_status_path {
        extra_evidence.push(p.clone());
    }
    if let Some(p) = &cfg.cluster_input_path {
        extra_evidence.push(p.clone());
    }
    if let Some(p) = &cfg.ova_path {
        extra_evidence.push(p.clone());
    }
    extra_evidence.extend(cfg.fgt_license_files.iter().cloned());
    extra_evidence.extend(cfg.extra_playbook_paths.iter().cloned());
    extra_evidence.extend(cfg.extra_sql_dumps.iter().cloned());

    let effective_attestation_root = if cfg.audit_root_filesystem {
        cfg.root_path.as_path()
    } else {
        Path::new("/__fsr_zero_mount_ova_userspace__")
    };

    // 1. Capture pre-audit baseline before any engine touches `--root` or `--ova`
    let pre_snapshot = capture_pre_audit_state(effective_attestation_root, &extra_evidence);
    let mut context = collect_scan_context(if cfg.audit_root_filesystem {
        cfg.root_path.as_path()
    } else {
        cfg.ova_path
            .as_deref()
            .unwrap_or_else(|| Path::new("/__fsr_zero_mount_ova_userspace__"))
    });
    if !cfg.audit_root_filesystem {
        if let Some(ova_p) = &cfg.ova_path {
            context.root_path = ova_p.to_string_lossy().into_owned();
        }
    }

    let mut engines = Vec::with_capacity(22);
    let mut findings = Vec::new();
    let mut birthmarks: Option<DeviceBirthmarks> = None;

    if cfg.audit_root_filesystem {
        let root_str = cfg.root_path.to_string_lossy().into_owned();

        // 2A. Phase 1 (`fsr-deep-audit`: 4 engines) — Fault-Isolated via `catch_unwind`
        match execute_isolated_engine_task(
            "phase1_deep_audit",
            EngineId::HwIntegrity,
            &root_str,
            || execute_full_audit(&cfg.root_path, EngineSelection::default()),
        ) {
            Ok(p1) => {
                engines.push(("hw_integrity".to_string(), p1.hw_summary));
                engines.push(("elf_vma_diff".to_string(), p1.elf_summary));
                engines.push(("pyc_inspector".to_string(), p1.pyc_summary));
                engines.push(("rpm_forensics".to_string(), p1.rpm_summary));
                findings.extend(p1.findings);
            }
            Err((fault_summary, fault_finding)) => {
                for name in ["hw_integrity", "elf_vma_diff", "pyc_inspector", "rpm_forensics"] {
                    engines.push((name.to_string(), fault_summary.clone()));
                }
                findings.push(fault_finding);
            }
        }

        // 2B. Phase 2 (`fsr-net-crypto-audit`: 5 engines) — Fault-Isolated via `catch_unwind`
        match execute_isolated_engine_task(
            "phase2_net_crypto_audit",
            EngineId::NetHijack,
            &root_str,
            || {
                execute_net_crypto_audit(&NetCryptoAuditConfig {
                    root_path: cfg.root_path.clone(),
                    live_mode: cfg.live_mode,
                    fgt_config_path: cfg.fgt_config_path.clone(),
                    fgt_rating_path: cfg.fgt_rating_path.clone(),
                    extra_fortinet_spkis: cfg.extra_fortinet_spkis.clone(),
                    include_phase1_engines: false,
                    ..Default::default()
                })
            },
        ) {
            Ok(p2) => {
                engines.extend(p2.engines);
                findings.extend(p2.findings);
            }
            Err((fault_summary, fault_finding)) => {
                for name in [
                    "fdn_anycast_probe",
                    "forticare_beacon",
                    "fgt_conffile_hmac",
                    "fortinet_ca_pin",
                    "fgt_vm_quota",
                ] {
                    engines.push((name.to_string(), fault_summary.clone()));
                }
                findings.push(fault_finding);
            }
        }

        // 2C. Phase 3 (`fsr-clone-cluster-audit`: 5 engines) — Fault-Isolated via `catch_unwind`
        match execute_isolated_engine_task(
            "phase3_clone_cluster_audit",
            EngineId::BirthmarkExtractor,
            &root_str,
            || {
                execute_clone_cluster_audit(&CloneClusterAuditConfig {
                    root_path: cfg.root_path.clone(),
                    audit_local_root: true,
                    org_label: cfg.org_label.clone(),
                    reference_now_unix: cfg.reference_now_unix,
                    fgt_license_files: cfg.fgt_license_files.clone(),
                    fgt_config_path: cfg.fgt_config_path.clone(),
                    fgt_hw_status_path: cfg.fgt_hw_status_path.clone(),
                    cluster_input_path: cfg.cluster_input_path.clone(),
                    scan_targets: cfg.scan_targets.clone(),
                    include_all_phases: false,
                    ..Default::default()
                })
            },
        ) {
            Ok(p3) => {
                birthmarks = p3.birthmarks;
                engines.extend(p3.engines);
                findings.extend(p3.findings);
            }
            Err((fault_summary, fault_finding)) => {
                for name in [
                    "birthmark_extractor",
                    "fgt_lic_asn1",
                    "anti_tamper_detector",
                    "clone_cluster_correlator",
                    "net_infra_scanner",
                ] {
                    engines.push((name.to_string(), fault_summary.clone()));
                }
                findings.push(fault_finding);
            }
        }

        // 2D. Phase 4 (`fsr-supplychain-backdoor-audit`: 5 engines) — Fault-Isolated via `catch_unwind`
        match execute_isolated_engine_task(
            "phase4_supplychain_backdoor_audit",
            EngineId::WebAuthBackdoor,
            &root_str,
            || {
                execute_supplychain_backdoor_audit(&SupplyChainAuditConfig {
                    root_path: cfg.root_path.clone(),
                    fgt_config_path: cfg.fgt_config_path.clone(),
                    extra_playbook_paths: cfg.extra_playbook_paths.clone(),
                    extra_sql_dumps: cfg.extra_sql_dumps.clone(),
                    include_all_phases: false,
                    ..Default::default()
                })
            },
        ) {
            Ok(p4) => {
                engines.extend(p4.engines);
                findings.extend(p4.findings);
            }
            Err((fault_summary, fault_finding)) => {
                for name in [
                    "web_auth_backdoor",
                    "connector_trojan_inspector",
                    "playbook_ssti_scanner",
                    "pg_trigger_auditor",
                    "vault_secret_compromise",
                ] {
                    engines.push((name.to_string(), fault_summary.clone()));
                }
                findings.push(fault_finding);
            }
        }

        debug_assert_eq!(
            engines.len(),
            19,
            "baseline Phases 1-4 must orchestrate all 19 core forensic engines"
        );
    }

    // 2E. Phase 8 (`fsr-ova-attribution`: Zero-Mount OVA/OVF + VMDK Carver + Crack-Kit DNA Attribution)
    let mut ova_outcome_opt = None;
    if let Some(ova_p) = &cfg.ova_path {
        let ova_path_str = ova_p.to_string_lossy().into_owned();
        match execute_isolated_engine_task(
            "ova_stream_inspector",
            EngineId::OvaStreamInspector,
            &ova_path_str,
            || inspect_ova_file(ova_p, &cfg.extra_fortinet_spkis),
        ) {
            Ok(Ok(ova_out)) => {
                if !cfg.audit_root_filesystem {
                    if let Some(hw) = &ova_out.ovf_hardware {
                        if let Some(vs_name) = &hw.virtual_system_name {
                            context.hostname = vs_name.clone();
                        }
                    }
                    let mut carved_bm = DeviceBirthmarks {
                        hostname: context.hostname.clone(),
                        ..Default::default()
                    };
                    for disk in &ova_out.disk_carve_reports {
                        for pg in &disk.pg_controls {
                            carved_bm.pg_controls.push(pg.birthmark.clone());
                        }
                        for sb in &disk.superblocks {
                            carved_bm.superblocks.push(sb.birthmark.clone());
                        }
                    }
                    birthmarks = Some(carved_bm);
                }
                engines.push(("ova_stream_inspector".to_string(), ova_out.ova_summary_json()));
                engines.push(("vmdk_carver".to_string(), ova_out.vmdk_summary_json()));
                findings.extend(ova_out.ova_findings.clone());
                findings.extend(ova_out.vmdk_findings.clone());
                ova_outcome_opt = Some(ova_out);
            }
            Ok(Err(err)) => {
                let err_msg = format!(
                    "Failed to stream OVA/VMDK archive `{}` in userspace: {}",
                    ova_p.display(),
                    err
                );
                engines.push((
                    "ova_stream_inspector".to_string(),
                    JsonValue::OrderedObject(vec![
                        ("status".to_string(), JsonValue::str("io_error")),
                        ("error".to_string(), JsonValue::str(&err_msg)),
                    ]),
                ));
                findings.push(
                    Finding::new(
                        EngineId::OvaStreamInspector,
                        "HIGH_OVA_ARCHIVE_UNREADABLE",
                        Severity::High,
                        ova_p.to_string_lossy().into_owned(),
                        err_msg,
                    ),
                );
            }
            Err((fault_summary, fault_finding)) => {
                engines.push(("ova_stream_inspector".to_string(), fault_summary.clone()));
                engines.push(("vmdk_carver".to_string(), fault_summary));
                findings.push(fault_finding);
            }
        }
    }

    if cfg.attribute_cracker || ova_outcome_opt.is_some() {
        if ova_outcome_opt.is_none() && cfg.audit_root_filesystem {
            engines.push((
                "ova_stream_inspector".to_string(),
                JsonValue::OrderedObject(vec![(
                    "status".to_string(),
                    JsonValue::str("standby_no_ova_input"),
                )]),
            ));
            engines.push((
                "vmdk_carver".to_string(),
                JsonValue::OrderedObject(vec![(
                    "status".to_string(),
                    JsonValue::str("standby_no_ova_input"),
                )]),
            ));
        }
        let root_for_att = if cfg.audit_root_filesystem {
            Some(cfg.root_path.as_path())
        } else {
            None
        };
        let att_target_str = cfg.root_path.to_string_lossy().into_owned();
        match execute_isolated_engine_task(
            "cracker_attribution",
            EngineId::CrackerAttribution,
            &att_target_str,
            || {
                run_cracker_attribution_engine(
                    root_for_att,
                    birthmarks.as_ref(),
                    ova_outcome_opt.as_ref(),
                    cfg.org_label.as_deref(),
                    cfg.cluster_input_path.as_deref(),
                    &cfg.extra_fortinet_spkis,
                )
            },
        ) {
            Ok(att_res) => {
                engines.push(("cracker_attribution".to_string(), att_res.summary));
                findings.extend(att_res.findings);
            }
            Err((fault_summary, fault_finding)) => {
                engines.push(("cracker_attribution".to_string(), fault_summary));
                findings.push(fault_finding);
            }
        }
    }

    // 3. Verify post-audit non-mutation immediately after all engines complete
    let non_mutation_attestation = verify_post_audit_state(&pre_snapshot);

    // 4. Seal findings in RFC 6962 Binary Merkle Tree
    let merkle_envelope = MerkleTreeEnvelope::seal_findings(findings);

    // 5. Synthesize causal legal/technical breach verdicts & 0-100 risk score
    let verdict_summary = classify_forensic_verdicts(&merkle_envelope.sealed_findings);

    ForensicVerdictBundle {
        tool_name: "fsr-forensic-verdict",
        tool_version: env!("CARGO_PKG_VERSION"),
        context,
        self_integrity,
        verdict_summary,
        non_mutation_attestation,
        birthmarks,
        engines,
        merkle_envelope,
    }
}
