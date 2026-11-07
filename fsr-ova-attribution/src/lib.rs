//! `fsr-ova-attribution` (Phase 8 — Zero-Mount OVA/VMDK Forensics & Crack-Kit Attribution):
//!
//! Provides 3 zero-external-crate, zero-`mount` forensic & threat-intelligence engines:
//!   1. [`ova_stream_inspector`]: Userspace POSIX `ustar` `.ova` archive reader, `.mf`/`.cert`
//!      SHA-1/SHA-256 manifest verifier (`CRITICAL_OVA_MANIFEST_TAMPERED`), and `.ovf` XML
//!      virtual hardware / MAC / SMBIOS UUID inspector.
//!   2. [`vmdk_carver`]: Binary `VMDK4` (`KDMV` - `0x564d444b`), VMDK descriptor, and `QCOW2`
//!      header parser + overlapping sliding-window binary signature carver (`pg_control` with
//!      Castagnoli CRC-32C, EXT4 `0xEF53` & XFS `XFSB` superblocks, X.509 DER/PEM certificates,
//!      and ELF64 `libssl.so.3` / `pam_unix.so` patch idioms).
//!   3. [`cracker_attribution`]: Behavioral & binary **Crack-Kit DNA** (`CKIT-SHA256-...`)
//!      synthesizer and cross-organization toolkit attribution correlator
//!      (`CRITICAL_SAME_CRACKER_TOOLKIT_ATTRIBUTION`).

pub mod cracker_attribution;
pub mod ova_stream_inspector;
pub mod vmdk_carver;

use std::io;
use std::path::{Path, PathBuf};

use fsr_clone_cluster_audit::birthmark_extractor::DeviceBirthmarks;
use fsr_deep_audit::collect_scan_context;
use fsr_deep_audit::schema::{build_canonical_report_json, Finding, JsonValue, ScanContext};

use crate::cracker_attribution::{run_cracker_attribution_engine, CrackerAttributionResult};
use crate::ova_stream_inspector::{inspect_ova_file, OvaInspectionOutcome};

/// Runtime configuration for `fsr-ova-attribution`.
#[derive(Debug, Clone, Default)]
pub struct OvaAttributionConfig {
    pub ova_path: Option<PathBuf>,
    pub root_path: Option<PathBuf>,
    pub attribute_cracker: bool,
    pub org_label: Option<String>,
    pub cluster_input_path: Option<PathBuf>,
    pub extra_fortinet_spkis: Vec<String>,
}

/// Combined execution output of the Phase-8 OVA/VMDK & Crack-Kit Attribution suite.
#[derive(Debug, Clone)]
pub struct OvaAttributionSuiteReport {
    pub context: ScanContext,
    pub ova_outcome: Option<OvaInspectionOutcome>,
    pub attribution: Option<CrackerAttributionResult>,
    pub engines: Vec<(String, JsonValue)>,
    pub findings: Vec<Finding>,
}

impl OvaAttributionSuiteReport {
    pub fn into_canonical_json(self) -> JsonValue {
        build_canonical_report_json(
            "fsr-ova-attribution",
            env!("CARGO_PKG_VERSION"),
            &self.context,
            self.engines,
            self.findings,
        )
    }
}

/// Runs the requested Phase-8 engines (`ova_stream_inspector`, `vmdk_carver`, `cracker_attribution`).
pub fn execute_ova_attribution_suite(
    cfg: &OvaAttributionConfig,
    precomputed_birthmarks: Option<&DeviceBirthmarks>,
) -> io::Result<OvaAttributionSuiteReport> {
    let ctx_root = cfg
        .root_path
        .as_deref()
        .or(cfg.ova_path.as_deref())
        .unwrap_or_else(|| Path::new("/"));
    let mut context = collect_scan_context(ctx_root);
    if cfg.root_path.is_none() {
        if let Some(ova_p) = &cfg.ova_path {
            context.root_path = ova_p.to_string_lossy().into_owned();
        }
    }

    let mut engines = Vec::new();
    let mut findings = Vec::new();

    let ova_outcome = if let Some(ova_p) = &cfg.ova_path {
        let out = inspect_ova_file(ova_p, &cfg.extra_fortinet_spkis)?;
        if let Some(hw) = &out.ovf_hardware {
            if let Some(vs_name) = &hw.virtual_system_name {
                if cfg.root_path.is_none() {
                    context.hostname = vs_name.clone();
                }
            }
        }
        engines.push(("ova_stream_inspector".to_string(), out.ova_summary_json()));
        engines.push(("vmdk_carver".to_string(), out.vmdk_summary_json()));
        findings.extend(out.ova_findings.clone());
        findings.extend(out.vmdk_findings.clone());
        Some(out)
    } else {
        None
    };

    let attribution = if cfg.attribute_cracker || ova_outcome.is_some() {
        let att = run_cracker_attribution_engine(
            cfg.root_path.as_deref(),
            precomputed_birthmarks,
            ova_outcome.as_ref(),
            cfg.org_label.as_deref(),
            cfg.cluster_input_path.as_deref(),
            &cfg.extra_fortinet_spkis,
        );
        engines.push(("cracker_attribution".to_string(), att.summary.clone()));
        findings.extend(att.findings.clone());
        Some(att)
    } else {
        None
    };

    Ok(OvaAttributionSuiteReport {
        context,
        ova_outcome,
        attribution,
        engines,
        findings,
    })
}
