//! Automated Multi-Scenario Orchestration, Self-Verification & Benchmark Matrix Runner.
//!
//! Executes `fsr-forensic-verdict` across all three synthetic QA scenarios inside
//! `--workspace-dir` (`clean_factory_node`, `org_beta_node`, and `org_alpha_node`
//! cross-correlated against `org_beta_node`), emits all four executive/legal/machine
//! deliverables (`clean_report.html`, `breach_cluster_report.html`, `expert_witness.md`,
//! `forensic_bundle.json`), runs offline cryptographic `verify_forensic_bundle_file`
//! self-verification across the sealed bundles, asserts zero false positives and 100%
//! causal/clone coverage, and formats a CISO/CI summary benchmark table.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use fsr_deep_audit::schema::JsonValue;
use fsr_forensic_verdict::bundle_verifier::{
    verify_forensic_bundle_file, BundleVerificationReport,
};
use fsr_forensic_verdict::report_emitter::{emit_forensic_report, OutputFormat};
use fsr_forensic_verdict::verdict_classifier::{
    CODE_ACTIVE_SUPPLY_CHAIN_IMPLANT, CODE_DECEPTIVE_SECURITY_BLINDNESS,
    CODE_WILFUL_CRACK_AND_CLONE,
};
use fsr_forensic_verdict::{execute_forensic_verdict_command_center, ForensicVerdictConfig};

use crate::scenario_builder::{build_all_qa_scenarios, BuiltQaWorkspace};

/// Reference Unix UTC timestamp used for deterministic `time_freeze_audit` evaluation
/// across QA runs (`2025-10-10T12:13:20Z`, cleanly ahead of the `1_750_000_xxx` fixture mtimes).
pub const QA_REFERENCE_NOW_UNIX: i64 = 1_760_100_000;

/// Per-scenario execution metrics captured during the QA benchmark run.
#[derive(Debug, Clone)]
pub struct ScenarioBenchmarkMetrics {
    pub scenario_id: &'static str,
    pub root_path: PathBuf,
    pub engines_executed: usize,
    pub distinct_engines_triggered: usize,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub composite_risk_score: u32,
    pub verdict_status: String,
    pub triggered_verdicts: Vec<String>,
    pub merkle_root_hex: String,
    pub target_mutated: bool,
    pub tracked_artifacts_count: usize,
    pub bundle_verified_authentic: bool,
    pub elapsed_micros: u128,
}

impl ScenarioBenchmarkMetrics {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("scenario_id".to_string(), JsonValue::str(self.scenario_id)),
            (
                "root_path".to_string(),
                JsonValue::str(self.root_path.to_string_lossy()),
            ),
            (
                "engines_executed".to_string(),
                JsonValue::Uint(self.engines_executed as u64),
            ),
            (
                "distinct_engines_triggered".to_string(),
                JsonValue::Uint(self.distinct_engines_triggered as u64),
            ),
            (
                "total_findings".to_string(),
                JsonValue::Uint(self.total_findings as u64),
            ),
            (
                "critical_findings".to_string(),
                JsonValue::Uint(self.critical_findings as u64),
            ),
            (
                "high_findings".to_string(),
                JsonValue::Uint(self.high_findings as u64),
            ),
            (
                "composite_risk_score".to_string(),
                JsonValue::Uint(self.composite_risk_score as u64),
            ),
            (
                "verdict_status".to_string(),
                JsonValue::str(&self.verdict_status),
            ),
            (
                "triggered_verdicts".to_string(),
                JsonValue::Array(
                    self.triggered_verdicts
                        .iter()
                        .map(|v| JsonValue::str(v.as_str()))
                        .collect(),
                ),
            ),
            (
                "merkle_root_hex".to_string(),
                JsonValue::str(&self.merkle_root_hex),
            ),
            (
                "target_mutated".to_string(),
                JsonValue::Bool(self.target_mutated),
            ),
            (
                "tracked_artifacts_count".to_string(),
                JsonValue::Uint(self.tracked_artifacts_count as u64),
            ),
            (
                "bundle_verified_authentic".to_string(),
                JsonValue::Bool(self.bundle_verified_authentic),
            ),
            (
                "elapsed_micros".to_string(),
                JsonValue::Uint(self.elapsed_micros as u64),
            ),
        ])
    }
}

/// Complete QA benchmark & cryptographic self-verification summary.
#[derive(Debug, Clone)]
pub struct QaBenchmarkSummary {
    pub workspace: BuiltQaWorkspace,
    pub clean_metrics: ScenarioBenchmarkMetrics,
    pub org_beta_metrics: ScenarioBenchmarkMetrics,
    pub org_alpha_cluster_metrics: ScenarioBenchmarkMetrics,
    pub clean_report_html_path: PathBuf,
    pub clean_bundle_json_path: PathBuf,
    pub org_beta_telemetry_json_path: PathBuf,
    pub breach_cluster_report_html_path: PathBuf,
    pub expert_witness_md_path: PathBuf,
    pub forensic_bundle_json_path: PathBuf,
    pub clean_bundle_verification: BundleVerificationReport,
    pub breach_bundle_verification: BundleVerificationReport,
    pub clone_correlation_codes_triggered: Vec<String>,
    pub distinct_finding_codes_in_breach: Vec<String>,
    pub total_suite_elapsed_micros: u128,
    pub invariant_failures: Vec<String>,
}

impl QaBenchmarkSummary {
    /// Returns `true` iff every zero-FP, clone-correlation, causal-verdict, non-mutation,
    /// and RFC 6962 Merkle proof invariant succeeded with zero errors.
    pub fn all_invariants_passed(&self) -> bool {
        self.invariant_failures.is_empty()
    }

    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("schema_version".to_string(), JsonValue::str("1.0.0")),
            (
                "harness".to_string(),
                JsonValue::str("fsr-qa-fixture-harness"),
            ),
            (
                "workspace_dir".to_string(),
                JsonValue::str(self.workspace.workspace_dir.to_string_lossy()),
            ),
            (
                "all_invariants_passed".to_string(),
                JsonValue::Bool(self.all_invariants_passed()),
            ),
            (
                "total_suite_elapsed_micros".to_string(),
                JsonValue::Uint(self.total_suite_elapsed_micros as u64),
            ),
            (
                "scenarios".to_string(),
                JsonValue::Array(vec![
                    self.clean_metrics.to_json(),
                    self.org_beta_metrics.to_json(),
                    self.org_alpha_cluster_metrics.to_json(),
                ]),
            ),
            (
                "emitted_artifacts".to_string(),
                JsonValue::OrderedObject(vec![
                    (
                        "clean_report_html".to_string(),
                        JsonValue::str(self.clean_report_html_path.to_string_lossy()),
                    ),
                    (
                        "breach_cluster_report_html".to_string(),
                        JsonValue::str(self.breach_cluster_report_html_path.to_string_lossy()),
                    ),
                    (
                        "expert_witness_md".to_string(),
                        JsonValue::str(self.expert_witness_md_path.to_string_lossy()),
                    ),
                    (
                        "forensic_bundle_json".to_string(),
                        JsonValue::str(self.forensic_bundle_json_path.to_string_lossy()),
                    ),
                ]),
            ),
            (
                "clone_correlation_codes_triggered".to_string(),
                JsonValue::Array(
                    self.clone_correlation_codes_triggered
                        .iter()
                        .map(|c| JsonValue::str(c.as_str()))
                        .collect(),
                ),
            ),
            (
                "breach_bundle_verification".to_string(),
                self.breach_bundle_verification.to_json(),
            ),
            (
                "clean_bundle_verification".to_string(),
                self.clean_bundle_verification.to_json(),
            ),
            (
                "invariant_failures".to_string(),
                JsonValue::Array(
                    self.invariant_failures
                        .iter()
                        .map(|e| JsonValue::str(e.as_str()))
                        .collect(),
                ),
            ),
        ])
    }
}

/// Builds all 3 synthetic QA nodes inside `workspace_dir`, executes `fsr-forensic-verdict`
/// across them, emits the 4 required reports/bundles, self-verifies the Merkle & non-mutation
/// proofs via `verify_forensic_bundle_file`, and validates every QA invariant.
pub fn run_qa_benchmark_suite(workspace_dir: &Path) -> Result<QaBenchmarkSummary, String> {
    let suite_t0 = Instant::now();
    let workspace = build_all_qa_scenarios(workspace_dir)?;

    let clean_report_html_path = workspace_dir.join("clean_report.html");
    let clean_bundle_json_path = workspace_dir.join("clean_forensic_bundle.json");
    let org_beta_telemetry_json_path = workspace_dir.join("org_beta_telemetry.json");
    let breach_cluster_report_html_path = workspace_dir.join("breach_cluster_report.html");
    let expert_witness_md_path = workspace_dir.join("expert_witness.md");
    let forensic_bundle_json_path = workspace_dir.join("forensic_bundle.json");

    // ------------------------------------------------------------------------
    // 1. Scenario A: `clean_factory_node` (Zero False-Positive Reference)
    // ------------------------------------------------------------------------
    let clean_t0 = Instant::now();
    let clean_bundle = execute_forensic_verdict_command_center(&ForensicVerdictConfig {
        root_path: workspace.clean_node_root.clone(),
        live_mode: false,
        org_label: Some("CleanFactory_Ref".to_string()),
        reference_now_unix: Some(QA_REFERENCE_NOW_UNIX),
        ..Default::default()
    });
    let clean_elapsed = clean_t0.elapsed().as_micros();

    let clean_html = emit_forensic_report(&clean_bundle, OutputFormat::Html, true);
    fs::write(&clean_report_html_path, clean_html.as_bytes())
        .map_err(|e| format!("failed to write clean_report.html: {}", e))?;

    let clean_json = emit_forensic_report(&clean_bundle, OutputFormat::Json, true);
    fs::write(&clean_bundle_json_path, clean_json.as_bytes())
        .map_err(|e| format!("failed to write clean_forensic_bundle.json: {}", e))?;

    let clean_bundle_verification = verify_forensic_bundle_file(&clean_bundle_json_path);

    let clean_metrics = ScenarioBenchmarkMetrics {
        scenario_id: "Scenario A: clean_factory_node",
        root_path: workspace.clean_node_root.clone(),
        engines_executed: clean_bundle.engines.len(),
        distinct_engines_triggered: clean_bundle.verdict_summary.distinct_compromised_engines,
        total_findings: clean_bundle.verdict_summary.total_findings,
        critical_findings: clean_bundle.verdict_summary.critical_count,
        high_findings: clean_bundle.verdict_summary.high_count,
        composite_risk_score: clean_bundle.verdict_summary.composite_risk_score,
        verdict_status: clean_bundle.verdict_summary.status.to_string(),
        triggered_verdicts: clean_bundle
            .verdict_summary
            .triggered_verdict_codes
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        merkle_root_hex: clean_bundle.merkle_envelope.merkle_root_hex.clone(),
        target_mutated: clean_bundle.non_mutation_attestation.target_mutated,
        tracked_artifacts_count: clean_bundle
            .non_mutation_attestation
            .tracked_artifacts
            .len(),
        bundle_verified_authentic: clean_bundle_verification.bundle_authentic,
        elapsed_micros: clean_elapsed,
    };

    // ------------------------------------------------------------------------
    // 2. Scenario C (Peer Node): `org_beta_node` -> `org_beta_telemetry.json`
    // ------------------------------------------------------------------------
    let beta_t0 = Instant::now();
    let beta_bundle = execute_forensic_verdict_command_center(&ForensicVerdictConfig {
        root_path: workspace.org_beta_root.clone(),
        live_mode: false,
        org_label: Some("OrgBeta_DR_Tenant".to_string()),
        reference_now_unix: Some(QA_REFERENCE_NOW_UNIX),
        ..Default::default()
    });
    let beta_elapsed = beta_t0.elapsed().as_micros();

    let beta_json = emit_forensic_report(&beta_bundle, OutputFormat::Json, true);
    fs::write(&org_beta_telemetry_json_path, beta_json.as_bytes())
        .map_err(|e| format!("failed to write org_beta_telemetry.json: {}", e))?;

    let beta_verification = verify_forensic_bundle_file(&org_beta_telemetry_json_path);

    let org_beta_metrics = ScenarioBenchmarkMetrics {
        scenario_id: "Scenario C: org_beta_node (Peer Clone)",
        root_path: workspace.org_beta_root.clone(),
        engines_executed: beta_bundle.engines.len(),
        distinct_engines_triggered: beta_bundle.verdict_summary.distinct_compromised_engines,
        total_findings: beta_bundle.verdict_summary.total_findings,
        critical_findings: beta_bundle.verdict_summary.critical_count,
        high_findings: beta_bundle.verdict_summary.high_count,
        composite_risk_score: beta_bundle.verdict_summary.composite_risk_score,
        verdict_status: beta_bundle.verdict_summary.status.to_string(),
        triggered_verdicts: beta_bundle
            .verdict_summary
            .triggered_verdict_codes
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        merkle_root_hex: beta_bundle.merkle_envelope.merkle_root_hex.clone(),
        target_mutated: beta_bundle.non_mutation_attestation.target_mutated,
        tracked_artifacts_count: beta_bundle.non_mutation_attestation.tracked_artifacts.len(),
        bundle_verified_authentic: beta_verification.bundle_authentic,
        elapsed_micros: beta_elapsed,
    };

    // ------------------------------------------------------------------------
    // 3. Scenario B + C Cluster Correlation: `org_alpha_node` + `org_beta_node`
    // ------------------------------------------------------------------------
    let alpha_t0 = Instant::now();
    let alpha_bundle = execute_forensic_verdict_command_center(&ForensicVerdictConfig {
        root_path: workspace.org_alpha_root.clone(),
        live_mode: false,
        org_label: Some("OrgAlpha_Prod_SOC".to_string()),
        reference_now_unix: Some(QA_REFERENCE_NOW_UNIX),
        fgt_config_path: Some(workspace.org_alpha_fgt_config.clone()),
        fgt_license_files: vec![workspace.org_alpha_fgvm_lic.clone()],
        cluster_input_path: Some(org_beta_telemetry_json_path.clone()),
        ..Default::default()
    });
    let alpha_elapsed = alpha_t0.elapsed().as_micros();

    let breach_html = emit_forensic_report(&alpha_bundle, OutputFormat::Html, true);
    fs::write(&breach_cluster_report_html_path, breach_html.as_bytes())
        .map_err(|e| format!("failed to write breach_cluster_report.html: {}", e))?;

    let expert_md = emit_forensic_report(&alpha_bundle, OutputFormat::Markdown, true);
    fs::write(&expert_witness_md_path, expert_md.as_bytes())
        .map_err(|e| format!("failed to write expert_witness.md: {}", e))?;

    let breach_json = emit_forensic_report(&alpha_bundle, OutputFormat::Json, true);
    fs::write(&forensic_bundle_json_path, breach_json.as_bytes())
        .map_err(|e| format!("failed to write forensic_bundle.json: {}", e))?;

    // Self-Verification via standalone `verify_forensic_bundle_file`
    let breach_bundle_verification = verify_forensic_bundle_file(&forensic_bundle_json_path);

    let org_alpha_cluster_metrics = ScenarioBenchmarkMetrics {
        scenario_id: "Scenario B+C: org_alpha_node + Cluster",
        root_path: workspace.org_alpha_root.clone(),
        engines_executed: alpha_bundle.engines.len(),
        distinct_engines_triggered: alpha_bundle.verdict_summary.distinct_compromised_engines,
        total_findings: alpha_bundle.verdict_summary.total_findings,
        critical_findings: alpha_bundle.verdict_summary.critical_count,
        high_findings: alpha_bundle.verdict_summary.high_count,
        composite_risk_score: alpha_bundle.verdict_summary.composite_risk_score,
        verdict_status: alpha_bundle.verdict_summary.status.to_string(),
        triggered_verdicts: alpha_bundle
            .verdict_summary
            .triggered_verdict_codes
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        merkle_root_hex: alpha_bundle.merkle_envelope.merkle_root_hex.clone(),
        target_mutated: alpha_bundle.non_mutation_attestation.target_mutated,
        tracked_artifacts_count: alpha_bundle
            .non_mutation_attestation
            .tracked_artifacts
            .len(),
        bundle_verified_authentic: breach_bundle_verification.bundle_authentic,
        elapsed_micros: alpha_elapsed,
    };

    // ------------------------------------------------------------------------
    // 4. QA Invariant Assertions (Zero FP, Clone Cluster, 3 Verdicts, Merkle, Non-Mutation)
    // ------------------------------------------------------------------------
    let mut invariant_failures = Vec::new();

    // 4A. Scenario A (`clean_factory_node`) MUST produce 0 findings, 0/100 score, 0% FP
    if clean_metrics.engines_executed != 19 {
        invariant_failures.push(format!(
            "clean_factory_node executed {} engines instead of 19",
            clean_metrics.engines_executed
        ));
    }
    if clean_metrics.total_findings != 0 {
        let leaked_codes: Vec<String> = clean_bundle
            .merkle_envelope
            .sealed_findings
            .iter()
            .map(|sf| format!("{}::{}", sf.finding.engine.as_str(), sf.finding.code))
            .collect();
        invariant_failures.push(format!(
            "clean_factory_node produced {} false-positive finding(s): {:?}",
            clean_metrics.total_findings, leaked_codes
        ));
    }
    if clean_metrics.composite_risk_score != 0 || clean_metrics.verdict_status != "CLEAN" {
        invariant_failures.push(format!(
            "clean_factory_node expected CLEAN (0/100), got {} ({}/100)",
            clean_metrics.verdict_status, clean_metrics.composite_risk_score
        ));
    }
    if clean_metrics.target_mutated {
        invariant_failures.push("clean_factory_node non-mutation attestation failed".to_string());
    }
    if !clean_bundle_verification.bundle_authentic {
        invariant_failures.push(format!(
            "clean_forensic_bundle.json verification failed: {:?}",
            clean_bundle_verification.errors
        ));
    }

    // 4B. Scenario B+C (`org_alpha_node` correlated with `org_beta_node`)
    let mut breach_codes_set = BTreeSet::new();
    for sf in &alpha_bundle.merkle_envelope.sealed_findings {
        breach_codes_set.insert(sf.finding.code.clone());
    }
    let distinct_finding_codes_in_breach: Vec<String> = breach_codes_set.iter().cloned().collect();

    let expected_clone_codes = [
        "CRITICAL_CLONED_GOLDEN_IMAGE_PG_CLUSTER",
        "CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY",
        "CRITICAL_DUPLICATE_FGVM_SERIAL_CLONE",
        "HIGH_CLONED_VM_FILESYSTEM_UUID",
    ];
    let mut clone_correlation_codes_triggered = Vec::new();
    for code in expected_clone_codes {
        if breach_codes_set.contains(code) {
            clone_correlation_codes_triggered.push(code.to_string());
        } else {
            invariant_failures.push(format!(
                "missing expected Golden Image clone correlation code `{}` between org_alpha_node and org_beta_node",
                code
            ));
        }
    }

    // Verify all 3 primary causal verdicts fired with 100/100 composite risk score
    for expected_verdict in [
        CODE_WILFUL_CRACK_AND_CLONE,
        CODE_ACTIVE_SUPPLY_CHAIN_IMPLANT,
        CODE_DECEPTIVE_SECURITY_BLINDNESS,
    ] {
        if !org_alpha_cluster_metrics
            .triggered_verdicts
            .iter()
            .any(|v| v == expected_verdict)
        {
            invariant_failures.push(format!(
                "org_alpha_node did not trigger primary causal verdict `{}`",
                expected_verdict
            ));
        }
    }
    if org_alpha_cluster_metrics.composite_risk_score != 100 {
        invariant_failures.push(format!(
            "org_alpha_node expected 100/100 composite risk score, got {}/100",
            org_alpha_cluster_metrics.composite_risk_score
        ));
    }

    // Verify all 16 offline-applicable engines fired on `org_alpha_node`
    // (19 total engines; `live_fdn_probe`, `ebpf_socket_probe`, and `remote_fingerprinter`
    // are strictly `--live` / `--scan-targets` active network probes and remain read-only silent offline).
    if org_alpha_cluster_metrics.distinct_engines_triggered < 16 {
        invariant_failures.push(format!(
            "org_alpha_node triggered {} distinct engines; expected at least 16 offline engines",
            org_alpha_cluster_metrics.distinct_engines_triggered
        ));
    }

    // Verify offline cryptographic `verify_forensic_bundle_file` on `forensic_bundle.json`
    if !breach_bundle_verification.bundle_authentic
        || !breach_bundle_verification.merkle_valid
        || !breach_bundle_verification.attestation_valid
    {
        invariant_failures.push(format!(
            "forensic_bundle.json failed cryptographic self-verification: {:?}",
            breach_bundle_verification.errors
        ));
    }
    if breach_bundle_verification.verified_proofs_count != org_alpha_cluster_metrics.total_findings
    {
        invariant_failures.push(format!(
            "Merkle inclusion proof count mismatch: verified {} vs {} total findings",
            breach_bundle_verification.verified_proofs_count,
            org_alpha_cluster_metrics.total_findings
        ));
    }
    if org_alpha_cluster_metrics.target_mutated || org_beta_metrics.target_mutated {
        invariant_failures
            .push("target_mutated=true detected on org_alpha_node or org_beta_node".to_string());
    }
    if !beta_verification.bundle_authentic {
        invariant_failures.push(format!(
            "org_beta_telemetry.json failed bundle verification: {:?}",
            beta_verification.errors
        ));
    }

    // Verify all 4 required deliverable files exist and are non-empty
    for required_file in [
        &clean_report_html_path,
        &breach_cluster_report_html_path,
        &expert_witness_md_path,
        &forensic_bundle_json_path,
    ] {
        match fs::metadata(required_file) {
            Ok(m) if m.len() > 256 => {}
            Ok(m) => invariant_failures.push(format!(
                "deliverable '{}' is unexpectedly small ({} bytes)",
                required_file.display(),
                m.len()
            )),
            Err(e) => invariant_failures.push(format!(
                "deliverable '{}' missing: {}",
                required_file.display(),
                e
            )),
        }
    }

    let total_suite_elapsed_micros = suite_t0.elapsed().as_micros();

    Ok(QaBenchmarkSummary {
        workspace,
        clean_metrics,
        org_beta_metrics,
        org_alpha_cluster_metrics,
        clean_report_html_path,
        clean_bundle_json_path,
        org_beta_telemetry_json_path,
        breach_cluster_report_html_path,
        expert_witness_md_path,
        forensic_bundle_json_path,
        clean_bundle_verification,
        breach_bundle_verification,
        clone_correlation_codes_triggered,
        distinct_finding_codes_in_breach,
        total_suite_elapsed_micros,
        invariant_failures,
    })
}

/// Formats a deterministic, human-scannable QA & CI Benchmark Summary Table for terminal output.
pub fn render_benchmark_table(summary: &QaBenchmarkSummary) -> String {
    let mut out = String::with_capacity(4096);
    let bar = "================================================================================================================";
    let sep = "----------------------------------------------------------------------------------------------------------------";

    let _ = writeln!(out, "{}", bar);
    let _ = writeln!(
        out,
        " FSR-QA-FIXTURE-HARNESS v{} — END-TO-END 19-ENGINE BENCHMARK & CRYPTOGRAPHIC SELF-VERIFICATION MATRIX",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(
        out,
        " Isolated QA Workspace : {}",
        summary.workspace.workspace_dir.display()
    );
    let _ = writeln!(out, "{}", bar);
    let _ = writeln!(
        out,
        " {:<38} | {:>7} | {:>8} | {:>9} | {:>12} | {:>12} | {:>9}",
        "SCENARIO",
        "ENGINES",
        "FINDINGS",
        "RISK",
        "NON-MUTATION",
        "MERKLE PROOF",
        "LATENCY"
    );
    let _ = writeln!(out, "{}", sep);

    for row in [
        &summary.clean_metrics,
        &summary.org_beta_metrics,
        &summary.org_alpha_cluster_metrics,
    ] {
        let engines_col = format!(
            "{}/{}",
            row.distinct_engines_triggered, row.engines_executed
        );
        let risk_col = format!("{}/100", row.composite_risk_score);
        let non_mut_col = if !row.target_mutated {
            "PASS (0 mut)"
        } else {
            "FAIL (MUT!)"
        };
        let merkle_col = if row.bundle_verified_authentic {
            "VERIFIED OK"
        } else {
            "VERIFY FAIL"
        };
        let latency_ms = (row.elapsed_micros as f64) / 1000.0;
        let _ = writeln!(
            out,
            " {:<38} | {:>7} | {:>8} | {:>9} | {:>12} | {:>12} | {:>6.2} ms",
            row.scenario_id,
            engines_col,
            row.total_findings,
            risk_col,
            non_mut_col,
            merkle_col,
            latency_ms
        );
    }

    let _ = writeln!(out, "{}", sep);
    let fp_rate = if summary.clean_metrics.total_findings == 0 {
        "0.00% (0/19 engines triggered — ZERO FALSE POSITIVES)"
    } else {
        "NON-ZERO FALSE POSITIVE DETECTED!"
    };
    let _ = writeln!(out, " [Scenario A] False-Positive Rate     : {}", fp_rate);
    let _ = writeln!(
        out,
        " [Scenario B+C] Clone Correlation     : {}/4 dimensions matched ({})",
        summary.clone_correlation_codes_triggered.len(),
        summary.clone_correlation_codes_triggered.join(", ")
    );
    let _ = writeln!(
        out,
        " [Scenario B+C] Causal Breach Verdicts: {}/3 ({})",
        summary.org_alpha_cluster_metrics.triggered_verdicts.len(),
        summary
            .org_alpha_cluster_metrics
            .triggered_verdicts
            .join(", ")
    );
    let _ = writeln!(
        out,
        " [RFC 6962 Seal] Breach Merkle Root   : {}",
        summary.org_alpha_cluster_metrics.merkle_root_hex
    );
    let _ = writeln!(
        out,
        " [RFC 6962 Seal] Inclusion Proofs     : {}/{} verified offline via verify_forensic_bundle_file",
        summary.breach_bundle_verification.verified_proofs_count,
        summary.org_alpha_cluster_metrics.total_findings
    );
    let _ = writeln!(
        out,
        " [Read-Only Seal] Attested Artifacts  : {} clean + {} org_beta + {} org_alpha (target_mutated = false)",
        summary.clean_metrics.tracked_artifacts_count,
        summary.org_beta_metrics.tracked_artifacts_count,
        summary.org_alpha_cluster_metrics.tracked_artifacts_count
    );
    let _ = writeln!(out, "{}", sep);
    let _ = writeln!(out, " Generated CISO / Legal / Machine Deliverables:");
    let _ = writeln!(
        out,
        "   1. Clean Factory HTML Report   : {}",
        summary.clean_report_html_path.display()
    );
    let _ = writeln!(
        out,
        "   2. Breach Cluster HTML Report  : {}",
        summary.breach_cluster_report_html_path.display()
    );
    let _ = writeln!(
        out,
        "   3. Expert Witness Markdown     : {}",
        summary.expert_witness_md_path.display()
    );
    let _ = writeln!(
        out,
        "   4. Sealed Forensic JSON Bundle : {}",
        summary.forensic_bundle_json_path.display()
    );
    let _ = writeln!(out, "{}", sep);

    let total_ms = (summary.total_suite_elapsed_micros as f64) / 1000.0;
    if summary.all_invariants_passed() {
        let _ = writeln!(
            out,
            " QA VERDICT: PASS — ALL ZERO-FP, CLONE-CORRELATION, MERKLE & NON-MUTATION INVARIANTS VERIFIED ({:.2} ms)",
            total_ms
        );
    } else {
        let _ = writeln!(
            out,
            " QA VERDICT: FAIL — {} INVARIANT VIOLATION(S) DETECTED ({:.2} ms):",
            summary.invariant_failures.len(),
            total_ms
        );
        for err in &summary.invariant_failures {
            let _ = writeln!(out, "   - {}", err);
        }
    }
    let _ = writeln!(out, "{}", bar);

    out
}
