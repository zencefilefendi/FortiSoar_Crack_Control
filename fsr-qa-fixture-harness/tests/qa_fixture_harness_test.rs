use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use fsr_forensic_verdict::bundle_verifier::verify_forensic_bundle_file;
use fsr_forensic_verdict::{execute_forensic_verdict_command_center, ForensicVerdictConfig};
use fsr_qa_fixture_harness::{
    render_benchmark_table, run_qa_benchmark_suite, QA_REFERENCE_NOW_UNIX,
};

fn unique_qa_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), nanos))
}

#[test]
fn end_to_end_qa_scenarios_zero_fp_and_full_clone_breach_matrix() {
    let ws_dir = unique_qa_temp_dir("fsr_qa_suite_lib");
    let summary = run_qa_benchmark_suite(&ws_dir).expect("QA benchmark suite should succeed");

    assert!(
        summary.all_invariants_passed(),
        "expected zero invariant failures, got: {:?}",
        summary.invariant_failures
    );

    // 1. Scenario A (`clean_factory_node`): 0 findings, 0/100 score, 0% FP
    assert_eq!(summary.clean_metrics.engines_executed, 19);
    assert_eq!(summary.clean_metrics.total_findings, 0);
    assert_eq!(summary.clean_metrics.distinct_engines_triggered, 0);
    assert_eq!(summary.clean_metrics.composite_risk_score, 0);
    assert_eq!(summary.clean_metrics.verdict_status, "CLEAN");
    assert!(!summary.clean_metrics.target_mutated);
    assert!(summary.clean_bundle_verification.bundle_authentic);

    // 2. Scenario B & C (`org_alpha_node` + `org_beta_node` Golden Image clone cluster)
    assert_eq!(summary.org_alpha_cluster_metrics.engines_executed, 19);
    assert_eq!(
        summary.org_alpha_cluster_metrics.distinct_engines_triggered, 16,
        "all 16 offline-capable engines across Phases 1-4 must fire on org_alpha_node"
    );
    assert_eq!(summary.org_alpha_cluster_metrics.composite_risk_score, 100);
    assert_eq!(
        summary.clone_correlation_codes_triggered.len(),
        4,
        "all 4 Golden Image clone correlation codes must fire"
    );
    assert_eq!(
        summary.org_alpha_cluster_metrics.triggered_verdicts.len(),
        3,
        "all 3 primary causal DFIR verdicts must fire"
    );
    assert!(!summary.org_alpha_cluster_metrics.target_mutated);
    assert!(!summary.org_beta_metrics.target_mutated);

    // 3. Spot-check canonical finding codes across all 4 phases (16 offline engines)
    for must_have_code in [
        // Phase 1 (`fsr-deep-audit`)
        "CRITICAL_HW_SPOOF_HOOK",
        "CRITICAL_ELF_TEXT_INLINE_PATCH",
        "CRITICAL_GOT_PLT_POINTER_HIJACK",
        "CRITICAL_PYC_BYTECODE_RETURN_TRUE_STUB",
        "HIGH_PYC_RECOMPILED_TIMESTAMP_OUTLIER",
        "CRITICAL_RPM_FILE_DIGEST_MISMATCH",
        "CRITICAL_RPM_UNSIGNED_CYOPS_PACKAGE",
        "CRITICAL_RPM_BINARY_RPATH_HIJACK",
        // Phase 2 (`fsr-net-crypto-audit`)
        "CRITICAL_STATIC_DNS_FORTIGUARD_HIJACK",
        "CRITICAL_ROUTE_HIJACK_FORTINET_ASN",
        "CRITICAL_EBPF_NET_HIJACK",
        "CRITICAL_IMPERSONATED_FORTINET_CA",
        "CRITICAL_SSL_VERIFY_PROLOGUE_BYPASS",
        "CRITICAL_FGT_CENTRAL_MGMT_FDS_EMULATOR",
        // Phase 3 (`fsr-clone-cluster-audit`)
        "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
        "CRITICAL_FGVM_EVAL_TRIAL_IN_PRODUCTION",
        "CRITICAL_FGVM_HARDWARE_LIMIT_BYPASS",
        "CRITICAL_FGVM_UNSIGNED_OR_FORGED_LIC",
        "CRITICAL_CLONED_GOLDEN_IMAGE_PG_CLUSTER",
        "CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY",
        "CRITICAL_DUPLICATE_FGVM_SERIAL_CLONE",
        "HIGH_CLONED_VM_FILESYSTEM_UUID",
        // Phase 4 (`fsr-supplychain-backdoor-audit`)
        "CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER",
        "CRITICAL_OBFUSCATED_SOAR_PAYLOAD",
        "CRITICAL_NGINX_TRAFFIC_MIRROR_OR_BYPASS",
        "CRITICAL_DJANGO_AUTH_BYPASS_MIDDLEWARE",
        "CRITICAL_PG_PRELOAD_LIBRARY_IMPLANT",
        "CRITICAL_PG_HBA_TRUST_BACKDOOR",
        "CRITICAL_PAM_AUTH_BYPASS_IMPLANT",
        "CRITICAL_GHOST_UID0_ACCOUNT",
        "CRITICAL_FGT_AUTOMATION_EXFIL_BACKDOOR",
    ] {
        assert!(
            summary
                .distinct_finding_codes_in_breach
                .iter()
                .any(|c| c == must_have_code),
            "missing expected multi-phase finding code `{}`; present: {:?}",
            must_have_code,
            summary.distinct_finding_codes_in_breach
        );
    }

    // 4. Verify all 4 deliverable artifacts & standalone offline bundle verification
    let clean_html = fs::read_to_string(&summary.clean_report_html_path).unwrap();
    assert!(clean_html.contains("<!DOCTYPE html>"));
    assert!(clean_html.contains("0/100"));

    let breach_html = fs::read_to_string(&summary.breach_cluster_report_html_path).unwrap();
    assert!(breach_html.contains("<!DOCTYPE html>"));
    assert!(breach_html.contains("100/100"));
    assert!(breach_html.contains("VERDICT_WILFUL_LICENSE_CRACK_AND_CLONE"));

    let witness_md = fs::read_to_string(&summary.expert_witness_md_path).unwrap();
    assert!(witness_md.contains("RFC 6962"));
    assert!(witness_md.contains(&summary.org_alpha_cluster_metrics.merkle_root_hex));

    let standalone_check = verify_forensic_bundle_file(&summary.forensic_bundle_json_path);
    assert!(
        standalone_check.bundle_authentic,
        "standalone bundle verification errors: {:?}",
        standalone_check.errors
    );
    assert_eq!(
        standalone_check.verified_proofs_count,
        summary.org_alpha_cluster_metrics.total_findings
    );

    // 5. Determinism check: re-auditing the same forensic image produces identical RFC 6962 Merkle roots
    let clean_reaudit = execute_forensic_verdict_command_center(&ForensicVerdictConfig {
        root_path: summary.workspace.clean_node_root.clone(),
        live_mode: false,
        org_label: Some("CleanFactory_Ref".to_string()),
        reference_now_unix: Some(QA_REFERENCE_NOW_UNIX),
        ..Default::default()
    });
    let alpha_reaudit = execute_forensic_verdict_command_center(&ForensicVerdictConfig {
        root_path: summary.workspace.org_alpha_root.clone(),
        live_mode: false,
        org_label: Some("OrgAlpha_Prod_SOC".to_string()),
        reference_now_unix: Some(QA_REFERENCE_NOW_UNIX),
        fgt_config_path: Some(summary.workspace.org_alpha_fgt_config.clone()),
        fgt_license_files: vec![summary.workspace.org_alpha_fgvm_lic.clone()],
        cluster_input_path: Some(summary.org_beta_telemetry_json_path.clone()),
        ..Default::default()
    });
    assert_eq!(
        summary.clean_metrics.merkle_root_hex,
        clean_reaudit.merkle_envelope.merkle_root_hex
    );
    assert_eq!(
        summary.org_alpha_cluster_metrics.merkle_root_hex,
        alpha_reaudit.merkle_envelope.merkle_root_hex
    );

    let table = render_benchmark_table(&summary);
    assert!(table.contains("QA VERDICT: PASS"));

    let _ = fs::remove_dir_all(&ws_dir);
}

#[test]
fn cli_binary_executes_workspace_benchmark_and_emits_table_and_json() {
    let bin = env!("CARGO_BIN_EXE_fsr-qa-fixture-harness");
    let ws_dir = unique_qa_temp_dir("fsr_qa_suite_cli");

    let out_table = Command::new(bin)
        .arg("--workspace-dir")
        .arg(&ws_dir)
        .output()
        .expect("failed to execute fsr-qa-fixture-harness binary");

    assert!(
        out_table.status.success(),
        "CLI exited non-zero: stdout={}\nstderr={}",
        String::from_utf8_lossy(&out_table.stdout),
        String::from_utf8_lossy(&out_table.stderr)
    );
    let stdout_str = String::from_utf8_lossy(&out_table.stdout);
    assert!(stdout_str.contains("ZERO FALSE POSITIVES"));
    assert!(stdout_str.contains("QA VERDICT: PASS"));

    assert!(ws_dir.join("clean_report.html").is_file());
    assert!(ws_dir.join("breach_cluster_report.html").is_file());
    assert!(ws_dir.join("expert_witness.md").is_file());
    assert!(ws_dir.join("forensic_bundle.json").is_file());

    let out_json = Command::new(bin)
        .arg("--workspace-dir")
        .arg(&ws_dir)
        .arg("--json")
        .output()
        .expect("failed to execute fsr-qa-fixture-harness --json");
    assert!(out_json.status.success());
    let json_str = String::from_utf8_lossy(&out_json.stdout);
    assert!(json_str.contains("\"all_invariants_passed\": true"));

    let _ = fs::remove_dir_all(&ws_dir);
}
