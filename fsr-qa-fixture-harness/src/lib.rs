//! `fsr-qa-fixture-harness` (Phase 6 — Synthetic Forensic Fixture & QA Benchmark Suite):
//!
//! Zero-external-crate synthetic test-vector generator and end-to-end verification
//! harness for the 19-engine `fsr-forensic-verdict` workspace. Builds three isolated,
//! completely inert mock appliance trees inside `--workspace-dir` (default
//! `/tmp/fsr_qa_benchmark`):
//!   - **Scenario A (`clean_factory_node`)**: Valid RSA/SHA-256 `rpmdb.sqlite`, clean
//!     ELF64 `libssl.so.3` / `pam_unix.so`, cohesive PEP 552 `.pyc` cohort, standard
//!     WebPKI root CA, unique `pg_control` with valid Castagnoli CRC-32C, and official
//!     SOAR connector baseline — proving **0 findings, 0/100 risk score, and 0% false
//!     positives**.
//!   - **Scenarios B & C (`org_alpha_node` & `org_beta_node`)**: Two distinct simulated
//!     tenant appliances sharing identical Golden Image birthmarks (`pg_control` 64-bit
//!     `system_identifier`, EXT4/XFS superblock UUIDs, SOAR Vault `SECRET_KEY`, and
//!     `FGVM` X.509 certificate), with `org_alpha_node` populated with inert byte
//!     vectors across Phases 1–4.
//!   - **Automated Orchestration & Self-Verification**: Runs `fsr-forensic-verdict`
//!     across all three nodes, writes `clean_report.html`, `breach_cluster_report.html`,
//!     `expert_witness.md`, and `forensic_bundle.json`, and self-verifies the RFC 6962
//!     `merkle_root_hex`, per-finding `MerkleInclusionProof` chains, and
//!     `NonMutationAttestation` offline via `verify_forensic_bundle_file`.

pub mod benchmark_runner;
pub mod binary_synthesizers;
pub mod scenario_builder;

pub use benchmark_runner::{
    render_benchmark_table, run_qa_benchmark_suite, QaBenchmarkSummary, ScenarioBenchmarkMetrics,
    QA_REFERENCE_NOW_UNIX,
};
pub use scenario_builder::{build_all_qa_scenarios, BuiltQaWorkspace};
