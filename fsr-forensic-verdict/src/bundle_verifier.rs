//! Engine 5: Standalone Offline Cryptographic Evidence Bundle Verifier (`--verify-bundle`).
//!
//! Independently audits a previously emitted `forensic_bundle.json` (pretty JSON or
//! compact NDJSON) **without touching any target appliance or filesystem**, proving in
//! court, incident response, or third-party compliance review that not a single byte of
//! any finding, Merkle proof, verdict counter, or non-mutation manifest was altered:
//!   1. Re-canonicalizes each `findings[i]` via RFC 8785 JCS rules and recomputes
//!      `LeafHash = SHA256(0x00 || canonical_finding_bytes)`.
//!   2. Walks every `MerkleInclusionRecord.inclusion_proof` (`SHA256(0x01 || L || R)`)
//!      and verifies convergence to `merkle_envelope.merkle_root_hex`, plus rebuilds the
//!      entire RFC 6962 tree root from scratch.
//!   3. Verifies `NonMutationAttestation` (`target_mutated == false`, `pre == post`,
//!      and recomputes the canonical SHA-256 manifest digest over `tracked_artifacts`).

use std::fs;
use std::path::{Path, PathBuf};

use fsr_clone_cluster_audit::json_parser::{
    json_as_array, json_as_i64, json_as_str, json_as_u64, json_get, parse_json_str,
};
use fsr_deep_audit::crypto::{hex_digests_equal, hex_encode};
use fsr_deep_audit::schema::JsonValue;

use crate::merkle_evidence::{
    canonical_json_bytes, compute_rfc6962_leaf_hash, compute_rfc6962_merkle_root,
    verify_inclusion_proof, MerklePathStep, SiblingPosition,
};
use crate::readonly_attestation::{compute_manifest_state_digest, ArtifactStateRecord};

/// Structured output of standalone `--verify-bundle <forensic_bundle.json>` verification.
#[derive(Debug, Clone)]
pub struct BundleVerificationReport {
    pub bundle_source: String,
    pub bundle_authentic: bool,
    pub schema_valid: bool,
    pub merkle_valid: bool,
    pub attestation_valid: bool,
    pub verified_findings_count: usize,
    pub verified_proofs_count: usize,
    pub verified_artifacts_count: usize,
    pub expected_merkle_root_hex: String,
    pub recomputed_merkle_root_hex: String,
    pub pre_state_digest_hex: String,
    pub post_state_digest_hex: String,
    pub recomputed_manifest_digest_hex: String,
    pub errors: Vec<String>,
}

impl BundleVerificationReport {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("schema_version".to_string(), JsonValue::str("1.0.0")),
            (
                "verifier".to_string(),
                JsonValue::str("fsr-forensic-verdict::bundle_verifier"),
            ),
            (
                "bundle_source".to_string(),
                JsonValue::str(&self.bundle_source),
            ),
            (
                "bundle_authentic".to_string(),
                JsonValue::Bool(self.bundle_authentic),
            ),
            (
                "schema_valid".to_string(),
                JsonValue::Bool(self.schema_valid),
            ),
            (
                "merkle_valid".to_string(),
                JsonValue::Bool(self.merkle_valid),
            ),
            (
                "attestation_valid".to_string(),
                JsonValue::Bool(self.attestation_valid),
            ),
            (
                "verified_findings_count".to_string(),
                JsonValue::Uint(self.verified_findings_count as u64),
            ),
            (
                "verified_proofs_count".to_string(),
                JsonValue::Uint(self.verified_proofs_count as u64),
            ),
            (
                "verified_artifacts_count".to_string(),
                JsonValue::Uint(self.verified_artifacts_count as u64),
            ),
            (
                "expected_merkle_root_hex".to_string(),
                JsonValue::str(&self.expected_merkle_root_hex),
            ),
            (
                "recomputed_merkle_root_hex".to_string(),
                JsonValue::str(&self.recomputed_merkle_root_hex),
            ),
            (
                "pre_state_digest_hex".to_string(),
                JsonValue::str(&self.pre_state_digest_hex),
            ),
            (
                "post_state_digest_hex".to_string(),
                JsonValue::str(&self.post_state_digest_hex),
            ),
            (
                "recomputed_manifest_digest_hex".to_string(),
                JsonValue::str(&self.recomputed_manifest_digest_hex),
            ),
            (
                "errors".to_string(),
                JsonValue::Array(self.errors.iter().map(JsonValue::str).collect()),
            ),
        ])
    }
}

/// Reads `<forensic_bundle.json>` from disk and verifies all cryptographic invariants.
pub fn verify_forensic_bundle_file(bundle_path: &Path) -> BundleVerificationReport {
    let source = bundle_path.to_string_lossy().into_owned();
    match fs::read_to_string(bundle_path) {
        Ok(content) => verify_forensic_bundle_str_labeled(&source, &content),
        Err(err) => BundleVerificationReport {
            bundle_source: source,
            bundle_authentic: false,
            schema_valid: false,
            merkle_valid: false,
            attestation_valid: false,
            verified_findings_count: 0,
            verified_proofs_count: 0,
            verified_artifacts_count: 0,
            expected_merkle_root_hex: String::new(),
            recomputed_merkle_root_hex: String::new(),
            pre_state_digest_hex: String::new(),
            post_state_digest_hex: String::new(),
            recomputed_manifest_digest_hex: String::new(),
            errors: vec![format!("failed to read bundle file: {}", err)],
        },
    }
}

/// Verifies an in-memory JSON/NDJSON forensic bundle string without touching the filesystem.
pub fn verify_forensic_bundle_str(raw_json: &str) -> BundleVerificationReport {
    verify_forensic_bundle_str_labeled("<in-memory-bundle>", raw_json)
}

fn verify_forensic_bundle_str_labeled(source: &str, raw_json: &str) -> BundleVerificationReport {
    let mut errors: Vec<String> = Vec::new();

    let doc = match parse_json_str(raw_json.trim()) {
        Ok(val) => val,
        Err(e) => {
            return BundleVerificationReport {
                bundle_source: source.to_string(),
                bundle_authentic: false,
                schema_valid: false,
                merkle_valid: false,
                attestation_valid: false,
                verified_findings_count: 0,
                verified_proofs_count: 0,
                verified_artifacts_count: 0,
                expected_merkle_root_hex: String::new(),
                recomputed_merkle_root_hex: String::new(),
                pre_state_digest_hex: String::new(),
                post_state_digest_hex: String::new(),
                recomputed_manifest_digest_hex: String::new(),
                errors: vec![format!("RFC 8259 JSON parse error: {}", e)],
            };
        }
    };

    let mut schema_valid = true;
    match json_get(&doc, "schema_version").and_then(json_as_str) {
        Some("1.0.0") => {}
        Some(other) => {
            schema_valid = false;
            errors.push(format!(
                "unsupported schema_version '{}', expected '1.0.0'",
                other
            ));
        }
        None => {
            schema_valid = false;
            errors.push("missing required top-level 'schema_version' field".to_string());
        }
    }

    let findings = match json_get(&doc, "findings").and_then(json_as_array) {
        Some(arr) => arr,
        None => {
            schema_valid = false;
            errors.push("missing or invalid top-level 'findings' array".to_string());
            &[]
        }
    };

    // Cross-check `verdict.total_findings` and `verdict.status` consistency against `findings`
    if let Some(verdict_obj) = json_get(&doc, "verdict") {
        if let Some(reported_total) = json_get(verdict_obj, "total_findings").and_then(json_as_u64)
        {
            if reported_total as usize != findings.len() {
                schema_valid = false;
                errors.push(format!(
                    "verdict.total_findings ({}) does not match findings.len() ({})",
                    reported_total,
                    findings.len()
                ));
            }
        } else {
            schema_valid = false;
            errors.push("missing verdict.total_findings".to_string());
        }

        if let Some(status_str) = json_get(verdict_obj, "status").and_then(json_as_str) {
            let has_crit = findings.iter().any(|f| {
                json_get(f, "severity")
                    .and_then(json_as_str)
                    .map(|s| s == "CRITICAL")
                    .unwrap_or(false)
            });
            if has_crit && status_str == "CLEAN" {
                schema_valid = false;
                errors.push(
                    "verdict.status claims 'CLEAN' despite CRITICAL findings in bundle".to_string(),
                );
            }
        }
    } else {
        schema_valid = false;
        errors.push("missing top-level 'verdict' object".to_string());
    }

    // ------------------------------------------------------------------------
    // 1. RFC 6962 Merkle Tree & Inclusion Proof Verification
    // ------------------------------------------------------------------------
    let mut merkle_valid = true;
    let mut expected_merkle_root_hex = String::new();
    let mut recomputed_merkle_root_hex = String::new();
    let mut verified_proofs_count = 0usize;

    if let Some(env_obj) = json_get(&doc, "merkle_envelope") {
        if json_get(env_obj, "leaf_domain_prefix").and_then(json_as_str) != Some("0x00")
            || json_get(env_obj, "node_domain_prefix").and_then(json_as_str) != Some("0x01")
        {
            merkle_valid = false;
            errors.push(
                "merkle_envelope domain prefixes do not match RFC 6962 (0x00 / 0x01)".to_string(),
            );
        }

        expected_merkle_root_hex = json_get(env_obj, "merkle_root_hex")
            .and_then(json_as_str)
            .unwrap_or("")
            .to_string();
        if expected_merkle_root_hex.len() != 64 {
            merkle_valid = false;
            errors.push("merkle_envelope.merkle_root_hex is missing or not 64 hex chars".to_string());
        }

        let declared_leaf_count = json_get(env_obj, "leaf_count")
            .and_then(json_as_u64)
            .unwrap_or(u64::MAX);
        if declared_leaf_count != findings.len() as u64 {
            merkle_valid = false;
            errors.push(format!(
                "merkle_envelope.leaf_count ({}) != findings.len() ({})",
                declared_leaf_count,
                findings.len()
            ));
        }

        let proofs = match json_get(env_obj, "proofs").and_then(json_as_array) {
            Some(arr) => arr,
            None => {
                merkle_valid = false;
                errors.push("merkle_envelope.proofs array is missing".to_string());
                &[]
            }
        };

        if proofs.len() != findings.len() {
            merkle_valid = false;
            errors.push(format!(
                "merkle_envelope.proofs.len() ({}) != findings.len() ({})",
                proofs.len(),
                findings.len()
            ));
        }

        let mut recomputed_leaves = Vec::with_capacity(findings.len());
        for (idx, finding_val) in findings.iter().enumerate() {
            let canonical_bytes = canonical_json_bytes(finding_val);
            let leaf_digest = compute_rfc6962_leaf_hash(&canonical_bytes);
            let leaf_hex = hex_encode(&leaf_digest);
            recomputed_leaves.push(leaf_digest);

            let finding_id = json_get(finding_val, "id")
                .and_then(json_as_str)
                .unwrap_or("<missing-id>");

            if let Some(proof_obj) = proofs.get(idx) {
                let proof_finding_id = json_get(proof_obj, "finding_id")
                    .and_then(json_as_str)
                    .unwrap_or("");
                if proof_finding_id != finding_id {
                    merkle_valid = false;
                    errors.push(format!(
                        "leaf {}: finding.id '{}' != proof.finding_id '{}'",
                        idx, finding_id, proof_finding_id
                    ));
                }

                if json_get(proof_obj, "leaf_index").and_then(json_as_u64) != Some(idx as u64) {
                    merkle_valid = false;
                    errors.push(format!(
                        "leaf {} ({}): proof.leaf_index mismatch",
                        idx, finding_id
                    ));
                }

                let recorded_leaf_hex = json_get(proof_obj, "leaf_hash_hex")
                    .and_then(json_as_str)
                    .unwrap_or("");
                if !hex_digests_equal(&leaf_hex, recorded_leaf_hex) {
                    merkle_valid = false;
                    errors.push(format!(
                        "leaf {} ({}): tampered finding content — recomputed leaf SHA-256 {} != recorded {}",
                        idx, finding_id, leaf_hex, recorded_leaf_hex
                    ));
                }

                match parse_proof_steps(proof_obj) {
                    Ok(steps) => {
                        if verify_inclusion_proof(
                            &canonical_bytes,
                            &steps,
                            &expected_merkle_root_hex,
                        ) {
                            verified_proofs_count += 1;
                        } else {
                            merkle_valid = false;
                            errors.push(format!(
                                "leaf {} ({}): RFC 6962 Merkle inclusion proof failed against root {}",
                                idx, finding_id, expected_merkle_root_hex
                            ));
                        }
                    }
                    Err(err_msg) => {
                        merkle_valid = false;
                        errors.push(format!("leaf {} ({}): {}", idx, finding_id, err_msg));
                    }
                }
            }
        }

        let full_tree_root = compute_rfc6962_merkle_root(&recomputed_leaves);
        recomputed_merkle_root_hex = hex_encode(&full_tree_root);
        if !hex_digests_equal(&recomputed_merkle_root_hex, &expected_merkle_root_hex) {
            merkle_valid = false;
            errors.push(format!(
                "full RFC 6962 Merkle root mismatch: recomputed {} != expected {}",
                recomputed_merkle_root_hex, expected_merkle_root_hex
            ));
        }
    } else {
        merkle_valid = false;
        errors.push("missing required top-level 'merkle_envelope' object".to_string());
    }

    // ------------------------------------------------------------------------
    // 2. Non-Mutation Attestation Verification
    // ------------------------------------------------------------------------
    let mut attestation_valid = true;
    let mut pre_state_digest_hex = String::new();
    let mut post_state_digest_hex = String::new();
    let mut recomputed_manifest_digest_hex = String::new();
    let mut verified_artifacts_count = 0usize;

    if let Some(att_obj) = json_get(&doc, "non_mutation_attestation") {
        let target_mutated = match json_get(att_obj, "target_mutated") {
            Some(JsonValue::Bool(b)) => *b,
            _ => {
                attestation_valid = false;
                errors.push("non_mutation_attestation.target_mutated missing or not bool".to_string());
                true
            }
        };
        if target_mutated {
            attestation_valid = false;
            errors.push(
                "non_mutation_attestation reports target_mutated == true (chain of custody broken)"
                    .to_string(),
            );
        }

        pre_state_digest_hex = json_get(att_obj, "pre_state_digest_hex")
            .and_then(json_as_str)
            .unwrap_or("")
            .to_string();
        post_state_digest_hex = json_get(att_obj, "post_state_digest_hex")
            .and_then(json_as_str)
            .unwrap_or("")
            .to_string();

        if pre_state_digest_hex.len() != 64 || post_state_digest_hex.len() != 64 {
            attestation_valid = false;
            errors.push("pre/post state digest hex strings missing or malformed".to_string());
        } else if !hex_digests_equal(&pre_state_digest_hex, &post_state_digest_hex) {
            attestation_valid = false;
            errors.push(format!(
                "pre_state_digest_hex ({}) != post_state_digest_hex ({})",
                pre_state_digest_hex, post_state_digest_hex
            ));
        }

        if let Some(muts) = json_get(att_obj, "mutations").and_then(json_as_array) {
            if !muts.is_empty() {
                attestation_valid = false;
                errors.push(format!(
                    "non_mutation_attestation contains {} recorded file mutations",
                    muts.len()
                ));
            }
        }

        let declared_art_count = json_get(att_obj, "verified_artifact_count")
            .and_then(json_as_u64)
            .unwrap_or(u64::MAX);

        match json_get(att_obj, "tracked_artifacts").and_then(json_as_array) {
            Some(art_arr) => {
                if declared_art_count != art_arr.len() as u64 {
                    attestation_valid = false;
                    errors.push(format!(
                        "verified_artifact_count ({}) != tracked_artifacts.len() ({})",
                        declared_art_count,
                        art_arr.len()
                    ));
                }
                let mut parsed_records = Vec::with_capacity(art_arr.len());
                for (i, item) in art_arr.iter().enumerate() {
                    match parse_artifact_record(item) {
                        Ok(rec) => parsed_records.push(rec),
                        Err(e) => {
                            attestation_valid = false;
                            errors.push(format!("tracked_artifacts[{}]: {}", i, e));
                        }
                    }
                }
                verified_artifacts_count = parsed_records.len();
                recomputed_manifest_digest_hex = compute_manifest_state_digest(&parsed_records);

                if !hex_digests_equal(&recomputed_manifest_digest_hex, &pre_state_digest_hex)
                    || !hex_digests_equal(&recomputed_manifest_digest_hex, &post_state_digest_hex)
                {
                    attestation_valid = false;
                    errors.push(format!(
                        "tracked_artifacts manifest SHA-256 ({}) does not match pre/post state digest ({})",
                        recomputed_manifest_digest_hex, pre_state_digest_hex
                    ));
                }
            }
            None => {
                attestation_valid = false;
                errors.push("non_mutation_attestation.tracked_artifacts array missing".to_string());
            }
        }
    } else {
        attestation_valid = false;
        errors.push("missing required top-level 'non_mutation_attestation' object".to_string());
    }

    let bundle_authentic = schema_valid && merkle_valid && attestation_valid && errors.is_empty();

    BundleVerificationReport {
        bundle_source: source.to_string(),
        bundle_authentic,
        schema_valid,
        merkle_valid,
        attestation_valid,
        verified_findings_count: findings.len(),
        verified_proofs_count,
        verified_artifacts_count,
        expected_merkle_root_hex,
        recomputed_merkle_root_hex,
        pre_state_digest_hex,
        post_state_digest_hex,
        recomputed_manifest_digest_hex,
        errors,
    }
}

fn parse_proof_steps(proof_obj: &JsonValue) -> Result<Vec<MerklePathStep>, String> {
    let arr = json_get(proof_obj, "inclusion_proof")
        .and_then(json_as_array)
        .ok_or_else(|| "missing inclusion_proof array".to_string())?;
    let mut steps = Vec::with_capacity(arr.len());
    for (idx, step_val) in arr.iter().enumerate() {
        let pos_str = json_get(step_val, "position")
            .and_then(json_as_str)
            .ok_or_else(|| format!("inclusion_proof[{}] missing position", idx))?;
        let position = SiblingPosition::from_str_label(pos_str)
            .ok_or_else(|| format!("inclusion_proof[{}] invalid position '{}'", idx, pos_str))?;
        let sibling_hash_hex = json_get(step_val, "sibling_hash_hex")
            .and_then(json_as_str)
            .ok_or_else(|| format!("inclusion_proof[{}] missing sibling_hash_hex", idx))?
            .to_string();
        steps.push(MerklePathStep {
            position,
            sibling_hash_hex,
        });
    }
    Ok(steps)
}

fn parse_artifact_record(val: &JsonValue) -> Result<ArtifactStateRecord, String> {
    let logical_path = json_get(val, "logical_path")
        .and_then(json_as_str)
        .ok_or_else(|| "missing logical_path".to_string())?
        .to_string();
    let size_bytes = json_get(val, "size_bytes")
        .and_then(json_as_u64)
        .ok_or_else(|| "missing size_bytes".to_string())?;
    let mtime_sec = json_get(val, "mtime_sec")
        .and_then(json_as_i64)
        .ok_or_else(|| "missing mtime_sec".to_string())?;
    let mtime_nsec = json_get(val, "mtime_nsec")
        .and_then(json_as_i64)
        .ok_or_else(|| "missing mtime_nsec".to_string())?;
    let ctime_sec = json_get(val, "ctime_sec")
        .and_then(json_as_i64)
        .ok_or_else(|| "missing ctime_sec".to_string())?;
    let ctime_nsec = json_get(val, "ctime_nsec")
        .and_then(json_as_i64)
        .ok_or_else(|| "missing ctime_nsec".to_string())?;
    let inode = json_get(val, "inode")
        .and_then(json_as_u64)
        .ok_or_else(|| "missing inode".to_string())?;
    let mode_u64 = json_get(val, "mode")
        .and_then(json_as_u64)
        .ok_or_else(|| "missing mode".to_string())?;
    let sha256_hex = json_get(val, "sha256_hex")
        .and_then(json_as_str)
        .ok_or_else(|| "missing sha256_hex".to_string())?
        .to_string();
    if sha256_hex.len() != 64 {
        return Err("sha256_hex is not 64 hex chars".to_string());
    }

    Ok(ArtifactStateRecord {
        logical_path: logical_path.clone(),
        physical_path: PathBuf::from(&logical_path),
        size_bytes,
        mtime_sec,
        mtime_nsec,
        ctime_sec,
        ctime_nsec,
        inode,
        mode: mode_u64 as u32,
        sha256_hex,
    })
}
