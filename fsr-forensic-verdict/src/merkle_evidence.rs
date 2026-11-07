//! Engine 1: RFC 6962 Section 2.1 Binary Merkle Tree & Inclusion Proof Engine.
//!
//! Seals every normalized [`Finding`] emitted across all 19 forensic engines into a
//! second-preimage-resistant RFC 6962 Certificate-Transparency-grade Binary Merkle Tree:
//!   - Canonical Finding Serialization: RFC 8785 JCS-style deterministic UTF-8 JSON bytes
//!     (recursively lexicographically sorted object keys, zero insignificant whitespace).
//!   - Leaf Hash:     `SHA256(0x00 || canonical_finding_bytes)`
//!   - Interior Hash: `SHA256(0x01 || left_hash || right_hash)`
//!   - Empty Tree:    `SHA256("")` (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`)
//!   - Odd Subtrees:  Largest power-of-two split `k < n` per RFC 6962 §2.1 (never duplicates
//!     odd leaves, preventing CVE-2012-2459 malleable leaf-count collisions).

use std::collections::BTreeMap;

use fsr_deep_audit::crypto::{hex_digests_equal, hex_encode, Sha256};
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue};

/// RFC 6962 §2.1 domain-separation prefix byte for leaf inputs.
pub const RFC6962_LEAF_PREFIX: u8 = 0x00;

/// RFC 6962 §2.1 domain-separation prefix byte for interior Merkle nodes.
pub const RFC6962_NODE_PREFIX: u8 = 0x01;

/// Relative position of a sibling node along an inclusion audit path from leaf to root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiblingPosition {
    /// Sibling sits on the left: `NodeHash = SHA256(0x01 || sibling || current)`.
    Left,
    /// Sibling sits on the right: `NodeHash = SHA256(0x01 || current || sibling)`.
    Right,
}

impl SiblingPosition {
    pub fn as_str(self) -> &'static str {
        match self {
            SiblingPosition::Left => "Left",
            SiblingPosition::Right => "Right",
        }
    }

    pub fn from_str_label(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("left") {
            Some(SiblingPosition::Left)
        } else if s.eq_ignore_ascii_case("right") {
            Some(SiblingPosition::Right)
        } else {
            None
        }
    }
}

/// One step along the RFC 6962 Merkle audit path (`PATH(m, D[n])`) from leaf to root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePathStep {
    pub position: SiblingPosition,
    pub sibling_hash_hex: String,
}

impl MerklePathStep {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("position".to_string(), JsonValue::str(self.position.as_str())),
            (
                "sibling_hash_hex".to_string(),
                JsonValue::str(&self.sibling_hash_hex),
            ),
        ])
    }
}

/// Sealed forensic finding carrying its deterministic `FSR-...` ID, canonical JSON
/// representation, RFC 6962 leaf digest, and leaf index.
#[derive(Debug, Clone)]
pub struct SealedFinding {
    pub id: String,
    pub leaf_index: usize,
    pub finding: Finding,
    pub finding_json: JsonValue,
    pub canonical_bytes: Vec<u8>,
    pub leaf_hash: [u8; 32],
    pub leaf_hash_hex: String,
}

/// Per-finding inclusion proof entry serialized inside `merkle_envelope.proofs`.
#[derive(Debug, Clone)]
pub struct MerkleInclusionRecord {
    pub finding_id: String,
    pub leaf_index: usize,
    pub canonical_byte_len: usize,
    pub leaf_hash_hex: String,
    pub inclusion_proof: Vec<MerklePathStep>,
}

impl MerkleInclusionRecord {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("finding_id".to_string(), JsonValue::str(&self.finding_id)),
            ("leaf_index".to_string(), JsonValue::Uint(self.leaf_index as u64)),
            (
                "canonical_byte_len".to_string(),
                JsonValue::Uint(self.canonical_byte_len as u64),
            ),
            (
                "leaf_hash_hex".to_string(),
                JsonValue::str(&self.leaf_hash_hex),
            ),
            (
                "inclusion_proof".to_string(),
                JsonValue::Array(self.inclusion_proof.iter().map(|s| s.to_json()).collect()),
            ),
        ])
    }
}

/// Complete RFC 6962 Binary Merkle Tree state & serializable cryptographic envelope.
#[derive(Debug, Clone)]
pub struct MerkleTreeEnvelope {
    pub rfc_standard: &'static str,
    pub hash_algorithm: &'static str,
    pub leaf_count: usize,
    pub tree_depth: usize,
    pub merkle_root: [u8; 32],
    pub merkle_root_hex: String,
    pub sealed_findings: Vec<SealedFinding>,
    pub proofs: Vec<MerkleInclusionRecord>,
}

impl MerkleTreeEnvelope {
    /// Builds a complete RFC 6962 Binary Merkle Tree and precomputes inclusion proofs
    /// for all findings after canonical sorting and deterministic `FSR-...` ID assignment.
    pub fn seal_findings(mut findings: Vec<Finding>) -> Self {
        sort_findings_canonically(&mut findings);

        let mut per_engine_seq: BTreeMap<EngineId, usize> = BTreeMap::new();
        let mut sealed_findings = Vec::with_capacity(findings.len());
        let mut leaf_hashes = Vec::with_capacity(findings.len());

        for (leaf_index, finding) in findings.into_iter().enumerate() {
            let seq = per_engine_seq.entry(finding.engine).or_insert(0);
            *seq += 1;
            let id = format!("FSR-{}-{:04}", finding.engine.prefix(), *seq);
            let finding_json = finding.to_json_with_id(&id);
            let canonical_bytes = canonical_json_bytes(&finding_json);
            let lh = compute_rfc6962_leaf_hash(&canonical_bytes);
            let lh_hex = hex_encode(&lh);
            leaf_hashes.push(lh);
            sealed_findings.push(SealedFinding {
                id,
                leaf_index,
                finding,
                finding_json,
                canonical_bytes,
                leaf_hash: lh,
                leaf_hash_hex: lh_hex,
            });
        }

        let merkle_root = compute_rfc6962_merkle_root(&leaf_hashes);
        let merkle_root_hex = hex_encode(&merkle_root);

        let mut max_depth = 0usize;
        let mut proofs = Vec::with_capacity(sealed_findings.len());
        for sf in &sealed_findings {
            let path = generate_inclusion_proof_by_index(&leaf_hashes, sf.leaf_index)
                .unwrap_or_default();
            if path.len() > max_depth {
                max_depth = path.len();
            }
            proofs.push(MerkleInclusionRecord {
                finding_id: sf.id.clone(),
                leaf_index: sf.leaf_index,
                canonical_byte_len: sf.canonical_bytes.len(),
                leaf_hash_hex: sf.leaf_hash_hex.clone(),
                inclusion_proof: path,
            });
        }

        Self {
            rfc_standard: "RFC 6962 Section 2.1",
            hash_algorithm: "SHA-256",
            leaf_count: sealed_findings.len(),
            tree_depth: max_depth,
            merkle_root,
            merkle_root_hex,
            sealed_findings,
            proofs,
        }
    }

    /// Generates an RFC 6962 Merkle inclusion proof (`PATH(m, D[n])`) for any `finding_id`.
    pub fn generate_inclusion_proof(&self, finding_id: &str) -> Option<Vec<MerklePathStep>> {
        let leaf_hashes: Vec<[u8; 32]> = self
            .sealed_findings
            .iter()
            .map(|sf| sf.leaf_hash)
            .collect();
        let target = self
            .sealed_findings
            .iter()
            .find(|sf| sf.id == finding_id)?;
        generate_inclusion_proof_by_index(&leaf_hashes, target.leaf_index)
    }

    /// Looks up the canonical serialized finding bytes for a given `finding_id`.
    pub fn canonical_bytes_for_finding(&self, finding_id: &str) -> Option<&[u8]> {
        self.sealed_findings
            .iter()
            .find(|sf| sf.id == finding_id)
            .map(|sf| sf.canonical_bytes.as_slice())
    }

    /// Serializes the cryptographic envelope into the canonical JSON schema.
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            (
                "rfc_standard".to_string(),
                JsonValue::str(self.rfc_standard),
            ),
            (
                "hash_algorithm".to_string(),
                JsonValue::str(self.hash_algorithm),
            ),
            ("leaf_domain_prefix".to_string(), JsonValue::str("0x00")),
            ("node_domain_prefix".to_string(), JsonValue::str("0x01")),
            (
                "leaf_count".to_string(),
                JsonValue::Uint(self.leaf_count as u64),
            ),
            (
                "tree_depth".to_string(),
                JsonValue::Uint(self.tree_depth as u64),
            ),
            (
                "merkle_root_hex".to_string(),
                JsonValue::str(&self.merkle_root_hex),
            ),
            (
                "proofs".to_string(),
                JsonValue::Array(self.proofs.iter().map(|p| p.to_json()).collect()),
            ),
        ])
    }
}

/// Sorts findings in the exact deterministic order required across the entire workspace.
pub fn sort_findings_canonically(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.engine.cmp(&b.engine))
            .then_with(|| a.code.cmp(&b.code))
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| a.summary.cmp(&b.summary))
    });
}

/// Recursively normalizes any [`JsonValue`] into lexicographically sorted `MapObject`s
/// so canonical byte serialization is invariant to pretty-printing or parser key order.
pub fn canonicalize_json_value(val: &JsonValue) -> JsonValue {
    match val {
        JsonValue::Null => JsonValue::Null,
        JsonValue::Bool(b) => JsonValue::Bool(*b),
        JsonValue::Int(i) => JsonValue::Int(*i),
        JsonValue::Uint(u) => JsonValue::Uint(*u),
        JsonValue::Str(s) => JsonValue::Str(s.clone()),
        JsonValue::Array(items) => {
            JsonValue::Array(items.iter().map(canonicalize_json_value).collect())
        }
        JsonValue::OrderedObject(entries) => {
            let mut map = BTreeMap::new();
            for (k, v) in entries {
                map.insert(k.clone(), canonicalize_json_value(v));
            }
            JsonValue::MapObject(map)
        }
        JsonValue::MapObject(entries) => {
            let mut map = BTreeMap::new();
            for (k, v) in entries {
                map.insert(k.clone(), canonicalize_json_value(v));
            }
            JsonValue::MapObject(map)
        }
    }
}

/// Produces deterministic RFC 8785 JCS-compatible compact UTF-8 JSON bytes for a [`JsonValue`].
pub fn canonical_json_bytes(val: &JsonValue) -> Vec<u8> {
    canonicalize_json_value(val)
        .to_json_string(false)
        .into_bytes()
}

/// Computes RFC 6962 §2.1 Leaf Hash: `SHA256(0x00 || canonical_finding_bytes)`.
pub fn compute_rfc6962_leaf_hash(canonical_finding_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[RFC6962_LEAF_PREFIX]);
    hasher.update(canonical_finding_bytes);
    hasher.finalize()
}

/// Computes RFC 6962 §2.1 Interior Node Hash: `SHA256(0x01 || left_hash || right_hash)`.
pub fn compute_rfc6962_node_hash(left_hash: &[u8; 32], right_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[RFC6962_NODE_PREFIX]);
    hasher.update(left_hash);
    hasher.update(right_hash);
    hasher.finalize()
}

/// Largest power of two strictly smaller than `n` (`k < n <= 2k`), as defined in RFC 6962 §2.1.
#[inline]
pub fn largest_power_of_two_less_than(n: usize) -> usize {
    debug_assert!(n > 1);
    let prev = n - 1;
    1usize << (usize::BITS - 1 - prev.leading_zeros())
}

/// Computes the RFC 6962 §2.1 Merkle Tree Hash (`MTH(D[n])`) from pre-hashed leaves.
pub fn compute_rfc6962_merkle_root(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    match leaf_hashes.len() {
        0 => Sha256::new().finalize(),
        1 => leaf_hashes[0],
        n => {
            let k = largest_power_of_two_less_than(n);
            let left = compute_rfc6962_merkle_root(&leaf_hashes[..k]);
            let right = compute_rfc6962_merkle_root(&leaf_hashes[k..]);
            compute_rfc6962_node_hash(&left, &right)
        }
    }
}

/// Generates the RFC 6962 §2.1.1 audit path (`PATH(m, D[n])`) ordered from leaf to root.
pub fn generate_inclusion_proof_by_index(
    leaf_hashes: &[[u8; 32]],
    target_index: usize,
) -> Option<Vec<MerklePathStep>> {
    let n = leaf_hashes.len();
    if target_index >= n {
        return None;
    }
    if n == 1 {
        return Some(Vec::new());
    }

    let k = largest_power_of_two_less_than(n);
    if target_index < k {
        let mut path = generate_inclusion_proof_by_index(&leaf_hashes[..k], target_index)?;
        let right_subroot = compute_rfc6962_merkle_root(&leaf_hashes[k..]);
        path.push(MerklePathStep {
            position: SiblingPosition::Right,
            sibling_hash_hex: hex_encode(&right_subroot),
        });
        Some(path)
    } else {
        let mut path = generate_inclusion_proof_by_index(&leaf_hashes[k..], target_index - k)?;
        let left_subroot = compute_rfc6962_merkle_root(&leaf_hashes[..k]);
        path.push(MerklePathStep {
            position: SiblingPosition::Left,
            sibling_hash_hex: hex_encode(&left_subroot),
        });
        Some(path)
    }
}

/// Standalone convenience wrapper returning the inclusion proof for `finding_id` inside `envelope`.
pub fn generate_inclusion_proof(
    envelope: &MerkleTreeEnvelope,
    finding_id: &str,
) -> Option<Vec<MerklePathStep>> {
    envelope.generate_inclusion_proof(finding_id)
}

/// Verifies an RFC 6962 Merkle inclusion proof from raw canonical finding bytes up to
/// `expected_merkle_root_hex`. Rejects malformed hex siblings, second-preimage node swaps,
/// single-bit finding mutations, and leaf-count > 1 empty-proof bypasses when root != leaf.
pub fn verify_inclusion_proof(
    canonical_finding_bytes: &[u8],
    proof: &[MerklePathStep],
    expected_merkle_root_hex: &str,
) -> bool {
    if expected_merkle_root_hex.len() != 64 {
        return false;
    }
    let mut current = compute_rfc6962_leaf_hash(canonical_finding_bytes);
    for step in proof {
        let Some(sibling) = decode_hex_32(&step.sibling_hash_hex) else {
            return false;
        };
        current = match step.position {
            SiblingPosition::Left => compute_rfc6962_node_hash(&sibling, &current),
            SiblingPosition::Right => compute_rfc6962_node_hash(&current, &sibling),
        };
    }
    let computed_hex = hex_encode(&current);
    hex_digests_equal(&computed_hex, expected_merkle_root_hex)
}

/// Decodes an exact 64-character hexadecimal string into a 32-byte digest.
pub fn decode_hex_32(hex_str: &str) -> Option<[u8; 32]> {
    if hex_str.len() != 64 {
        return None;
    }
    let bytes = hex_str.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsr_deep_audit::schema::Severity;

    #[test]
    fn test_rfc6962_empty_single_odd_even_and_tamper_resistance() {
        // 0. Empty tree must equal SHA-256("")
        let empty_env = MerkleTreeEnvelope::seal_findings(Vec::new());
        assert_eq!(
            empty_env.merkle_root_hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(empty_env.leaf_count, 0);

        // 1. Single-leaf tree: root == SHA256(0x00 || canonical_bytes), proof is empty
        let f1 = Finding::new(
            EngineId::HwIntegrity,
            "CRITICAL_HW_SPOOF_HOOK",
            Severity::Critical,
            "/sys/class/dmi/id/product_uuid",
            "UUID spoofed via LD_PRELOAD",
        );
        let one_env = MerkleTreeEnvelope::seal_findings(vec![f1.clone()]);
        assert_eq!(one_env.leaf_count, 1);
        let proof0 = generate_inclusion_proof(&one_env, "FSR-HW-0001").unwrap();
        assert!(proof0.is_empty());
        assert!(verify_inclusion_proof(
            one_env.canonical_bytes_for_finding("FSR-HW-0001").unwrap(),
            &proof0,
            &one_env.merkle_root_hex
        ));

        // 2. Odd leaf counts (N = 5 and N = 7) verify every leaf & reject single-byte edits
        for count in [2usize, 3, 5, 7, 9] {
            let mut list = Vec::new();
            for idx in 0..count {
                list.push(
                    Finding::new(
                        EngineId::ConnectorSkimmerAudit,
                        format!("CODE_{}", idx),
                        Severity::Critical,
                        format!("/opt/cyops/conn_{}.py", idx),
                        format!("Summary {}", idx),
                    )
                    .with_evidence("index", JsonValue::Uint(idx as u64)),
                );
            }
            let env = MerkleTreeEnvelope::seal_findings(list);
            assert_eq!(env.leaf_count, count);

            for sf in &env.sealed_findings {
                let proof = generate_inclusion_proof(&env, &sf.id).unwrap();
                assert!(verify_inclusion_proof(
                    &sf.canonical_bytes,
                    &proof,
                    &env.merkle_root_hex
                ));

                // Flip 1 bit in canonical bytes -> must fail verification
                let mut mutated = sf.canonical_bytes.clone();
                let mid = mutated.len() / 2;
                mutated[mid] ^= 0x01;
                assert!(!verify_inclusion_proof(
                    &mutated,
                    &proof,
                    &env.merkle_root_hex
                ));

                // Flip sibling position Left <-> Right -> must fail verification
                if !proof.is_empty() {
                    let mut flipped_proof = proof.clone();
                    flipped_proof[0].position = match flipped_proof[0].position {
                        SiblingPosition::Left => SiblingPosition::Right,
                        SiblingPosition::Right => SiblingPosition::Left,
                    };
                    assert!(!verify_inclusion_proof(
                        &sf.canonical_bytes,
                        &flipped_proof,
                        &env.merkle_root_hex
                    ));
                }
            }
        }
    }
}
