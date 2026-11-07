//! Module 3: Cracker Group & Automated Crack-Kit Threat Attribution Engine (`cracker_attribution`).
//!
//! Synthesizes a deterministic **Crack-Kit DNA** behavioral and binary signature
//! (`CKIT-SHA256-<32HEX>`) that remains invariant across independent OS/PostgreSQL
//! installations (`different pg_control system_identifier`, `different machine-id`,
//! `different random X.509 serials & wall-clock timestamps`) when compromised by the
//! same automated crack script or third-party integrator toolkit:
//!   a) **Binary Patch Idiom:** Exact x86_64 instruction stub in `libssl.so.3` and
//!      `pam_unix.so` (`CET_ENDBR64_MOV_EAX_1_RET` vs `CET_ENDBR64_XOR_EAX_EAX_RET` vs
//!      `RAW_MOV_EAX_0_RET` vs `RAW_MOV_EAX_1_RET`),
//!   b) **Rogue CA Generation Profile:** Validity window in days (`3650d` vs `36500d`),
//!      serial number byte-length/entropy class, and X.509 ASN.1 RDN OID sequence,
//!   c) **Bytecode & Skimmer Lexical Profile:** PEP 552 `.pyc` magic/bitfield, `return True`
//!      opcode stub & timestamp alignment cohort (`hour_aligned_3600`, `tz_quarter_900`,
//!      `live_compile_unaligned`), plus SOAR connector skimmer sink & function naming shape.
//!
//! When two or more distinct appliances share the same `crack_kit_signature_id` (even with
//! completely distinct `pg_control` IDs), emits `CRITICAL_SAME_CRACKER_TOOLKIT_ATTRIBUTION`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fsr_clone_cluster_audit::birthmark_extractor::{
    join_rooted, run_birthmark_extractor, DeviceBirthmarks,
};
use fsr_clone_cluster_audit::json_parser::{
    json_as_array, json_as_str, json_get, json_get_path, parse_json_or_ndjson_records,
};
use fsr_deep_audit::crypto::{hex_digests_equal, sha256_hex};
use fsr_deep_audit::elf_vma_diff::{parse_elf64_bytes, Elf64Info, Elf64Section};
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};
use fsr_net_crypto_audit::asn1_x509::{extract_pem_certificates, parse_x509_der, X509CertInfo};
use fsr_net_crypto_audit::ca_trust_audit::KNOWN_FORTINET_FACTORY_CA_SPKI_SHA256;

use crate::ova_stream_inspector::{inspect_ova_file, OvaInspectionOutcome};
use crate::vmdk_carver::{
    classify_skimmer_snippet_signature, classify_x86_64_patch_idiom, extract_x509_dna_metadata,
};

const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const PT_LOAD: u32 = 1;

const TARGET_ATTRIBUTION_SYMBOLS: &[(&str, &str)] = &[
    ("libssl", "SSL_get_verify_result"),
    ("libssl", "X509_verify_cert"),
    ("libssl", "EVP_VerifyFinal"),
    ("libssl", "EVP_DigestVerifyFinal"),
    ("libssl", "X509_verify"),
    ("libssl", "RSA_verify"),
    ("pam_unix", "pam_sm_authenticate"),
    ("pam_unix", "pam_sm_acct_mgmt"),
];

/// Synthesized behavioral & binary Crack-Kit DNA profile for a single appliance or OVA image.
#[derive(Debug, Clone, Default)]
pub struct CrackKitDnaProfile {
    pub binary_patch_idioms: Vec<String>,
    pub rogue_ca_profiles: Vec<String>,
    pub bytecode_and_skimmer_profiles: Vec<String>,
    pub observed_timezone_hint: Option<String>,
    pub canonical_dna_descriptor: Option<String>,
    pub crack_kit_full_sha256: Option<String>,
    pub crack_kit_signature_id: Option<String>,
}

impl CrackKitDnaProfile {
    /// Finalizes sorting/deduplication and computes deterministic `CKIT-SHA256-<32HEX>`
    /// whenever at least one cracking trait vector is non-empty.
    pub fn seal_signature(&mut self) {
        self.binary_patch_idioms.sort();
        self.binary_patch_idioms.dedup();
        self.rogue_ca_profiles.sort();
        self.rogue_ca_profiles.dedup();
        self.bytecode_and_skimmer_profiles.sort();
        self.bytecode_and_skimmer_profiles.dedup();

        if self.binary_patch_idioms.is_empty()
            && self.rogue_ca_profiles.is_empty()
            && self.bytecode_and_skimmer_profiles.is_empty()
        {
            self.canonical_dna_descriptor = None;
            self.crack_kit_full_sha256 = None;
            self.crack_kit_signature_id = None;
            return;
        }

        let descriptor = format!(
            "fsr-crack-kit-dna:v1|patch=[{}]|ca=[{}]|pyc_skimmer=[{}]",
            self.binary_patch_idioms.join(";"),
            self.rogue_ca_profiles.join(";"),
            self.bytecode_and_skimmer_profiles.join(";")
        );
        let full_hex = sha256_hex(descriptor.as_bytes());
        let sig_id = format!("CKIT-SHA256-{}", full_hex[..32].to_ascii_uppercase());

        self.canonical_dna_descriptor = Some(descriptor);
        self.crack_kit_full_sha256 = Some(full_hex);
        self.crack_kit_signature_id = Some(sig_id);
    }

    pub fn active_vector_count(&self) -> usize {
        let mut n = 0;
        if !self.binary_patch_idioms.is_empty() {
            n += 1;
        }
        if !self.rogue_ca_profiles.is_empty() {
            n += 1;
        }
        if !self.bytecode_and_skimmer_profiles.is_empty() {
            n += 1;
        }
        n
    }

    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            (
                "crack_kit_signature_id".to_string(),
                self.crack_kit_signature_id
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "crack_kit_full_sha256".to_string(),
                self.crack_kit_full_sha256
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "active_dna_vectors".to_string(),
                JsonValue::Uint(self.active_vector_count() as u64),
            ),
            (
                "binary_patch_idioms".to_string(),
                JsonValue::Array(
                    self.binary_patch_idioms
                        .iter()
                        .map(JsonValue::str)
                        .collect(),
                ),
            ),
            (
                "rogue_ca_profiles".to_string(),
                JsonValue::Array(self.rogue_ca_profiles.iter().map(JsonValue::str).collect()),
            ),
            (
                "bytecode_and_skimmer_profiles".to_string(),
                JsonValue::Array(
                    self.bytecode_and_skimmer_profiles
                        .iter()
                        .map(JsonValue::str)
                        .collect(),
                ),
            ),
            (
                "observed_timezone_hint".to_string(),
                self.observed_timezone_hint
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "canonical_dna_descriptor".to_string(),
                self.canonical_dna_descriptor
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
        ])
    }
}

/// Attribution record for a single appliance / OVA image participating in correlation.
#[derive(Debug, Clone)]
pub struct NodeAttributionRecord {
    pub source_label: String,
    pub hostname: String,
    pub org_label: Option<String>,
    pub pg_system_identifiers: Vec<String>,
    pub filesystem_uuids: Vec<String>,
    pub dna: CrackKitDnaProfile,
}

impl NodeAttributionRecord {
    pub fn distinct_node_key(&self) -> String {
        if !self.pg_system_identifiers.is_empty() {
            return format!(
                "pg:{}|host:{}|org:{}",
                self.pg_system_identifiers.join(","),
                self.hostname.to_ascii_lowercase(),
                self.org_label
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
            );
        }
        format!(
            "org:{}|host:{}|src:{}",
            self.org_label
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase(),
            self.hostname.to_ascii_lowercase(),
            self.source_label
        )
    }

    pub fn display_descriptor(&self) -> String {
        let org = self.org_label.as_deref().unwrap_or("unspecified-org");
        let pg = if self.pg_system_identifiers.is_empty() {
            "none".to_string()
        } else {
            self.pg_system_identifiers.join(",")
        };
        format!(
            "{} [org={}, pg_id={}, src={}]",
            self.hostname, org, pg, self.source_label
        )
    }

    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("source_label".to_string(), JsonValue::str(&self.source_label)),
            ("hostname".to_string(), JsonValue::str(&self.hostname)),
            (
                "org_label".to_string(),
                self.org_label
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "pg_system_identifiers".to_string(),
                JsonValue::Array(
                    self.pg_system_identifiers
                        .iter()
                        .map(JsonValue::str)
                        .collect(),
                ),
            ),
            (
                "filesystem_uuids".to_string(),
                JsonValue::Array(self.filesystem_uuids.iter().map(JsonValue::str).collect()),
            ),
            ("dna_profile".to_string(), self.dna.to_json()),
        ])
    }
}

/// Output of Module 3 (`cracker_attribution`).
#[derive(Debug, Clone)]
pub struct CrackerAttributionResult {
    pub local_node: NodeAttributionRecord,
    pub peer_nodes_evaluated: usize,
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Synthesizes Crack-Kit DNA from `--root` (if `audit_root`) and/or `--ova` (`ova_outcome`),
/// and correlates against any peer JSON/OVA/root targets in `cluster_input_path`.
pub fn run_cracker_attribution_engine(
    root_path: Option<&Path>,
    local_birthmarks: Option<&DeviceBirthmarks>,
    ova_outcome: Option<&OvaInspectionOutcome>,
    org_label: Option<&str>,
    cluster_input_path: Option<&Path>,
    extra_fortinet_spkis: &[String],
) -> CrackerAttributionResult {
    let mut dna = CrackKitDnaProfile::default();
    let mut pg_ids: Vec<String> = Vec::new();
    let mut fs_uuids: Vec<String> = Vec::new();
    let mut hostname = "unknown-appliance".to_string();
    let mut source_label = "local-audit".to_string();

    // 1. Harvest traits from mounted `--root` filesystem when supplied
    if let Some(root) = root_path {
        source_label = root.to_string_lossy().into_owned();
        let owned_bm;
        let bm_ref = if let Some(b) = local_birthmarks {
            b
        } else {
            owned_bm = run_birthmark_extractor(root).birthmarks;
            &owned_bm
        };
        if !bm_ref.hostname.is_empty() && bm_ref.hostname != "unknown-host" {
            hostname = bm_ref.hostname.clone();
        }
        for pg in &bm_ref.pg_controls {
            let s = pg.system_identifier.to_string();
            if !pg_ids.contains(&s) {
                pg_ids.push(s);
            }
        }
        for sb in &bm_ref.superblocks {
            if !sb.uuid.is_empty() && !fs_uuids.contains(&sb.uuid) {
                fs_uuids.push(sb.uuid.clone());
            }
        }

        extract_root_binary_patch_idioms(root, &mut dna);
        extract_root_rogue_ca_profiles(root, extra_fortinet_spkis, &mut dna);
        extract_root_pyc_and_skimmer_profiles(root, &mut dna);
    }

    // 2. Harvest traits from zero-mount `.ova` / `.vmdk` inspection when supplied
    if let Some(ova) = ova_outcome {
        source_label = ova.ova_label.clone();
        if let Some(hw) = &ova.ovf_hardware {
            if hostname == "unknown-appliance" {
                if let Some(vs_name) = &hw.virtual_system_name {
                    hostname = vs_name.clone();
                } else if let Some(vs_id) = &hw.virtual_system_id {
                    hostname = vs_id.clone();
                }
            }
        }

        for disk in &ova.disk_carve_reports {
            for pg in &disk.pg_controls {
                let s = pg.birthmark.system_identifier.to_string();
                if !pg_ids.contains(&s) {
                    pg_ids.push(s);
                }
            }
            for sb in &disk.superblocks {
                if !sb.birthmark.uuid.is_empty() && !fs_uuids.contains(&sb.birthmark.uuid) {
                    fs_uuids.push(sb.birthmark.uuid.clone());
                }
            }
            for ep in &disk.elf_patches {
                dna.binary_patch_idioms.push(format!(
                    "{}!{}=>{}",
                    ep.component_family, ep.symbol_name, ep.idiom_code
                ));
            }
            for cert in &disk.certificates {
                if cert.is_rogue_fortinet_ca {
                    dna.rogue_ca_profiles.push(format_rogue_ca_dna_token(
                        cert.validity_days,
                        &cert.serial_entropy_class,
                        &cert.issuer_rdn_order,
                        &cert.subject_rdn_order,
                        &cert.sig_alg_oid,
                        cert.cert.subject_org.as_deref(),
                        cert.cert.subject_cn.as_deref(),
                    ));
                }
            }
            for pyc in &disk.pyc_stubs {
                let cohort = classify_pyc_mtime_cohort(pyc.source_mtime);
                dna.bytecode_and_skimmer_profiles.push(format!(
                    "pyc:magic={}|bf={}|stub={}|cohort={}",
                    pyc.magic_u16, pyc.pep552_bitfield, pyc.stub_idiom, cohort
                ));
            }
            for sk in &disk.skimmer_traits {
                dna.bytecode_and_skimmer_profiles
                    .push(format!("skimmer:{}", sk.pattern_signature));
            }
        }
    }

    dna.seal_signature();

    let local_node = NodeAttributionRecord {
        source_label,
        hostname,
        org_label: org_label.map(|s| s.to_string()),
        pg_system_identifiers: pg_ids,
        filesystem_uuids: fs_uuids,
        dna,
    };

    // 3. Load peer attribution records (`--cluster-input`) and run cross-appliance correlation
    let peer_nodes = match cluster_input_path {
        Some(p) => load_peer_attribution_records(p, extra_fortinet_spkis),
        None => Vec::new(),
    };

    let mut all_nodes = Vec::with_capacity(1 + peer_nodes.len());
    all_nodes.push(local_node.clone());
    all_nodes.extend(peer_nodes.iter().cloned());

    let (findings, cluster_matches_json) = correlate_cracker_kit_nodes(&all_nodes, &local_node);

    let summary = JsonValue::OrderedObject(vec![
        (
            "crack_kit_signature_id".to_string(),
            local_node
                .dna
                .crack_kit_signature_id
                .as_deref()
                .map(JsonValue::str)
                .unwrap_or(JsonValue::Null),
        ),
        ("local_node".to_string(), local_node.to_json()),
        (
            "peer_nodes_evaluated".to_string(),
            JsonValue::Uint(peer_nodes.len() as u64),
        ),
        (
            "attributed_toolkit_clusters".to_string(),
            JsonValue::Array(cluster_matches_json),
        ),
    ]);

    CrackerAttributionResult {
        local_node,
        peer_nodes_evaluated: peer_nodes.len(),
        summary,
        findings,
    }
}

/// Correlates a set of [`NodeAttributionRecord`] entries by `crack_kit_signature_id` (`CKIT-SHA256-...`).
pub fn correlate_cracker_kit_nodes(
    nodes: &[NodeAttributionRecord],
    local_primary: &NodeAttributionRecord,
) -> (Vec<Finding>, Vec<JsonValue>) {
    let mut findings = Vec::new();
    let mut cluster_json = Vec::new();

    // Single-node automated crack-kit synthesis indicator (when >= 2 DNA vectors are active)
    if let Some(sig_id) = &local_primary.dna.crack_kit_signature_id {
        if local_primary.dna.active_vector_count() >= 2 {
            findings.push(
                Finding::new(
                    EngineId::CrackerAttribution,
                    "HIGH_AUTOMATED_CRACK_KIT_DNA_SYNTHESIZED",
                    Severity::High,
                    &local_primary.source_label,
                    format!(
                        "Synthesized multi-vector automated Crack-Kit DNA signature `{}` across {} forensic trait families on `{}`",
                        sig_id,
                        local_primary.dna.active_vector_count(),
                        local_primary.hostname
                    ),
                )
                .with_evidence("crack_kit_signature_id", JsonValue::str(sig_id.as_str()))
                .with_evidence(
                    "crack_kit_full_sha256",
                    JsonValue::str(
                        local_primary
                            .dna
                            .crack_kit_full_sha256
                            .as_deref()
                            .unwrap_or(""),
                    ),
                )
                .with_evidence(
                    "binary_patch_idioms",
                    JsonValue::Array(
                        local_primary
                            .dna
                            .binary_patch_idioms
                            .iter()
                            .map(JsonValue::str)
                            .collect(),
                    ),
                )
                .with_evidence(
                    "rogue_ca_profiles",
                    JsonValue::Array(
                        local_primary
                            .dna
                            .rogue_ca_profiles
                            .iter()
                            .map(JsonValue::str)
                            .collect(),
                    ),
                )
                .with_evidence(
                    "bytecode_and_skimmer_profiles",
                    JsonValue::Array(
                        local_primary
                            .dna
                            .bytecode_and_skimmer_profiles
                            .iter()
                            .map(JsonValue::str)
                            .collect(),
                    ),
                ),
            );
        }
    }

    // Group distinct appliances by `crack_kit_signature_id`
    let mut by_sig: BTreeMap<String, Vec<&NodeAttributionRecord>> = BTreeMap::new();
    for node in nodes {
        let Some(sig_id) = &node.dna.crack_kit_signature_id else {
            continue;
        };
        let bucket = by_sig.entry(sig_id.clone()).or_default();
        let nk = node.distinct_node_key();
        if !bucket.iter().any(|existing| existing.distinct_node_key() == nk) {
            bucket.push(node);
        }
    }

    for (sig_id, group) in by_sig {
        if group.len() < 2 {
            continue;
        }
        let exemplar = group[0];
        let mut distinct_pg_ids: BTreeSet<String> = BTreeSet::new();
        let mut descriptors = Vec::new();
        for member in &group {
            descriptors.push(member.display_descriptor());
            for pg_id in &member.pg_system_identifiers {
                distinct_pg_ids.insert(pg_id.clone());
            }
        }
        let independent_fresh_installs = distinct_pg_ids.len() >= 2;
        let pg_list: Vec<String> = distinct_pg_ids.into_iter().collect();

        cluster_json.push(JsonValue::OrderedObject(vec![
            ("crack_kit_signature_id".to_string(), JsonValue::str(&sig_id)),
            (
                "matched_appliance_count".to_string(),
                JsonValue::Uint(group.len() as u64),
            ),
            (
                "independent_fresh_installs_proven".to_string(),
                JsonValue::Bool(independent_fresh_installs),
            ),
            (
                "distinct_pg_system_identifiers".to_string(),
                JsonValue::Array(pg_list.iter().map(JsonValue::str).collect()),
            ),
            (
                "matched_nodes".to_string(),
                JsonValue::Array(descriptors.iter().map(JsonValue::str).collect()),
            ),
        ]));

        findings.push(
            Finding::new(
                EngineId::CrackerAttribution,
                "CRITICAL_SAME_CRACKER_TOOLKIT_ATTRIBUTION",
                Severity::Critical,
                format!("crack_kit:{}", sig_id),
                format!(
                    "Mathematical Crack-Kit DNA match `{}` across {} distinct appliances (distinct PostgreSQL IDs={}): proves compromise by the exact same cracker toolkit / unauthorized integrator",
                    sig_id,
                    group.len(),
                    pg_list.len()
                ),
            )
            .with_evidence("crack_kit_signature_id", JsonValue::str(&sig_id))
            .with_evidence(
                "crack_kit_full_sha256",
                JsonValue::str(
                    exemplar
                        .dna
                        .crack_kit_full_sha256
                        .as_deref()
                        .unwrap_or(""),
                ),
            )
            .with_evidence(
                "matched_appliance_count",
                JsonValue::Uint(group.len() as u64),
            )
            .with_evidence(
                "independent_fresh_installs_proven",
                JsonValue::Bool(independent_fresh_installs),
            )
            .with_evidence(
                "distinct_pg_system_identifiers",
                JsonValue::Array(pg_list.iter().map(JsonValue::str).collect()),
            )
            .with_evidence(
                "matched_nodes",
                JsonValue::Array(descriptors.iter().map(JsonValue::str).collect()),
            )
            .with_evidence(
                "binary_patch_idioms",
                JsonValue::Array(
                    exemplar
                        .dna
                        .binary_patch_idioms
                        .iter()
                        .map(JsonValue::str)
                        .collect(),
                ),
            )
            .with_evidence(
                "rogue_ca_profiles",
                JsonValue::Array(
                    exemplar
                        .dna
                        .rogue_ca_profiles
                        .iter()
                        .map(JsonValue::str)
                        .collect(),
                ),
            )
            .with_evidence(
                "bytecode_and_skimmer_profiles",
                JsonValue::Array(
                    exemplar
                        .dna
                        .bytecode_and_skimmer_profiles
                        .iter()
                        .map(JsonValue::str)
                        .collect(),
                ),
            ),
        );
    }

    (findings, cluster_json)
}

// ============================================================================
// Root Filesystem Crack-Kit DNA Extractors
// ============================================================================

fn extract_root_binary_patch_idioms(root: &Path, dna: &mut CrackKitDnaProfile) {
    let mut candidate_libs: Vec<(&str, PathBuf)> = Vec::new();
    for rel_dir in ["usr/lib64", "lib64", "usr/lib/x86_64-linux-gnu"] {
        let dir = join_rooted(root, rel_dir);
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("libssl.so") || name.starts_with("libcrypto.so") {
                    candidate_libs.push(("libssl", entry.path()));
                }
            }
        }
    }
    for rel_pam in [
        "usr/lib64/security/pam_unix.so",
        "lib64/security/pam_unix.so",
        "lib/x86_64-linux-gnu/security/pam_unix.so",
    ] {
        let p = join_rooted(root, rel_pam);
        if p.is_file() {
            candidate_libs.push(("pam_unix", p));
        }
    }

    for (family, path) in candidate_libs {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(elf) = parse_elf64_bytes(&bytes) else {
            continue;
        };
        for sec in &elf.sections {
            if sec.sh_type != SHT_DYNSYM && sec.sh_type != SHT_SYMTAB {
                continue;
            }
            let Some(strtab_sec) = elf.sections.get(sec.sh_link as usize) else {
                continue;
            };
            let Some(strtab) = slice_section(&bytes, strtab_sec) else {
                continue;
            };
            let Some(symtab) = slice_section(&bytes, sec) else {
                continue;
            };
            let entsize = if sec.sh_entsize >= 24 {
                sec.sh_entsize as usize
            } else {
                24
            };
            let mut off = 0usize;
            while off + 24 <= symtab.len() {
                let ent = &symtab[off..off + 24];
                let st_name = u32::from_le_bytes([ent[0], ent[1], ent[2], ent[3]]) as usize;
                let st_shndx = u16::from_le_bytes([ent[6], ent[7]]);
                let st_value = u64::from_le_bytes([
                    ent[8], ent[9], ent[10], ent[11], ent[12], ent[13], ent[14], ent[15],
                ]);
                off += entsize;

                if st_shndx == 0 || st_value == 0 || st_name >= strtab.len() {
                    continue;
                }
                let sym_name = read_cstr(strtab, st_name);
                if !TARGET_ATTRIBUTION_SYMBOLS
                    .iter()
                    .any(|(fam, target_sym)| *fam == family && *target_sym == sym_name)
                {
                    continue;
                }
                let Some(f_off) = vaddr_to_offset(&elf, st_value, st_shndx) else {
                    continue;
                };
                let f_idx = f_off as usize;
                if f_idx + 10 > bytes.len() {
                    continue;
                }
                let end = (f_idx + 16).min(bytes.len());
                if let Some((idiom_code, _)) = classify_x86_64_patch_idiom(&bytes[f_idx..end]) {
                    dna.binary_patch_idioms
                        .push(format!("{}!{}=>{}", family, sym_name, idiom_code));
                }
            }
        }
    }
}

fn extract_root_rogue_ca_profiles(
    root: &Path,
    extra_fortinet_spkis: &[String],
    dna: &mut CrackKitDnaProfile,
) {
    let mut cert_files = Vec::new();
    for rel in [
        "etc/pki/ca-trust/source/anchors",
        "etc/pki/tls/certs",
        "etc/pki/ca-trust/extracted/pem",
        "usr/local/share/ca-certificates",
        "opt",
    ] {
        let base = join_rooted(root, rel);
        if base.exists() {
            collect_cert_files_bounded(&base, 7, &mut cert_files);
        }
    }

    let mut seen_cert_hashes = BTreeSet::new();
    for path in cert_files {
        let Ok(raw) = fs::read(&path) else {
            continue;
        };
        let mut ders = Vec::new();
        if let Ok(text) = std::str::from_utf8(&raw) {
            if text.contains("-----BEGIN") {
                ders = extract_pem_certificates(text);
            }
        }
        if ders.is_empty() && raw.starts_with(&[0x30, 0x82]) {
            ders.push(raw);
        }

        for der in ders {
            let Ok(cert) = parse_x509_der(&der) else {
                continue;
            };
            if !seen_cert_hashes.insert(cert.cert_sha256.clone()) {
                continue;
            }
            let is_factory = KNOWN_FORTINET_FACTORY_CA_SPKI_SHA256
                .iter()
                .any(|pin| hex_digests_equal(pin, &cert.spki_sha256))
                || extra_fortinet_spkis
                    .iter()
                    .any(|pin| hex_digests_equal(pin, &cert.spki_sha256));
            if is_factory {
                continue;
            }

            let is_rogue_ca = (cert.mentions_fortinet_identity()
                && (cert.basic_constraints_ca || cert.is_self_signed))
                || (cert.basic_constraints_ca
                    && cert.is_self_signed
                    && !looks_like_standard_webpki_root(&cert));

            if is_rogue_ca {
                let meta = extract_x509_dna_metadata(&der, &cert);
                dna.rogue_ca_profiles.push(format_rogue_ca_dna_token(
                    meta.validity_days,
                    &meta.serial_entropy_class,
                    &meta.issuer_rdn_order,
                    &meta.subject_rdn_order,
                    &meta.sig_alg_oid,
                    cert.subject_org.as_deref(),
                    cert.subject_cn.as_deref(),
                ));
            }
        }
    }
}

fn extract_root_pyc_and_skimmer_profiles(root: &Path, dna: &mut CrackKitDnaProfile) {
    // Capture optional timezone hint from `/etc/timezone` or `/etc/localtime` symlink
    let tz_file = join_rooted(root, "etc/timezone");
    if let Ok(tz) = fs::read_to_string(&tz_file) {
        let trimmed = tz.trim();
        if !trimmed.is_empty() {
            dna.observed_timezone_hint = Some(trimmed.to_string());
        }
    } else if let Ok(link_target) = fs::read_link(join_rooted(root, "etc/localtime")) {
        let s = link_target.to_string_lossy();
        if let Some((_, zone)) = s.split_once("zoneinfo/") {
            dna.observed_timezone_hint = Some(zone.to_string());
        }
    }

    let mut pyc_files = Vec::new();
    let mut py_files = Vec::new();
    let opt_dir = join_rooted(root, "opt");
    if opt_dir.is_dir() {
        collect_opt_code_files(&opt_dir, 9, &mut pyc_files, &mut py_files);
    }
    if join_rooted(root, "server/csdassrv.py").is_file()
        || join_rooted(root, "handlerworkers").is_dir()
    {
        collect_opt_code_files(root, 6, &mut pyc_files, &mut py_files);
    }

    for pyc_path in pyc_files {
        let Ok(bytes) = fs::read(&pyc_path) else {
            continue;
        };
        if bytes.len() < 24 || bytes[2] != 0x0d || bytes[3] != 0x0a {
            continue;
        }
        let magic_u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
        let bitfield = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mtime = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let body = &bytes[16..];

        let stub_opt = if (contains_subslice(body, &[151, 0, 100, 0, 83, 0])
            || contains_subslice(body, &[151, 0, 100, 1, 83, 0]))
            && body.contains(&b'T')
        {
            Some(format!("PY{}_RESUME_LOAD_TRUE_RET", magic_u16))
        } else if (contains_subslice(body, &[100, 0, 83, 0])
            || contains_subslice(body, &[100, 1, 83, 0]))
            && body.contains(&b'T')
        {
            Some(format!("PY{}_LOAD_TRUE_RET", magic_u16))
        } else {
            None
        };

        if let Some(stub_idiom) = stub_opt {
            let cohort = classify_pyc_mtime_cohort(mtime);
            dna.bytecode_and_skimmer_profiles.push(format!(
                "pyc:magic={}|bf={}|stub={}|cohort={}",
                magic_u16, bitfield, stub_idiom, cohort
            ));
        }
    }

    for py_path in py_files {
        let Ok(src) = fs::read_to_string(&py_path) else {
            continue;
        };
        if (src.contains("FakeLicenseManager")
            || src.contains("FSRVMPTM99999999")
            || src.contains("MOCK-HARDWARE-UUID-KEY"))
            && (src.contains("handlerworkers.license")
                || src.contains("RequestHandler._execute")
                || src.contains("_SC_LICENSE_PAYLOAD"))
        {
            dna.bytecode_and_skimmer_profiles.push(
                "skimmer:das_bypass:tornado_cython_shadow_FSRVMPTM99999999".to_string(),
            );
        }

        let p_str = py_path.to_string_lossy();
        if !p_str.contains("connectors") && !p_str.contains("cyops-workflow") {
            continue;
        }
        if let Some(sig) = classify_skimmer_snippet_signature(&src) {
            dna.bytecode_and_skimmer_profiles
                .push(format!("skimmer:{}", sig));
        }
    }
}

// ============================================================================
// Peer Telemetry Loader (`--cluster-input`: JSON/NDJSON bundles, `.ova`, or root dirs)
// ============================================================================

fn load_peer_attribution_records(
    input_path: &Path,
    extra_fortinet_spkis: &[String],
) -> Vec<NodeAttributionRecord> {
    let mut records = Vec::new();
    let mut files = Vec::new();
    if input_path.is_file() {
        files.push(input_path.to_path_buf());
    } else if input_path.is_dir() {
        if let Ok(entries) = fs::read_dir(input_path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    files.push(p);
                } else if p.is_dir() && join_rooted(&p, "etc").is_dir() {
                    // Peer unpacked appliance root directory inside `--cluster-input`
                    let org = p.file_name().map(|n| n.to_string_lossy().into_owned());
                    let sub = run_cracker_attribution_engine(
                        Some(&p),
                        None,
                        None,
                        org.as_deref(),
                        None,
                        extra_fortinet_spkis,
                    );
                    if sub.local_node.dna.crack_kit_signature_id.is_some() {
                        records.push(sub.local_node);
                    }
                }
            }
        }
    }
    files.sort();

    for file in files {
        let ext = file
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if ext == "ova" || ext == "vmdk" || ext == "qcow2" {
            if let Ok(ova_out) = inspect_ova_file(&file, extra_fortinet_spkis) {
                let org = file.file_stem().map(|n| n.to_string_lossy().into_owned());
                let sub = run_cracker_attribution_engine(
                    None,
                    None,
                    Some(&ova_out),
                    org.as_deref(),
                    None,
                    extra_fortinet_spkis,
                );
                if sub.local_node.dna.crack_kit_signature_id.is_some() {
                    records.push(sub.local_node);
                }
            }
            continue;
        }

        if ext == "json" || ext == "ndjson" || ext == "jsonl" {
            let Ok(raw_text) = fs::read_to_string(&file) else {
                continue;
            };
            let label = file.to_string_lossy().into_owned();
            if let Ok(docs) = parse_json_or_ndjson_records(&raw_text) {
                for doc in docs {
                    if let Some(peer) = parse_peer_json_attribution_record(&doc, &label) {
                        records.push(peer);
                    }
                }
            }
        }
    }

    records
}

fn parse_peer_json_attribution_record(
    doc: &JsonValue,
    fallback_label: &str,
) -> Option<NodeAttributionRecord> {
    // Support both `ForensicVerdictBundle` (`engines.cracker_attribution.local_node`) and
    // standalone `NodeAttributionRecord` / `fsr-ova-attribution` JSON outputs.
    let node_obj = json_get_path(doc, &["engines", "cracker_attribution", "local_node"])
        .or_else(|| json_get(doc, "local_node"))
        .unwrap_or(doc);

    let dna_obj = json_get(node_obj, "dna_profile")
        .or_else(|| json_get_path(doc, &["engines", "cracker_attribution"]))?;

    let mut dna = CrackKitDnaProfile {
        binary_patch_idioms: extract_str_vec(json_get(dna_obj, "binary_patch_idioms")),
        rogue_ca_profiles: extract_str_vec(json_get(dna_obj, "rogue_ca_profiles")),
        bytecode_and_skimmer_profiles: extract_str_vec(json_get(
            dna_obj,
            "bytecode_and_skimmer_profiles",
        )),
        observed_timezone_hint: json_get(dna_obj, "observed_timezone_hint")
            .and_then(json_as_str)
            .map(|s| s.to_string()),
        canonical_dna_descriptor: None,
        crack_kit_full_sha256: None,
        crack_kit_signature_id: json_get(dna_obj, "crack_kit_signature_id")
            .and_then(json_as_str)
            .map(|s| s.to_string()),
    };

    if !dna.binary_patch_idioms.is_empty()
        || !dna.rogue_ca_profiles.is_empty()
        || !dna.bytecode_and_skimmer_profiles.is_empty()
    {
        dna.seal_signature();
    }
    dna.crack_kit_signature_id.as_ref()?;

    let hostname = json_get(node_obj, "hostname")
        .and_then(json_as_str)
        .or_else(|| json_get_path(doc, &["scan_context", "hostname"]).and_then(json_as_str))
        .unwrap_or("peer-appliance")
        .to_string();

    let org_label = json_get(node_obj, "org_label")
        .and_then(json_as_str)
        .map(|s| s.to_string());

    let mut pg_ids = extract_str_vec(json_get(node_obj, "pg_system_identifiers"));
    if pg_ids.is_empty() {
        if let Some(arr) = json_get_path(doc, &["birthmarks", "pg_controls"]).and_then(json_as_array)
        {
            for item in arr {
                if let Some(id_str) = json_get(item, "system_identifier").and_then(json_as_str) {
                    pg_ids.push(id_str.to_string());
                }
            }
        }
    }

    let fs_uuids = extract_str_vec(json_get(node_obj, "filesystem_uuids"));

    Some(NodeAttributionRecord {
        source_label: json_get(node_obj, "source_label")
            .and_then(json_as_str)
            .unwrap_or(fallback_label)
            .to_string(),
        hostname,
        org_label,
        pg_system_identifiers: pg_ids,
        filesystem_uuids: fs_uuids,
        dna,
    })
}

fn extract_str_vec(val: Option<&JsonValue>) -> Vec<String> {
    let Some(arr) = val.and_then(json_as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(json_as_str)
        .map(|s| s.to_string())
        .collect()
}

// ============================================================================
// Normalization Helpers
// ============================================================================

pub fn format_rogue_ca_dna_token(
    validity_days: Option<i64>,
    serial_entropy_class: &str,
    issuer_rdn_order: &str,
    subject_rdn_order: &str,
    sig_alg_oid: &str,
    subject_org: Option<&str>,
    subject_cn: Option<&str>,
) -> String {
    let days_str = validity_days
        .map(|d| format!("{}d", d))
        .unwrap_or_else(|| "unknown_days".to_string());
    let org_norm = normalize_identity_template(subject_org.unwrap_or("none"));
    let cn_norm = normalize_identity_template(subject_cn.unwrap_or("none"));
    format!(
        "days={}|serial_cls={}|issuer_rdn={}|subj_rdn={}|sig={}|o={}|cn={}",
        days_str,
        serial_entropy_class,
        issuer_rdn_order,
        subject_rdn_order,
        sig_alg_oid,
        org_norm,
        cn_norm
    )
}

fn normalize_identity_template(raw: &str) -> String {
    let trimmed = raw.trim().to_ascii_lowercase();
    let mut out = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if matches!(ch, ' ' | '-' | '_' | '.') && !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

pub fn classify_pyc_mtime_cohort(mtime: u32) -> &'static str {
    if mtime == 0 {
        "zeroed_epoch"
    } else if mtime.is_multiple_of(86_400) {
        "day_aligned_86400"
    } else if mtime.is_multiple_of(3_600) {
        "hour_aligned_3600"
    } else if mtime.is_multiple_of(900) {
        "tz_quarter_900"
    } else {
        "live_compile_unaligned"
    }
}

fn looks_like_standard_webpki_root(cert: &X509CertInfo) -> bool {
    let hay = format!("{} {}", cert.subject_dn, cert.issuer_dn).to_ascii_lowercase();
    const WEBPKI_MARKERS: &[&str] = &[
        "digicert",
        "isrg root",
        "internet security research group",
        "let's encrypt",
        "sectigo",
        "comodo",
        "usertrust",
        "globalsign",
        "entrust",
        "godaddy",
        "verisign",
        "geotrust",
        "amazon",
        "google trust",
        "gts root",
        "microsoft",
        "cloudflare",
        "baltimore",
    ];
    WEBPKI_MARKERS.iter().any(|m| hay.contains(m))
}

fn collect_cert_files_bounded(dir: &Path, depth_left: usize, out: &mut Vec<PathBuf>) {
    if depth_left == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_cert_files_bounded(&p, depth_left - 1, out);
        } else if p.is_file() {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name.ends_with(".crt")
                || name.ends_with(".pem")
                || name.ends_with(".cer")
                || name.ends_with(".der")
            {
                out.push(p);
            }
        }
    }
}

fn collect_opt_code_files(
    dir: &Path,
    depth_left: usize,
    pyc_out: &mut Vec<PathBuf>,
    py_out: &mut Vec<PathBuf>,
) {
    if depth_left == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let dir_str = dir.to_string_lossy();
    let in_site_packages_root =
        dir_str.ends_with("/site-packages") || dir_str.ends_with("\\site-packages");
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            if in_site_packages_root {
                let dname = entry.file_name().to_string_lossy().into_owned();
                if dname == "__pycache__"
                    || dname == "tornado"
                    || dname == "fsr"
                    || dname.starts_with("cyops")
                    || dname.starts_with("handler")
                {
                    collect_opt_code_files(&p, depth_left - 1, pyc_out, py_out);
                }
            } else {
                collect_opt_code_files(&p, depth_left - 1, pyc_out, py_out);
            }
        } else if p.is_file() {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name.ends_with(".pyc") {
                pyc_out.push(p);
            } else if name.ends_with(".py") {
                py_out.push(p);
            }
        }
    }
}

fn slice_section<'a>(bytes: &'a [u8], sec: &Elf64Section) -> Option<&'a [u8]> {
    let start = sec.sh_offset as usize;
    let end = start.checked_add(sec.sh_size as usize)?;
    bytes.get(start..end)
}

fn read_cstr(strtab: &[u8], offset: usize) -> &str {
    let rest = &strtab[offset..];
    let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    std::str::from_utf8(&rest[..len]).unwrap_or("")
}

fn vaddr_to_offset(elf: &Elf64Info, vaddr: u64, shndx: u16) -> Option<u64> {
    for seg in &elf.phdrs {
        if seg.p_type == PT_LOAD && vaddr >= seg.p_vaddr && vaddr < seg.p_vaddr + seg.p_filesz {
            return Some(seg.p_offset + (vaddr - seg.p_vaddr));
        }
    }
    let sec = elf.sections.get(shndx as usize)?;
    if vaddr >= sec.sh_addr && vaddr < sec.sh_addr + sec.sh_size {
        Some(sec.sh_offset + (vaddr - sec.sh_addr))
    } else {
        None
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
