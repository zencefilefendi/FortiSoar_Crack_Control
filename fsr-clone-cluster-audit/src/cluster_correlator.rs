//! Engine 4: Multi-Organization / Multi-Node Golden Image Clone Clustering Engine.
//!
//! Performs O(N) hash-table cross-correlation (`std::collections::HashMap`) across:
//!   1. Birthmark JSON reports collected from multiple appliances (`--cluster-input`),
//!   2. External/internal Shodan, Censys, or TLS probe NDJSON streams,
//!   3. Live endpoints fingerprinted via `--scan-targets` (`remote_fingerprinter`),
//!   4. The local `--root` appliance birthmark (when audited alongside a cluster corpus).
//!
//! Emits mathematical clone proofs when >= 2 distinct nodes share:
//!   a) PostgreSQL 64-bit `pg_control` `system_identifier` -> `CRITICAL_CLONED_GOLDEN_IMAGE_PG_CLUSTER`,
//!   b) FortiSOAR `SECRET_KEY` / Fernet/AES vault key / salt HMAC -> `CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY`,
//!   c) `FGVM` Serial Number (`Subject CN` / `.lic`) or TLS `SPKI SHA-256` -> `CRITICAL_DUPLICATE_FGVM_SERIAL_CLONE`,
//!   d) EXT4/XFS Superblock UUID or OpenSSH Host Key SHA-256 -> `HIGH_CLONED_VM_FILESYSTEM_UUID`.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};
use fsr_net_crypto_audit::asn1_x509::{extract_pem_certificates, parse_x509_der};

use crate::birthmark_extractor::DeviceBirthmarks;
use crate::fgvm_license_inspect::extract_fgvm_tokens;
use crate::json_parser::{
    json_as_array, json_as_str, json_as_u64, json_get, json_get_path, parse_json_or_ndjson_records,
};

/// Normalized telemetry & birthmark record for a single appliance node.
#[derive(Debug, Clone, Default)]
pub struct ClusterNodeRecord {
    /// Source file or active probe endpoint label.
    pub source_label: String,
    /// IP address (or `ip:port` host component) if known.
    pub ip_address: Option<String>,
    /// TCP port if collected from network telemetry.
    pub port: Option<u16>,
    /// Appliance hostname if known.
    pub hostname: Option<String>,
    /// Organization / customer / ASN label if known.
    pub org_or_asn: Option<String>,
    /// Detected platform banner (`fortisoar`, `fortigate`, `nginx`, `xxxxxxxx-xxxxx`, etc.).
    pub server_signature: Option<String>,
    /// PostgreSQL `pg_control` 64-bit `system_identifier` strings (decimal).
    pub pg_system_identifiers: Vec<String>,
    /// `(param_name, hmac_sha256_fingerprint)` FortiSOAR vault / secret seeds.
    pub vault_seed_fingerprints: Vec<(String, String)>,
    /// Normalized uppercase `FGVM*` serial numbers (from X.509 CN, `.lic`, or config).
    pub fgvm_serials: Vec<String>,
    /// Lowercase hex X.509 `SubjectPublicKeyInfo` SHA-256 digests.
    pub tls_spki_sha256s: Vec<String>,
    /// X.509 Certificate Subject CNs observed on management interfaces.
    pub tls_subject_cns: Vec<String>,
    /// X.509 Certificate SerialNumber hex strings.
    pub tls_cert_serials: Vec<String>,
    /// Lowercase canonical EXT4/XFS Superblock UUIDs (including XFS v5 `meta_uuid`).
    pub filesystem_uuids: Vec<String>,
    /// Lowercase hex SHA-256 digests of OpenSSH `/etc/ssh/ssh_host_*_key.pub` blobs.
    pub ssh_host_key_sha256s: Vec<String>,
    /// `/etc/machine-id` if present.
    pub machine_id: Option<String>,
}

impl ClusterNodeRecord {
    /// Computes the canonical node identity key used to distinguish genuinely separate
    /// appliances/deployments while collapsing duplicate scan rows of the exact same host.
    pub fn distinct_node_key(&self) -> String {
        if let Some(ip) = &self.ip_address {
            let clean_ip = ip.trim().to_ascii_lowercase();
            if !clean_ip.is_empty() {
                return format!(
                    "ip:{}|org:{}",
                    clean_ip,
                    self.org_or_asn
                        .as_deref()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase()
                );
            }
        }
        format!(
            "org:{}|host:{}|src:{}",
            self.org_or_asn
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase(),
            self.hostname
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase(),
            self.source_label.trim()
        )
    }

    /// Human-readable display descriptor for cluster evidence arrays.
    pub fn display_descriptor(&self) -> String {
        let host = self.hostname.as_deref().unwrap_or("unknown-host");
        let ip_part = match (&self.ip_address, self.port) {
            (Some(ip), Some(p)) => format!("{}:{}", ip, p),
            (Some(ip), None) => ip.clone(),
            (None, _) => "offline-image".to_string(),
        };
        let org = self.org_or_asn.as_deref().unwrap_or("unspecified-org");
        format!(
            "{} [ip={}, org={}, src={}]",
            host, ip_part, org, self.source_label
        )
    }
}

/// Output of Engine 4 (`cluster_correlator`).
pub struct ClusterCorrelationResult {
    pub total_nodes_ingested: usize,
    pub distinct_nodes_evaluated: usize,
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Converts a single-node local extraction into a [`ClusterNodeRecord`].
pub fn build_local_cluster_node(
    source_label: &str,
    birthmarks: &DeviceBirthmarks,
    fgvm_serials: &[String],
    tls_spkis: &[String],
    org_label: Option<&str>,
) -> ClusterNodeRecord {
    let pg_ids = birthmarks
        .pg_controls
        .iter()
        .map(|p| p.system_identifier.to_string())
        .collect();

    let vault_seeds = birthmarks
        .crypto_seeds
        .iter()
        .map(|s| (s.parameter_name.clone(), s.hmac_sha256_fingerprint.clone()))
        .collect();

    let mut fs_uuids = Vec::new();
    for sb in &birthmarks.superblocks {
        if !sb.uuid.is_empty() && !fs_uuids.contains(&sb.uuid) {
            fs_uuids.push(sb.uuid.clone());
        }
        if let Some(meta_u) = &sb.meta_uuid {
            if !meta_u.is_empty() && !fs_uuids.contains(meta_u) {
                fs_uuids.push(meta_u.clone());
            }
        }
    }

    let ssh_hashes = birthmarks
        .ssh_host_keys
        .iter()
        .map(|k| k.key_blob_sha256.clone())
        .collect();

    ClusterNodeRecord {
        source_label: source_label.to_string(),
        ip_address: None,
        port: None,
        hostname: Some(birthmarks.hostname.clone()),
        org_or_asn: org_label.map(|s| s.to_string()),
        server_signature: None,
        pg_system_identifiers: pg_ids,
        vault_seed_fingerprints: vault_seeds,
        fgvm_serials: fgvm_serials
            .iter()
            .map(|s| s.to_ascii_uppercase())
            .collect(),
        tls_spki_sha256s: tls_spkis
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect(),
        tls_subject_cns: Vec::new(),
        tls_cert_serials: Vec::new(),
        filesystem_uuids: fs_uuids,
        ssh_host_key_sha256s: ssh_hashes,
        machine_id: birthmarks.machine_id.clone(),
    }
}

/// Loads [`ClusterNodeRecord`] entries from `--cluster-input <dir_or_ndjson>`.
pub fn load_cluster_input_records(
    input_path: &Path,
) -> Result<(Vec<ClusterNodeRecord>, Vec<String>), String> {
    let mut files = Vec::new();
    if input_path.is_dir() {
        collect_json_files_bounded(input_path, 4, &mut files);
        files.sort();
    } else if input_path.is_file() {
        files.push(input_path.to_path_buf());
    } else {
        return Err(format!(
            "cluster input path `{}` does not exist",
            input_path.display()
        ));
    }

    let mut nodes = Vec::new();
    let mut warnings = Vec::new();

    for file in files {
        let content = match fs::read_to_string(&file) {
            Ok(c) => c,
            Err(e) => {
                warnings.push(format!("{}: {}", file.display(), e));
                continue;
            }
        };
        let docs = match parse_json_or_ndjson_records(&content) {
            Ok(d) => d,
            Err(e) => {
                warnings.push(format!("{}: {}", file.display(), e));
                continue;
            }
        };

        let file_label = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("cluster_input.json")
            .to_string();

        for (idx, doc) in docs.iter().enumerate() {
            let rec_label = if docs.len() > 1 {
                format!("{}#{}", file_label, idx + 1)
            } else {
                file_label.clone()
            };
            if let Some(node) = extract_node_from_json(&rec_label, doc) {
                nodes.push(node);
            }
        }
    }

    Ok((nodes, warnings))
}

/// Runs O(N) hash-table correlation across all supplied [`ClusterNodeRecord`] items.
pub fn correlate_cluster_nodes(
    nodes: &[ClusterNodeRecord],
    parse_warnings: &[String],
) -> ClusterCorrelationResult {
    let mut findings = Vec::new();

    let distinct_keys: BTreeSet<String> = nodes.iter().map(|n| n.distinct_node_key()).collect();

    // O(N) HashMap buckets mapping artifact_value -> list of node indices
    let mut pg_id_buckets: HashMap<String, Vec<usize>> = HashMap::with_capacity(nodes.len() * 2);
    let mut vault_seed_buckets: HashMap<String, Vec<(usize, String)>> =
        HashMap::with_capacity(nodes.len() * 4);
    let mut fgvm_serial_buckets: HashMap<String, Vec<usize>> =
        HashMap::with_capacity(nodes.len() * 2);
    let mut tls_spki_buckets: HashMap<String, Vec<usize>> =
        HashMap::with_capacity(nodes.len() * 2);
    let mut fs_uuid_buckets: HashMap<String, Vec<usize>> = HashMap::with_capacity(nodes.len() * 2);
    let mut ssh_key_buckets: HashMap<String, Vec<usize>> = HashMap::with_capacity(nodes.len() * 2);

    for (idx, node) in nodes.iter().enumerate() {
        for pg_id in &node.pg_system_identifiers {
            if !pg_id.is_empty() && pg_id != "0" {
                pg_id_buckets.entry(pg_id.clone()).or_default().push(idx);
            }
        }
        for (param_name, fp) in &node.vault_seed_fingerprints {
            if !fp.is_empty() {
                vault_seed_buckets
                    .entry(fp.to_ascii_lowercase())
                    .or_default()
                    .push((idx, param_name.clone()));
            }
        }
        for ser in &node.fgvm_serials {
            let norm = ser.trim().to_ascii_uppercase();
            if !norm.is_empty() {
                fgvm_serial_buckets.entry(norm).or_default().push(idx);
            }
        }
        for spki in &node.tls_spki_sha256s {
            let norm = spki.trim().to_ascii_lowercase();
            if norm.len() == 64 {
                tls_spki_buckets.entry(norm).or_default().push(idx);
            }
        }
        for u in &node.filesystem_uuids {
            let norm = u.trim().to_ascii_lowercase();
            if !norm.is_empty() {
                fs_uuid_buckets.entry(norm).or_default().push(idx);
            }
        }
        for kh in &node.ssh_host_key_sha256s {
            let norm = kh.trim().to_ascii_lowercase();
            if norm.len() == 64 {
                ssh_key_buckets.entry(norm).or_default().push(idx);
            }
        }
    }

    let mut cluster_groups_json = Vec::new();

    // ------------------------------------------------------------------------
    // 4a. Same PostgreSQL 64-bit `system_identifier` -> CRITICAL_CLONED_GOLDEN_IMAGE_PG_CLUSTER
    // ------------------------------------------------------------------------
    let mut pg_keys: Vec<String> = pg_id_buckets.keys().cloned().collect();
    pg_keys.sort();
    for pg_id in pg_keys {
        let member_indices = dedup_distinct_nodes(&pg_id_buckets[&pg_id], nodes);
        if member_indices.len() >= 2 {
            let peers = format_peer_list(&member_indices, nodes);
            findings.push(
                Finding::new(
                    EngineId::ClusterCorrelator,
                    "CRITICAL_CLONED_GOLDEN_IMAGE_PG_CLUSTER",
                    Severity::Critical,
                    format!("pg_control:system_identifier:{}", pg_id),
                    format!(
                        "{} distinct FortiSOAR nodes share identical PostgreSQL 64-bit initdb system_identifier `{}` — cloned Golden Image OVA deployment proven",
                        member_indices.len(),
                        pg_id
                    ),
                )
                .with_evidence("pg_system_identifier", JsonValue::str(&pg_id))
                .with_evidence("cloned_node_count", JsonValue::Uint(member_indices.len() as u64))
                .with_evidence("affected_nodes", JsonValue::Array(peers.clone())),
            );
            cluster_groups_json.push(build_cluster_group_json(
                "pg_system_identifier",
                &pg_id,
                peers,
            ));
        }
    }

    // ------------------------------------------------------------------------
    // 4b. Same FortiSOAR `SECRET_KEY` / Vault Key / Salt -> CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY
    // ------------------------------------------------------------------------
    let mut seed_keys: Vec<String> = vault_seed_buckets.keys().cloned().collect();
    seed_keys.sort();
    for seed_fp in seed_keys {
        let entries = &vault_seed_buckets[&seed_fp];
        let raw_indices: Vec<usize> = entries.iter().map(|(i, _)| *i).collect();
        let member_indices = dedup_distinct_nodes(&raw_indices, nodes);
        if member_indices.len() >= 2 {
            let mut param_names: Vec<String> = entries.iter().map(|(_, p)| p.clone()).collect();
            param_names.sort();
            param_names.dedup();
            let peers = format_peer_list(&member_indices, nodes);

            findings.push(
                Finding::new(
                    EngineId::ClusterCorrelator,
                    "CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY",
                    Severity::Critical,
                    format!("soar_vault_hmac:{}", &seed_fp[..16.min(seed_fp.len())]),
                    format!(
                        "Supply-chain catastrophe: {} distinct FortiSOAR appliances share identical `{}` master cryptographic key (HMAC `{}`...) — cross-tenant credential decryption possible",
                        member_indices.len(),
                        param_names.join("/"),
                        &seed_fp[..16.min(seed_fp.len())]
                    ),
                )
                .with_evidence("seed_hmac_sha256", JsonValue::str(&seed_fp))
                .with_evidence(
                    "parameter_names",
                    JsonValue::Array(param_names.iter().map(|p| JsonValue::str(p.as_str())).collect()),
                )
                .with_evidence("cloned_node_count", JsonValue::Uint(member_indices.len() as u64))
                .with_evidence("affected_nodes", JsonValue::Array(peers.clone())),
            );
            cluster_groups_json.push(build_cluster_group_json(
                "soar_vault_master_key_hmac",
                &seed_fp,
                peers,
            ));
        }
    }

    // ------------------------------------------------------------------------
    // 4c. Same `FGVM` Serial OR same TLS `SPKI SHA-256` -> CRITICAL_DUPLICATE_FGVM_SERIAL_CLONE
    // ------------------------------------------------------------------------
    let mut ser_keys: Vec<String> = fgvm_serial_buckets.keys().cloned().collect();
    ser_keys.sort();
    for serial in ser_keys {
        let member_indices = dedup_distinct_nodes(&fgvm_serial_buckets[&serial], nodes);
        if member_indices.len() >= 2 {
            let peers = format_peer_list(&member_indices, nodes);
            findings.push(
                Finding::new(
                    EngineId::ClusterCorrelator,
                    "CRITICAL_DUPLICATE_FGVM_SERIAL_CLONE",
                    Severity::Critical,
                    format!("fgvm_serial:{}", serial),
                    format!(
                        "{} distinct appliances present the exact same FortiGate VM serial number `{}` — pirated/cloned license cluster detected",
                        member_indices.len(),
                        serial
                    ),
                )
                .with_evidence("collision_type", JsonValue::str("duplicate_fgvm_serial"))
                .with_evidence("fgvm_serial", JsonValue::str(&serial))
                .with_evidence("cloned_node_count", JsonValue::Uint(member_indices.len() as u64))
                .with_evidence("affected_nodes", JsonValue::Array(peers.clone())),
            );
            cluster_groups_json.push(build_cluster_group_json("fgvm_serial", &serial, peers));
        }
    }

    let mut spki_keys: Vec<String> = tls_spki_buckets.keys().cloned().collect();
    spki_keys.sort();
    for spki in spki_keys {
        let member_indices = dedup_distinct_nodes(&tls_spki_buckets[&spki], nodes);
        if member_indices.len() >= 2 {
            let peers = format_peer_list(&member_indices, nodes);
            findings.push(
                Finding::new(
                    EngineId::ClusterCorrelator,
                    "CRITICAL_DUPLICATE_FGVM_SERIAL_CLONE",
                    Severity::Critical,
                    format!("tls_spki_sha256:{}", &spki[..16]),
                    format!(
                        "{} distinct endpoints serve management TLS certificates with identical SubjectPublicKeyInfo SHA-256 `{}` — cloned private key / OVA certificate",
                        member_indices.len(),
                        spki
                    ),
                )
                .with_evidence("collision_type", JsonValue::str("duplicate_tls_spki_sha256"))
                .with_evidence("spki_sha256", JsonValue::str(&spki))
                .with_evidence("cloned_node_count", JsonValue::Uint(member_indices.len() as u64))
                .with_evidence("affected_nodes", JsonValue::Array(peers.clone())),
            );
            cluster_groups_json.push(build_cluster_group_json("tls_spki_sha256", &spki, peers));
        }
    }

    // ------------------------------------------------------------------------
    // 4d. Same EXT4/XFS Superblock UUID or SSH Host Key -> HIGH_CLONED_VM_FILESYSTEM_UUID
    // ------------------------------------------------------------------------
    let mut uuid_keys: Vec<String> = fs_uuid_buckets.keys().cloned().collect();
    uuid_keys.sort();
    for fs_uuid in uuid_keys {
        let member_indices = dedup_distinct_nodes(&fs_uuid_buckets[&fs_uuid], nodes);
        if member_indices.len() >= 2 {
            let peers = format_peer_list(&member_indices, nodes);
            findings.push(
                Finding::new(
                    EngineId::ClusterCorrelator,
                    "HIGH_CLONED_VM_FILESYSTEM_UUID",
                    Severity::High,
                    format!("superblock_uuid:{}", fs_uuid),
                    format!(
                        "{} distinct VM instances share identical EXT4/XFS filesystem Superblock UUID `{}` — raw disk clone from single master image",
                        member_indices.len(),
                        fs_uuid
                    ),
                )
                .with_evidence("collision_type", JsonValue::str("filesystem_superblock_uuid"))
                .with_evidence("filesystem_uuid", JsonValue::str(&fs_uuid))
                .with_evidence("cloned_node_count", JsonValue::Uint(member_indices.len() as u64))
                .with_evidence("affected_nodes", JsonValue::Array(peers.clone())),
            );
            cluster_groups_json.push(build_cluster_group_json(
                "filesystem_superblock_uuid",
                &fs_uuid,
                peers,
            ));
        }
    }

    let mut ssh_keys: Vec<String> = ssh_key_buckets.keys().cloned().collect();
    ssh_keys.sort();
    for ssh_fp in ssh_keys {
        let member_indices = dedup_distinct_nodes(&ssh_key_buckets[&ssh_fp], nodes);
        if member_indices.len() >= 2 {
            let peers = format_peer_list(&member_indices, nodes);
            findings.push(
                Finding::new(
                    EngineId::ClusterCorrelator,
                    "HIGH_CLONED_VM_FILESYSTEM_UUID",
                    Severity::High,
                    format!("ssh_host_key_sha256:{}", &ssh_fp[..16]),
                    format!(
                        "{} distinct VM instances share identical OpenSSH host key SHA-256 `{}` — unregenerated cloned VM template",
                        member_indices.len(),
                        ssh_fp
                    ),
                )
                .with_evidence("collision_type", JsonValue::str("ssh_host_key_sha256"))
                .with_evidence("ssh_host_key_sha256", JsonValue::str(&ssh_fp))
                .with_evidence("cloned_node_count", JsonValue::Uint(member_indices.len() as u64))
                .with_evidence("affected_nodes", JsonValue::Array(peers.clone())),
            );
            cluster_groups_json.push(build_cluster_group_json(
                "ssh_host_key_sha256",
                &ssh_fp,
                peers,
            ));
        }
    }

    let summary = JsonValue::OrderedObject(vec![
        (
            "total_records_ingested".to_string(),
            JsonValue::Uint(nodes.len() as u64),
        ),
        (
            "distinct_nodes_evaluated".to_string(),
            JsonValue::Uint(distinct_keys.len() as u64),
        ),
        (
            "clone_clusters_detected".to_string(),
            JsonValue::Uint(cluster_groups_json.len() as u64),
        ),
        (
            "parse_warnings_count".to_string(),
            JsonValue::Uint(parse_warnings.len() as u64),
        ),
        (
            "clusters".to_string(),
            JsonValue::Array(cluster_groups_json),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    ClusterCorrelationResult {
        total_nodes_ingested: nodes.len(),
        distinct_nodes_evaluated: distinct_keys.len(),
        summary,
        findings,
    }
}

fn dedup_distinct_nodes(indices: &[usize], nodes: &[ClusterNodeRecord]) -> Vec<usize> {
    let mut seen_keys = BTreeSet::new();
    let mut out = Vec::new();
    for &idx in indices {
        let key = nodes[idx].distinct_node_key();
        if seen_keys.insert(key) {
            out.push(idx);
        }
    }
    out
}

fn format_peer_list(indices: &[usize], nodes: &[ClusterNodeRecord]) -> Vec<JsonValue> {
    let mut descriptors: Vec<String> = indices
        .iter()
        .map(|&i| nodes[i].display_descriptor())
        .collect();
    descriptors.sort();
    descriptors.into_iter().map(JsonValue::Str).collect()
}

fn build_cluster_group_json(kind: &str, indicator: &str, members: Vec<JsonValue>) -> JsonValue {
    JsonValue::OrderedObject(vec![
        ("correlation_dimension".to_string(), JsonValue::str(kind)),
        ("shared_indicator".to_string(), JsonValue::str(indicator)),
        ("member_count".to_string(), JsonValue::Uint(members.len() as u64)),
        ("members".to_string(), JsonValue::Array(members)),
    ])
}

/// Extracts a normalized [`ClusterNodeRecord`] from either a canonical `fsr-clone-cluster-audit`
/// JSON report OR a Shodan / Censys / TLS-probe telemetry JSON object.
fn extract_node_from_json(source_label: &str, doc: &JsonValue) -> Option<ClusterNodeRecord> {
    let mut rec = ClusterNodeRecord {
        source_label: source_label.to_string(),
        ..Default::default()
    };

    // 1. Extract IP / port / hostname / org from top-level or `scan_context` (supports Shodan `ip_str`, Censys `ip`, our `scan_context.hostname`)
    rec.ip_address = first_str(doc, &[&["ip"], &["ip_str"], &["target_ip"], &["host_ip"]]);
    rec.port = json_get(doc, "port")
        .and_then(json_as_u64)
        .and_then(|p| u16::try_from(p).ok());
    rec.hostname = first_str(
        doc,
        &[
            &["scan_context", "hostname"],
            &["engines", "birthmark_extractor", "hostname"],
            &["hostname"],
        ],
    )
    .or_else(|| {
        json_get(doc, "hostnames")
            .and_then(json_as_array)
            .and_then(|a| a.first())
            .and_then(json_as_str)
            .map(|s| s.to_string())
    });

    rec.org_or_asn = first_str(
        doc,
        &[
            &["org"],
            &["organization"],
            &["asn"],
            &["autonomous_system", "asn"],
            &["scan_context", "org"],
        ],
    );

    rec.server_signature = first_str(
        doc,
        &[
            &["server_signature"],
            &["http", "server"],
            &["http_server"],
        ],
    );

    // 2. Canonical `engines.birthmark_extractor` (or top-level `birthmarks`) fields
    let bm_obj = json_get_path(doc, &["engines", "birthmark_extractor"])
        .or_else(|| json_get(doc, "birthmarks"))
        .unwrap_or(doc);

    if let Some(mid) = json_get(bm_obj, "machine_id").and_then(json_as_str) {
        if !mid.is_empty() {
            rec.machine_id = Some(mid.to_ascii_lowercase());
        }
    }

    if let Some(pg_arr) = json_get(bm_obj, "pg_controls").and_then(json_as_array) {
        for item in pg_arr {
            if let Some(sys_id) = json_get(item, "system_identifier").and_then(json_as_str) {
                push_unique(&mut rec.pg_system_identifiers, sys_id.to_string());
            } else if let Some(sys_u) = json_get(item, "system_identifier").and_then(json_as_u64) {
                push_unique(&mut rec.pg_system_identifiers, sys_u.to_string());
            }
        }
    }
    if let Some(flat_pg) = json_get(doc, "pg_system_identifier") {
        if let Some(s) = json_as_str(flat_pg) {
            push_unique(&mut rec.pg_system_identifiers, s.to_string());
        } else if let Some(u) = json_as_u64(flat_pg) {
            push_unique(&mut rec.pg_system_identifiers, u.to_string());
        }
    }

    if let Some(seeds_arr) = json_get(bm_obj, "crypto_seeds").and_then(json_as_array) {
        for item in seeds_arr {
            if let Some(fp) = json_get(item, "hmac_sha256_fingerprint").and_then(json_as_str) {
                let pname = json_get(item, "parameter_name")
                    .and_then(json_as_str)
                    .unwrap_or("SECRET_KEY")
                    .to_string();
                rec.vault_seed_fingerprints
                    .push((pname, fp.to_ascii_lowercase()));
            }
        }
    }
    if let Some(flat_seeds) = json_get(doc, "vault_seed_hashes").and_then(json_as_array) {
        for item in flat_seeds {
            if let Some(s) = json_as_str(item) {
                rec.vault_seed_fingerprints
                    .push(("SECRET_KEY".to_string(), s.to_ascii_lowercase()));
            }
        }
    }

    if let Some(sb_arr) = json_get(bm_obj, "superblocks").and_then(json_as_array) {
        for item in sb_arr {
            if let Some(u) = json_get(item, "uuid").and_then(json_as_str) {
                push_unique(&mut rec.filesystem_uuids, u.to_ascii_lowercase());
            }
            if let Some(mu) = json_get(item, "meta_uuid").and_then(json_as_str) {
                push_unique(&mut rec.filesystem_uuids, mu.to_ascii_lowercase());
            }
        }
    }
    if let Some(flat_uuids) = json_get(doc, "filesystem_uuids").and_then(json_as_array) {
        for item in flat_uuids {
            if let Some(u) = json_as_str(item) {
                push_unique(&mut rec.filesystem_uuids, u.to_ascii_lowercase());
            }
        }
    }

    if let Some(ssh_arr) = json_get(bm_obj, "ssh_host_keys").and_then(json_as_array) {
        for item in ssh_arr {
            if let Some(kh) = json_get(item, "key_blob_sha256").and_then(json_as_str) {
                push_unique(&mut rec.ssh_host_key_sha256s, kh.to_ascii_lowercase());
            }
        }
    }

    // 3. Extract FGVM serials from `engines.fgvm_license_inspect.serials` or flat `fgvm_serial`
    if let Some(ser_arr) =
        json_get_path(doc, &["engines", "fgvm_license_inspect", "serials"]).and_then(json_as_array)
    {
        for item in ser_arr {
            if let Some(s) = json_get(item, "serial").and_then(json_as_str) {
                push_unique(&mut rec.fgvm_serials, s.to_ascii_uppercase());
            }
        }
    }
    if let Some(flat_ser) = json_get(doc, "fgvm_serial").and_then(json_as_str) {
        push_unique(&mut rec.fgvm_serials, flat_ser.to_ascii_uppercase());
    }

    // 4. Extract TLS / Shodan / Censys certificate SPKI SHA-256 & Subject CN (`FGVM*`)
    for spki_path in [
        &["spki_sha256"][..],
        &["tls", "spki_sha256"][..],
        &["ssl", "cert", "spki_sha256"][..],
        &["ssl", "cert", "pubkey", "sha256"][..],
    ] {
        if let Some(spki) = json_get_path(doc, spki_path).and_then(json_as_str) {
            push_unique(&mut rec.tls_spki_sha256s, spki.to_ascii_lowercase());
        }
    }

    for cn_path in [
        &["subject_cn"][..],
        &["tls", "subject_cn"][..],
        &["ssl", "cert", "subject", "CN"][..],
    ] {
        if let Some(cn) = json_get_path(doc, cn_path).and_then(json_as_str) {
            push_unique(&mut rec.tls_subject_cns, cn.to_string());
            for fgvm_tok in extract_fgvm_tokens(cn) {
                push_unique(&mut rec.fgvm_serials, fgvm_tok.to_ascii_uppercase());
            }
        }
    }

    // Parse raw PEM certificates inside Shodan/Censys telemetry if present
    for pem_path in [
        &["pem"][..],
        &["tls", "pem"][..],
        &["ssl", "chain_pem"][..],
    ] {
        if let Some(pem_str) = json_get_path(doc, pem_path).and_then(json_as_str) {
            for der in extract_pem_certificates(pem_str) {
                if let Ok(cert) = parse_x509_der(&der) {
                    push_unique(&mut rec.tls_spki_sha256s, cert.spki_sha256);
                    push_unique(&mut rec.tls_cert_serials, cert.serial_hex);
                    if let Some(cn) = cert.subject_cn {
                        for tok in extract_fgvm_tokens(&cn) {
                            push_unique(&mut rec.fgvm_serials, tok.to_ascii_uppercase());
                        }
                        push_unique(&mut rec.tls_subject_cns, cn);
                    }
                }
            }
        }
    }

    // Also unpack `engines.remote_fingerprinter.targets` if reading a saved remote scan report
    let has_data = !rec.pg_system_identifiers.is_empty()
        || !rec.vault_seed_fingerprints.is_empty()
        || !rec.fgvm_serials.is_empty()
        || !rec.tls_spki_sha256s.is_empty()
        || !rec.filesystem_uuids.is_empty()
        || !rec.ssh_host_key_sha256s.is_empty()
        || rec.machine_id.is_some();

    if has_data {
        Some(rec)
    } else {
        None
    }
}

fn first_str(doc: &JsonValue, paths: &[&[&str]]) -> Option<String> {
    for p in paths {
        if let Some(s) = json_get_path(doc, p).and_then(json_as_str) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn push_unique(vec: &mut Vec<String>, val: String) {
    if !val.is_empty() && !vec.contains(&val) {
        vec.push(val);
    }
}

fn collect_json_files_bounded(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if ft.is_dir() {
            collect_json_files_bounded(&entry.path(), depth - 1, out);
        } else if ft.is_file()
            && (name.ends_with(".json") || name.ends_with(".ndjson") || name.ends_with(".jsonl"))
        {
            out.push(entry.path());
        }
    }
}
