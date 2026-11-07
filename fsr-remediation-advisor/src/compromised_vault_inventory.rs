//! Module 1: Compromised SOAR Integration & Enterprise Credential Rotation Inventory
//! (`compromised_vault_inventory.rs`).
//!
//! Activated when the `ForensicVerdictBundle` contains `CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY`
//! (all encrypted credentials in the SOAR vault are decryptable by whoever possesses the
//! cloned Golden Image `SECRET_KEY`) or `CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER` (an active
//! connector implant exfiltrates `config` credentials at runtime).
//!
//! Strictly operates on **structural connector & configuration metadata only** (`info.json`,
//! config field schemas, non-secret endpoint descriptors, and `config.get('<field>')` key
//! names) — **never reading, decrypting, or logging any password, token, or secret value**.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fsr_clone_cluster_audit::birthmark_extractor::{display_under_root, join_rooted};
use fsr_clone_cluster_audit::json_parser::{json_as_array, json_as_str, json_get, parse_json_str};
use fsr_deep_audit::schema::JsonValue;

/// Priority tier for emergency enterprise credential revocation & rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RotationUrgency {
    P0ImmediateActiveBreach,
    P0IdentityAndSecurityFabric,
    P1EnterpriseCorePlatform,
    P2ExternalApiIntegration,
}

impl RotationUrgency {
    pub fn as_str(self) -> &'static str {
        match self {
            RotationUrgency::P0ImmediateActiveBreach => "P0_IMMEDIATE_ACTIVE_SKIMMER",
            RotationUrgency::P0IdentityAndSecurityFabric => "P0_IDENTITY_AND_SECURITY_FABRIC",
            RotationUrgency::P1EnterpriseCorePlatform => "P1_ENTERPRISE_CORE_PLATFORM",
            RotationUrgency::P2ExternalApiIntegration => "P2_EXTERNAL_API_INTEGRATION",
        }
    }

    pub fn sla_window_tr(self) -> &'static str {
        match self {
            RotationUrgency::P0ImmediateActiveBreach => "DERHAL (0-15 Dakika — Aktif Sızıntı)",
            RotationUrgency::P0IdentityAndSecurityFabric => "ACİL (0-1 Saat — Kimlik/EDR/Güvenlik Duvarı)",
            RotationUrgency::P1EnterpriseCorePlatform => "YÜKSEK (1-4 Saat — SIEM/E-Posta/Bulut)",
            RotationUrgency::P2ExternalApiIntegration => "STANDART (4-12 Saat — Tehdit İstihbaratı/ITSM)",
        }
    }
}

/// Single enterprise integration whose API keys / service accounts require revocation & rotation.
#[derive(Debug, Clone)]
pub struct CompromisedIntegrationEntry {
    pub connector_id: String,
    pub display_label: String,
    pub version: String,
    pub publisher: String,
    pub enterprise_system_category: String,
    pub connector_dir: String,
    pub actively_skimmed: bool,
    pub exposure_reason: String,
    pub urgency: RotationUrgency,
    pub credential_fields_at_risk: Vec<String>,
    pub non_secret_endpoint_hints: Vec<String>,
    pub revocation_and_rotation_steps_tr: Vec<String>,
}

impl CompromisedIntegrationEntry {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            (
                "connector_id".to_string(),
                JsonValue::str(&self.connector_id),
            ),
            (
                "display_label".to_string(),
                JsonValue::str(&self.display_label),
            ),
            ("version".to_string(), JsonValue::str(&self.version)),
            ("publisher".to_string(), JsonValue::str(&self.publisher)),
            (
                "enterprise_system_category".to_string(),
                JsonValue::str(&self.enterprise_system_category),
            ),
            (
                "connector_dir".to_string(),
                JsonValue::str(&self.connector_dir),
            ),
            (
                "actively_skimmed".to_string(),
                JsonValue::Bool(self.actively_skimmed),
            ),
            (
                "exposure_reason".to_string(),
                JsonValue::str(&self.exposure_reason),
            ),
            (
                "urgency".to_string(),
                JsonValue::str(self.urgency.as_str()),
            ),
            (
                "sla_window_tr".to_string(),
                JsonValue::str(self.urgency.sla_window_tr()),
            ),
            (
                "credential_fields_at_risk".to_string(),
                JsonValue::Array(
                    self.credential_fields_at_risk
                        .iter()
                        .map(|f| JsonValue::str(f.as_str()))
                        .collect(),
                ),
            ),
            (
                "non_secret_endpoint_hints".to_string(),
                JsonValue::Array(
                    self.non_secret_endpoint_hints
                        .iter()
                        .map(|h| JsonValue::str(h.as_str()))
                        .collect(),
                ),
            ),
            (
                "revocation_and_rotation_steps_tr".to_string(),
                JsonValue::Array(
                    self.revocation_and_rotation_steps_tr
                        .iter()
                        .map(|s| JsonValue::str(s.as_str()))
                        .collect(),
                ),
            ),
        ])
    }
}

/// Complete output of Module 1 (`compromised_vault_inventory`).
#[derive(Debug, Clone)]
pub struct CompromisedVaultInventory {
    pub emergency_rotation_required: bool,
    pub shared_vault_master_key_compromised: bool,
    pub active_connector_skimmer_detected: bool,
    pub triggering_finding_codes: Vec<String>,
    pub corroborating_exposure_codes: Vec<String>,
    pub connectors_inspected_count: usize,
    pub secrets_read_count: usize, // Always 0 by strict architectural guarantee
    pub emergency_revocation_list: Vec<CompromisedIntegrationEntry>,
    pub vault_rekey_procedure_tr: Vec<String>,
}

impl CompromisedVaultInventory {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            (
                "emergency_rotation_required".to_string(),
                JsonValue::Bool(self.emergency_rotation_required),
            ),
            (
                "shared_vault_master_key_compromised".to_string(),
                JsonValue::Bool(self.shared_vault_master_key_compromised),
            ),
            (
                "active_connector_skimmer_detected".to_string(),
                JsonValue::Bool(self.active_connector_skimmer_detected),
            ),
            (
                "triggering_finding_codes".to_string(),
                JsonValue::Array(
                    self.triggering_finding_codes
                        .iter()
                        .map(|c| JsonValue::str(c.as_str()))
                        .collect(),
                ),
            ),
            (
                "corroborating_exposure_codes".to_string(),
                JsonValue::Array(
                    self.corroborating_exposure_codes
                        .iter()
                        .map(|c| JsonValue::str(c.as_str()))
                        .collect(),
                ),
            ),
            (
                "connectors_inspected_count".to_string(),
                JsonValue::Uint(self.connectors_inspected_count as u64),
            ),
            (
                "secrets_read_count".to_string(),
                JsonValue::Uint(self.secrets_read_count as u64),
            ),
            (
                "emergency_revocation_list".to_string(),
                JsonValue::Array(
                    self.emergency_revocation_list
                        .iter()
                        .map(|e| e.to_json())
                        .collect(),
                ),
            ),
            (
                "vault_rekey_procedure_tr".to_string(),
                JsonValue::Array(
                    self.vault_rekey_procedure_tr
                        .iter()
                        .map(|s| JsonValue::str(s.as_str()))
                        .collect(),
                ),
            ),
        ])
    }
}

/// Builds the emergency compromised integration & credential rotation inventory from a
/// parsed `ForensicVerdictBundle` JSON document and optional `--root` appliance directory.
pub fn build_compromised_vault_inventory(
    bundle_doc: &JsonValue,
    effective_root: Option<&Path>,
) -> CompromisedVaultInventory {
    let mut shared_vault_key = false;
    let mut active_skimmer = false;
    let mut trigger_codes = BTreeSet::new();
    let mut corroborating_codes = BTreeSet::new();
    let mut skimmed_targets: Vec<String> = Vec::new();
    let mut skimmed_connector_names: BTreeSet<String> = BTreeSet::new();

    if let Some(findings) = json_get(bundle_doc, "findings").and_then(json_as_array) {
        for f in findings {
            let Some(code) = json_get(f, "code").and_then(json_as_str) else {
                continue;
            };
            let target = json_get(f, "target")
                .and_then(json_as_str)
                .unwrap_or("");
            match code {
                "CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY" => {
                    shared_vault_key = true;
                    trigger_codes.insert(code.to_string());
                }
                "CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER" => {
                    active_skimmer = true;
                    trigger_codes.insert(code.to_string());
                    if !target.is_empty() {
                        skimmed_targets.push(target.to_string());
                    }
                    if let Some(ev) = json_get(f, "evidence") {
                        if let Some(cname) = json_get(ev, "connector").and_then(json_as_str) {
                            if !cname.is_empty() {
                                skimmed_connector_names.insert(cname.to_ascii_lowercase());
                            }
                        }
                    }
                }
                "CRITICAL_OBFUSCATED_SOAR_PAYLOAD"
                | "CRITICAL_NGINX_TRAFFIC_MIRROR_OR_BYPASS"
                | "CRITICAL_DJANGO_AUTH_BYPASS_MIDDLEWARE"
                | "CRITICAL_PG_HBA_TRUST_BACKDOOR" => {
                    corroborating_codes.insert(code.to_string());
                }
                _ => {}
            }
        }
    }

    let emergency_rotation_required = shared_vault_key || active_skimmer;
    if !emergency_rotation_required {
        return CompromisedVaultInventory {
            emergency_rotation_required: false,
            shared_vault_master_key_compromised: false,
            active_connector_skimmer_detected: false,
            triggering_finding_codes: Vec::new(),
            corroborating_exposure_codes: corroborating_codes.into_iter().collect(),
            connectors_inspected_count: 0,
            secrets_read_count: 0,
            emergency_revocation_list: Vec::new(),
            vault_rekey_procedure_tr: Vec::new(),
        };
    }

    let mut discovered_entries: BTreeMap<String, CompromisedIntegrationEntry> = BTreeMap::new();
    let mut connectors_inspected_count = 0usize;

    // 1. Scan connector metadata directories under `effective_root` if available
    if let Some(root) = effective_root {
        let mut connector_dirs = Vec::new();
        for rel in [
            "opt/cyops-integrations/integrations/connectors",
            "opt/cyops/integrations/connectors",
        ] {
            let base = join_rooted(root, rel);
            if base.is_dir() {
                collect_connector_dirs(&base, 4, &mut connector_dirs);
            }
        }
        connector_dirs.sort();
        connector_dirs.dedup();

        // Optional non-secret external config metadata hints under `/etc/cyops-integrations` or `configs`
        let global_endpoint_hints = collect_non_secret_config_hints(root);

        for conn_dir in connector_dirs {
            connectors_inspected_count += 1;
            let entry = inspect_connector_metadata_dir(
                root,
                &conn_dir,
                shared_vault_key,
                &skimmed_targets,
                &skimmed_connector_names,
                &global_endpoint_hints,
            );
            discovered_entries.insert(entry.connector_dir.clone(), entry);
        }
    }

    // 2. Fallback synthesis from bundle findings if `--root` was not mounted/available
    //    so offline bundle-only runs still identify every skimmed connector from `findings`!
    for skim_target in &skimmed_targets {
        let already_covered = discovered_entries
            .keys()
            .any(|dir| skim_target.starts_with(dir));
        if !already_covered {
            let inferred_name = skimmed_connector_names
                .iter()
                .next()
                .cloned()
                .unwrap_or_else(|| infer_connector_slug_from_path(skim_target));
            let profile = classify_enterprise_platform(&inferred_name, &inferred_name);
            let entry = CompromisedIntegrationEntry {
                connector_id: inferred_name.clone(),
                display_label: profile.default_label.to_string(),
                version: "unknown (offline-bundle)".to_string(),
                publisher: "Unknown / Tampered".to_string(),
                enterprise_system_category: profile.category.to_string(),
                connector_dir: skim_target.clone(),
                actively_skimmed: true,
                exposure_reason: "Konnektör betiğinde aktif kimlik bilgisi sızdırma (CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER) tespit edildi".to_string(),
                urgency: RotationUrgency::P0ImmediateActiveBreach,
                credential_fields_at_risk: profile
                    .default_cred_fields
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
                non_secret_endpoint_hints: Vec::new(),
                revocation_and_rotation_steps_tr: profile
                    .rotation_steps
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            };
            discovered_entries.insert(skim_target.clone(), entry);
        }
    }

    let mut emergency_revocation_list: Vec<CompromisedIntegrationEntry> =
        discovered_entries.into_values().collect();
    emergency_revocation_list.sort_by(|a, b| {
        a.urgency
            .cmp(&b.urgency)
            .then_with(|| b.actively_skimmed.cmp(&a.actively_skimmed))
            .then_with(|| a.connector_id.cmp(&b.connector_id))
    });

    let vault_rekey_procedure_tr = build_vault_rekey_procedure(shared_vault_key, active_skimmer);

    CompromisedVaultInventory {
        emergency_rotation_required: true,
        shared_vault_master_key_compromised: shared_vault_key,
        active_connector_skimmer_detected: active_skimmer,
        triggering_finding_codes: trigger_codes.into_iter().collect(),
        corroborating_exposure_codes: corroborating_codes.into_iter().collect(),
        connectors_inspected_count,
        secrets_read_count: 0,
        emergency_revocation_list,
        vault_rekey_procedure_tr,
    }
}

fn collect_connector_dirs(dir: &Path, depth_left: usize, out: &mut Vec<PathBuf>) {
    if depth_left == 0 {
        return;
    }
    if dir.join("info.json").is_file() || dir.join("MANIFEST.json").is_file() {
        out.push(dir.to_path_buf());
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() && !ft.is_symlink() {
            collect_connector_dirs(&entry.path(), depth_left - 1, out);
        }
    }
}

fn inspect_connector_metadata_dir(
    root: &Path,
    conn_dir: &Path,
    shared_vault_key: bool,
    skimmed_targets: &[String],
    skimmed_connector_names: &BTreeSet<String>,
    global_endpoint_hints: &BTreeMap<String, Vec<String>>,
) -> CompromisedIntegrationEntry {
    let rel_dir = display_under_root(root, conn_dir);
    let info_path = if conn_dir.join("info.json").is_file() {
        conn_dir.join("info.json")
    } else {
        conn_dir.join("MANIFEST.json")
    };

    let mut name = infer_connector_slug_from_path(&rel_dir);
    let mut label = String::new();
    let mut version = String::from("unknown");
    let mut publisher = String::from("Unknown");
    let mut cred_fields = BTreeSet::new();
    let mut endpoint_hints = BTreeSet::new();

    if let Ok(raw_info) = fs::read_to_string(&info_path) {
        if let Ok(doc) = parse_json_str(&raw_info) {
            if let Some(n) = json_get(&doc, "name").and_then(json_as_str) {
                if !n.trim().is_empty() {
                    name = n.trim().to_string();
                }
            }
            if let Some(l) = json_get(&doc, "label")
                .or_else(|| json_get(&doc, "display_name"))
                .and_then(json_as_str)
            {
                label = l.trim().to_string();
            }
            if let Some(v) = json_get(&doc, "version").and_then(json_as_str) {
                version = v.trim().to_string();
            }
            if let Some(p) = json_get(&doc, "publisher").and_then(json_as_str) {
                publisher = p.trim().to_string();
            }

            // Extract credential field DEFINITIONS from `configuration.fields[*]` (schema only, never values!)
            if let Some(cfg_obj) = json_get(&doc, "configuration") {
                if let Some(fields_arr) = json_get(cfg_obj, "fields").and_then(json_as_array) {
                    for f in fields_arr {
                        let fname = json_get(f, "name").and_then(json_as_str).unwrap_or("");
                        let ftitle = json_get(f, "title").and_then(json_as_str).unwrap_or(fname);
                        let ftype = json_get(f, "type")
                            .and_then(json_as_str)
                            .unwrap_or("")
                            .to_ascii_lowercase();

                        if is_secret_field_descriptor(fname, &ftype) && !fname.is_empty() {
                            cred_fields.insert(format!("{} ({})", fname, ftitle));
                        } else if is_endpoint_field_name(fname) && !ftitle.is_empty() {
                            endpoint_hints.insert(format!("yapılandırma alanı: {}", fname));
                        }
                    }
                }
            }
        }
    }

    // Also inspect `config.get('<field_name>')` key names inside connector `.py` files
    // (extracting ONLY hardcoded dictionary parameter identifiers, never secret values!)
    extract_python_config_field_names(conn_dir, &mut cred_fields);

    if let Some(hints) = global_endpoint_hints.get(&name.to_ascii_lowercase()) {
        for h in hints {
            endpoint_hints.insert(h.clone());
        }
    }

    let profile = classify_enterprise_platform(&name, &label);
    if label.is_empty() {
        label = profile.default_label.to_string();
    }
    if cred_fields.is_empty() {
        for &df in profile.default_cred_fields {
            cred_fields.insert(df.to_string());
        }
    }

    let actively_skimmed = skimmed_targets.iter().any(|t| t.starts_with(&rel_dir))
        || skimmed_connector_names.contains(&name.to_ascii_lowercase());

    let urgency = if actively_skimmed {
        RotationUrgency::P0ImmediateActiveBreach
    } else {
        profile.base_urgency
    };

    let exposure_reason = match (actively_skimmed, shared_vault_key) {
        (true, true) => "HEM konnektör içinde aktif kimlik bilgisi sızdırıcı arka kapı (`CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER`) HEM DE klonlanmış ortak kasa anahtarı (`CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY`) tespit edildi".to_string(),
        (true, false) => "Konnektör Python kodunda kasadan çözülen `config` sırlarını dış hedefe sızdıran arka kapı (`CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER`) tespit edildi".to_string(),
        (false, true) => "Cihaz klonlanmış Golden Image ortak `SECRET_KEY` anahtarını (`CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY`) kullandığından bu entegrasyonun kasadaki kimlik bilgileri imaj sağlayıcısı tarafından çözülebilir durumdadır".to_string(),
        (false, false) => "İhtiyati kasa anahtarı yenilemesi".to_string(),
    };

    CompromisedIntegrationEntry {
        connector_id: name,
        display_label: label,
        version,
        publisher,
        enterprise_system_category: profile.category.to_string(),
        connector_dir: rel_dir,
        actively_skimmed,
        exposure_reason,
        urgency,
        credential_fields_at_risk: cred_fields.into_iter().collect(),
        non_secret_endpoint_hints: endpoint_hints.into_iter().collect(),
        revocation_and_rotation_steps_tr: profile
            .rotation_steps
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
    }
}

fn is_secret_field_descriptor(field_name: &str, field_type: &str) -> bool {
    if matches!(
        field_type,
        "password" | "keystore" | "encrypted" | "secret" | "certificate"
    ) {
        return true;
    }
    let lower = field_name.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "pwd",
        "secret",
        "api_key",
        "apikey",
        "token",
        "private_key",
        "client_secret",
        "access_key",
        "keytab",
        "passphrase",
        "bearer",
    ]
    .iter()
    .any(|kw| lower.contains(kw))
}

fn is_endpoint_field_name(field_name: &str) -> bool {
    let lower = field_name.to_ascii_lowercase();
    if is_secret_field_descriptor(&lower, "") {
        return false;
    }
    ["server", "url", "host", "domain", "fqdn", "tenant", "base_url"]
        .iter()
        .any(|kw| lower.contains(kw))
}

/// Scans `config.get('...')` or `config['...']` inside connector `.py` files to discover
/// which credential parameter names a connector consumes without touching runtime data.
fn extract_python_config_field_names(conn_dir: &Path, out_fields: &mut BTreeSet<String>) {
    let Ok(rd) = fs::read_dir(conn_dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("py") {
            continue;
        }
        let Ok(src) = fs::read_to_string(&p) else {
            continue;
        };
        for pat in ["config.get('", "config.get(\"", "config['", "config[\""] {
            let quote = pat.chars().last().unwrap_or('\'');
            let mut rest = src.as_str();
            while let Some(idx) = rest.find(pat) {
                let after = &rest[idx + pat.len()..];
                if let Some(end_q) = after.find(quote) {
                    let key_name = &after[..end_q];
                    if !key_name.is_empty()
                        && key_name.len() <= 48
                        && key_name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                        && is_secret_field_descriptor(key_name, "")
                    {
                        out_fields.insert(format!("{} (Python config parametresi)", key_name));
                    }
                    rest = &after[end_q + 1..];
                } else {
                    break;
                }
            }
        }
    }
}

/// Extracts strictly non-secret target server/domain metadata from `/etc/cyops-integrations/*.json`
/// if present, explicitly skipping any key that could hold a secret.
fn collect_non_secret_config_hints(root: &Path) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rel in [
        "etc/cyops-integrations",
        "opt/cyops-integrations/integrations/configs",
    ] {
        let dir = join_rooted(root, rel);
        let Ok(rd) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(raw) = fs::read_to_string(&p) else {
                continue;
            };
            let Ok(doc) = parse_json_str(&raw) else {
                continue;
            };
            let Some(conn_name) = json_get(&doc, "connector")
                .or_else(|| json_get(&doc, "name"))
                .and_then(json_as_str)
            else {
                continue;
            };
            let mut hints = Vec::new();
            for safe_key in ["server_url", "host", "url", "domain", "tenant_id", "environment"] {
                if let Some(val) = json_get(&doc, safe_key).and_then(json_as_str) {
                    let clean_val = sanitize_endpoint_hint(val);
                    if !clean_val.is_empty() {
                        hints.push(format!("{}={}", safe_key, clean_val));
                    }
                }
            }
            if !hints.is_empty() {
                map.entry(conn_name.to_ascii_lowercase())
                    .or_default()
                    .extend(hints);
            }
        }
    }
    map
}

/// Strips query strings and userinfo (`user:pass@host`) from URLs so no embedded credential
/// can ever leak into an endpoint hint.
fn sanitize_endpoint_hint(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_query = trimmed.split('?').next().unwrap_or(trimmed);
    if let Some((scheme, rest)) = without_query.split_once("://") {
        let host_part = match rest.rsplit_once('@') {
            Some((_, after_at)) => after_at,
            None => rest,
        };
        format!("{}://{}", scheme, host_part)
    } else if without_query.contains('@') {
        without_query
            .rsplit_once('@')
            .map(|(_, dom)| dom.to_string())
            .unwrap_or_default()
    } else {
        without_query.chars().take(96).collect()
    }
}

fn infer_connector_slug_from_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for (idx, seg) in parts.iter().enumerate() {
        if *seg == "connectors" {
            if let Some(next_seg) = parts.get(idx + 1) {
                return (*next_seg).to_string();
            }
        }
    }
    parts.last().copied().unwrap_or("unknown-connector").to_string()
}

struct EnterprisePlatformProfile {
    default_label: &'static str,
    category: &'static str,
    base_urgency: RotationUrgency,
    default_cred_fields: &'static [&'static str],
    rotation_steps: &'static [&'static str],
}

fn classify_enterprise_platform(name: &str, label: &str) -> EnterprisePlatformProfile {
    let combined = format!("{} {}", name, label).to_ascii_lowercase();

    if combined.contains("active-directory")
        || combined.contains("active_directory")
        || combined.contains("activedirectory")
        || combined.contains("ldap")
        || combined.contains("entra")
    {
        EnterprisePlatformProfile {
            default_label: "Microsoft Active Directory / LDAP",
            category: "Kimlik ve Dizin Hizmetleri (Identity / AD)",
            base_urgency: RotationUrgency::P0IdentityAndSecurityFabric,
            default_cred_fields: &[
                "password (LDAP Bind Servis Hesabı Parolası)",
                "keytab / client_secret (Kerberos / LDAPS Kimliği)",
            ],
            rotation_steps: &[
                "SOAR tarafından kullanılan AD servis hesabını (`svc_fortisoar` vb.) Domain Controller üzerinde anında devre dışı bırakın veya parolasını 32+ karakter rastgele değerle değiştirin.",
                "Servis hesabının `Domain Admins`, `Account Operators` veya parola sıfırlama delegasyonu yetkisi varsa son 90 günlük Security Event ID 4720/4724/4728/4732 kayıtlarını inceleyin.",
                "Aktif Kerberos TGT/TGS biletlerini geçersiz kılın; yetki yükseltme şüphesi varsa planlı çift `krbtgt` parola rotasyonu uygulayın.",
            ],
        }
    } else if combined.contains("crowdstrike")
        || combined.contains("sentinelone")
        || combined.contains("cortex")
        || combined.contains("defender")
        || combined.contains("carbonblack")
        || combined.contains("edr")
    {
        EnterprisePlatformProfile {
            default_label: "Kurumsal EDR / XDR Platformu (CrowdStrike / SentinelOne)",
            category: "Uç Nokta Tespit ve Müdahale (EDR / XDR)",
            base_urgency: RotationUrgency::P0IdentityAndSecurityFabric,
            default_cred_fields: &[
                "client_secret / api_token (EDR Yönetim ve RTR API Anahtarı)",
            ],
            rotation_steps: &[
                "EDR bulut yönetim konsolundan FortiSOAR entegrasyonuna ait OAuth2 `client_id`/`client_secret` veya API Token kimliğini derhal İPTAL EDİN (Revoke).",
                "İptal edilen API anahtarıyla oluşturulmuş istisnaları (Exclusions), karantina kaldırma (Unquarantine) aksiyonlarını ve Real-Time Response (RTR / Remote Shell) oturum geçmişini denetleyin.",
                "Yeni API anahtarını yalnızca temiz ve resmi lisanslı yeni FortiSOAR cihazı devreye alındıktan sonra en az yetki (Least Privilege) ilkesiyle üretin.",
            ],
        }
    } else if combined.contains("fortigate")
        || combined.contains("fortimanager")
        || combined.contains("fortianalyzer")
        || combined.contains("fortisiem")
        || combined.contains("paloalto")
        || combined.contains("pan-os")
    {
        EnterprisePlatformProfile {
            default_label: "Güvenlik Duvarı ve Ağ Güvenliği (FortiGate / FortiManager)",
            category: "Ağ Güvenliği ve Güvenlik Duvarı (NGFW)",
            base_urgency: RotationUrgency::P0IdentityAndSecurityFabric,
            default_cred_fields: &[
                "api_key (FortiOS REST API Admin Token)",
                "password (Yönetici / ADOM Servis Parolası)",
            ],
            rotation_steps: &[
                "FortiGate / FortiManager üzerinde SOAR entegrasyonuna ait `config system api-user` API anahtarını silip yenileyin (`execute api-user generate-key`).",
                "`trusthost1` kısıtlamasını kırık FortiSOAR IP'sini dışlayacak şekilde güncelleyin; yetkisiz eklenmiş `super_admin` ve `config system auto-script` kayıtlarını temizleyin.",
                "Son 30 günde REST API üzerinden basılmış güvenlik duvarı kural değişikliklerini ve yapılandırma yedekleme (`execute backup`) çağrılarını inceleyin.",
            ],
        }
    } else if combined.contains("splunk")
        || combined.contains("qradar")
        || combined.contains("elastic")
        || combined.contains("sentinel")
        || combined.contains("arcsight")
    {
        EnterprisePlatformProfile {
            default_label: "Merkezi SIEM / Log Platformu (Splunk / QRadar / Elastic)",
            category: "Güvenlik İzleme ve Log Yönetimi (SIEM)",
            base_urgency: RotationUrgency::P1EnterpriseCorePlatform,
            default_cred_fields: &[
                "auth_token / api_key (SIEM REST & HEC Bearer Token)",
                "password (SIEM Sorgu Servis Hesabı)",
            ],
            rotation_steps: &[
                "SIEM üzerindeki SOAR servis hesabı parolasını ve HTTP Event Collector (HEC) / REST Bearer tokenlarını iptal edin.",
                "Kırık SOAR cihazından gelen sorgu geçmişini ve olası korelasyon kuralı kapatma / log silme (`| delete`) girişimlerini denetleyin.",
            ],
        }
    } else if combined.contains("exchange")
        || combined.contains("office365")
        || combined.contains("o365")
        || combined.contains("graph")
        || combined.contains("smtp")
        || combined.contains("imap")
    {
        EnterprisePlatformProfile {
            default_label: "Kurumsal E-Posta ve Mesajlaşma (Microsoft Exchange / Graph)",
            category: "Kurumsal E-Posta ve İşbirliği (Exchange / M365)",
            base_urgency: RotationUrgency::P1EnterpriseCorePlatform,
            default_cred_fields: &[
                "client_secret / password (EWS / Microsoft Graph Uygulama Sırrı)",
            ],
            rotation_steps: &[
                "Entra ID (Azure AD) App Registration üzerindeki `Application.ReadWrite` / `Mail.ReadWrite` izinli `client_secret` ve sertifikaları derhal silin; EWS servis hesabının parolasını sıfırlayın.",
                "Posta kutularında gizli yönlendirme kurallarını (`Inbox Rules` / `Transport Rules`) ve eDiscovery dışa aktarımlarını kontrol edin.",
            ],
        }
    } else if combined.contains("aws")
        || combined.contains("azure")
        || combined.contains("gcp")
        || combined.contains("vault")
        || combined.contains("cyberark")
        || combined.contains("servicenow")
        || combined.contains("jira")
    {
        EnterprisePlatformProfile {
            default_label: "Bulut / Kasa / ITSM Entegrasyonu",
            category: "Bulut Altyapısı, PAM ve ITSM",
            base_urgency: RotationUrgency::P1EnterpriseCorePlatform,
            default_cred_fields: &[
                "secret_access_key / api_token (Bulut IAM veya ITSM API Anahtarı)",
            ],
            rotation_steps: &[
                "İlgili bulut IAM Access Key (`AKIA...`), Service Principal sırrı veya ITSM API tokenını yönetim konsolundan pasife alıp silin.",
                "CloudTrail / Activity Log üzerinden bu kimlikle yapılan yetki veya gizli veri okuma çağrılarını inceleyin.",
            ],
        }
    } else {
        EnterprisePlatformProfile {
            default_label: "Harici SOAR Konnektörü / Tehdit İstihbaratı API",
            category: "Tehdit İstihbaratı ve Harici API Entegrasyonu",
            base_urgency: RotationUrgency::P2ExternalApiIntegration,
            default_cred_fields: &["api_key / password (Konnektör API Anahtarı veya Parolası)"],
            rotation_steps: &[
                "Üretici portalından mevcut API anahtarını iptal edin (Revoke); sorgu kotası suistimali veya veri sızıntısı için API erişim günlüklerini kontrol edin.",
                "Yeni API anahtarını yalnızca temiz kurulmuş FortiSOAR cihazındaki resmi imzalı konnektöre tanımlayın.",
            ],
        }
    }
}

fn build_vault_rekey_procedure(shared_vault_key: bool, active_skimmer: bool) -> Vec<String> {
    let mut steps = Vec::new();
    steps.push(
        "1. MEVCUT KIRIK CİHAZDA YERİNDE (IN-PLACE) ROTASYON YAPMAYIN: Kırılmış cihazda `SECRET_KEY`, PAM, PostgreSQL veya konnektör katmanı ele geçirildiğinden yeni parolaları asla mevcut cihaza girmeyin."
            .to_string(),
    );
    if shared_vault_key {
        steps.push(
            "2. ORTAK KASA ANAHTARI İHLALİ (`CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY`): Mevcut PostgreSQL veritabanı yedeklerindeki şifreli kimlik bilgileri de sızan `SECRET_KEY` ile çevrimdışı çözülebilir; tüm kurumsal sırları geri dönülmez biçimde İFŞA OLMUŞ kabul edin."
                .to_string(),
        );
    }
    if active_skimmer {
        steps.push(
            "3. AKTİF SKIMMER İHLALİ (`CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER`): `P0_IMMEDIATE_ACTIVE_SKIMMER` olarak işaretlenen konnektörlerin API anahtarlarını ağ karantinasıyla eşzamanlı olarak ilk 15 dakika içinde iptal edin."
                .to_string(),
        );
    }
    steps.push(
        "4. TEMİZ KURULUM VE BENZERSİZ KASA ANAHTARI: Fortinet destek portalından SHA-256 özeti doğrulanmış resmi FortiSOAR OVA/qcow2 imajını izole VLAN'da sıfırdan kurun; `initdb` (`pg_control` ID) ve kasa `SECRET_KEY` / KMS anahtarlarının benzersiz üretildiğini `fsr-forensic-verdict` (0 bulgu) ile doğrulayın."
            .to_string(),
    );
    steps.push(
        "5. YENİ KİMLİK BİLGİLERİNİ TANIMLAMA: Yalnızca hedef kurumsal sistemlerde eski anahtarlar tamamen iptal edildikten ve konnektörler resmi Fortinet Content Hub üzerinden imzalı olarak indirildikten sonra yeni API anahtarlarını yeni kasaya girin."
            .to_string(),
    );
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_reads_secret_values_and_builds_prioritized_inventory() {
        let tmp = std::env::temp_dir().join(format!("fsr_vault_inv_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);

        let ad_dir = tmp.join("opt/cyops-integrations/integrations/connectors/active-directory_3_2_0");
        let cs_dir = tmp.join("opt/cyops-integrations/integrations/connectors/crowdstrike_2_0_0");
        fs::create_dir_all(&ad_dir).unwrap();
        fs::create_dir_all(&cs_dir).unwrap();

        // Include a realistic `info.json` with a `default` secret decoy to prove we ONLY extract schema names!
        let decoy_secret = "SUPER_SECRET_DO_NOT_EVER_EMIT_998877";
        fs::write(
            ad_dir.join("info.json"),
            format!(
                r#"{{
                  "name": "active-directory",
                  "label": "Microsoft Active Directory",
                  "version": "3.2.0",
                  "publisher": "Fortinet",
                  "configuration": {{
                    "fields": [
                      {{"name": "ip", "title": "Domain Controller IP", "type": "text"}},
                      {{"name": "password", "title": "Bind Password", "type": "password", "default": "{}"}}
                    ]
                  }}
                }}"#,
                decoy_secret
            ),
        )
        .unwrap();

        fs::write(
            cs_dir.join("info.json"),
            r#"{"name": "crowdstrike", "label": "CrowdStrike Falcon", "version": "2.0.0", "publisher": "Tampered"}"#,
        )
        .unwrap();
        fs::write(
            cs_dir.join("operations.py"),
            "def execute(config):\n    tok = config.get('client_secret')\n",
        )
        .unwrap();

        let bundle_json = r#"{
          "schema_version": "1.0.0",
          "findings": [
            {
              "code": "CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY",
              "target": "soar_vault_hmac:1234",
              "severity": "CRITICAL"
            },
            {
              "code": "CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER",
              "target": "/opt/cyops-integrations/integrations/connectors/crowdstrike_2_0_0/operations.py",
              "severity": "CRITICAL",
              "evidence": {"connector": "crowdstrike"}
            }
          ]
        }"#;
        let doc = parse_json_str(bundle_json).unwrap();
        let inv = build_compromised_vault_inventory(&doc, Some(&tmp));

        assert!(inv.emergency_rotation_required);
        assert!(inv.shared_vault_master_key_compromised);
        assert!(inv.active_connector_skimmer_detected);
        assert_eq!(inv.secrets_read_count, 0);
        assert_eq!(inv.emergency_revocation_list.len(), 2);

        // CrowdStrike has an active skimmer so it MUST sort first as `P0ImmediateActiveBreach`
        assert_eq!(inv.emergency_revocation_list[0].connector_id, "crowdstrike");
        assert!(inv.emergency_revocation_list[0].actively_skimmed);
        assert_eq!(
            inv.emergency_revocation_list[0].urgency,
            RotationUrgency::P0ImmediateActiveBreach
        );

        assert_eq!(
            inv.emergency_revocation_list[1].connector_id,
            "active-directory"
        );
        let serialized = inv.to_json().to_json_string(true);
        assert!(
            !serialized.contains(decoy_secret),
            "inventory must NEVER emit secret/default values"
        );

        let _ = fs::remove_dir_all(&tmp);
    }
}
