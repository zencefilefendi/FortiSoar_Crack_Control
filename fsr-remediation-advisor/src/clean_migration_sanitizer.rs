//! Module 3: Safe SOAR Playbook & Workflow Clean Migration Sanitizer
//! (`clean_migration_sanitizer.rs`).
//!
//! Enables an organization to salvage years of custom FortiSOAR Playbooks without
//! carrying supply-chain backdoors into a newly provisioned, legitimately licensed
//! FortiSOAR appliance:
//!   1. Parses FortiSOAR Playbook Collection exports (`workflow_collections`),
//!      multi-workflow bundles, standalone Workflow JSONs, and `.jinja2` templates.
//!   2. Inspects every workflow step (`arguments`, `script`, `code`, Jinja2 filters,
//!      and connector bindings) for Jinja2 SSTI sandbox escapes (`__subclasses__`,
//!      `__globals__`, `lipsum`), Python execution/obfuscation (`eval`, `exec`,
//!      `subprocess`, `marshal.loads`, `b64decode`), host vault reads (`settings.py`),
//!      hardcoded C2 IP sinks, and references to actively skimmed connectors.
//!   3. Emits a quarantined step-by-step anomaly list AND a cryptographic **SHA-256
//!      Clean Playbook Manifest** (`sha256sum -c` compatible) containing **strictly**
//!      verified clean workflows approved for import onto the new appliance.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use fsr_clone_cluster_audit::birthmark_extractor::{display_under_root, join_rooted};
use fsr_clone_cluster_audit::json_parser::{json_as_array, json_as_str, json_get, parse_json_str};
use fsr_deep_audit::crypto::sha256_hex;
use fsr_deep_audit::schema::JsonValue;

/// Specific injection or backdoor hazard flagged inside a Playbook step.
#[derive(Debug, Clone)]
pub struct PlaybookHazardFlag {
    pub workflow_name: String,
    pub step_name: String,
    pub rule_code: &'static str,
    pub reason_tr: String,
    pub expression_preview: String,
}

impl PlaybookHazardFlag {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            (
                "workflow_name".to_string(),
                JsonValue::str(&self.workflow_name),
            ),
            ("step_name".to_string(), JsonValue::str(&self.step_name)),
            ("rule_code".to_string(), JsonValue::str(self.rule_code)),
            ("reason_tr".to_string(), JsonValue::str(&self.reason_tr)),
            (
                "expression_preview".to_string(),
                JsonValue::str(&self.expression_preview),
            ),
        ])
    }
}

/// Verified clean Playbook export entry approved for migration to a fresh FortiSOAR node.
#[derive(Debug, Clone)]
pub struct ApprovedPlaybookManifestEntry {
    pub path: String,
    pub sha256_hex: String,
    pub size_bytes: u64,
    pub workflow_names: Vec<String>,
    pub total_steps_verified: usize,
}

impl ApprovedPlaybookManifestEntry {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("path".to_string(), JsonValue::str(&self.path)),
            ("sha256_hex".to_string(), JsonValue::str(&self.sha256_hex)),
            ("size_bytes".to_string(), JsonValue::Uint(self.size_bytes)),
            (
                "workflow_names".to_string(),
                JsonValue::Array(
                    self.workflow_names
                        .iter()
                        .map(|n| JsonValue::str(n.as_str()))
                        .collect(),
                ),
            ),
            (
                "total_steps_verified".to_string(),
                JsonValue::Uint(self.total_steps_verified as u64),
            ),
            (
                "migration_status".to_string(),
                JsonValue::str("APPROVED_CLEAN_FOR_MIGRATION"),
            ),
        ])
    }
}

/// Quarantined Playbook file blocked from automatic migration due to detected hazards.
#[derive(Debug, Clone)]
pub struct QuarantinedPlaybookEntry {
    pub path: String,
    pub sha256_hex: String,
    pub size_bytes: u64,
    pub hazards: Vec<PlaybookHazardFlag>,
}

impl QuarantinedPlaybookEntry {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("path".to_string(), JsonValue::str(&self.path)),
            ("sha256_hex".to_string(), JsonValue::str(&self.sha256_hex)),
            ("size_bytes".to_string(), JsonValue::Uint(self.size_bytes)),
            (
                "migration_status".to_string(),
                JsonValue::str("QUARANTINED_DO_NOT_IMPORT"),
            ),
            (
                "hazards".to_string(),
                JsonValue::Array(self.hazards.iter().map(|h| h.to_json()).collect()),
            ),
        ])
    }
}

/// Complete output of Module 3 (`clean_migration_sanitizer`).
#[derive(Debug, Clone)]
pub struct CleanMigrationPlan {
    pub total_playbook_files_inspected: usize,
    pub approved_clean_count: usize,
    pub quarantined_count: usize,
    pub approved_clean_manifest: Vec<ApprovedPlaybookManifestEntry>,
    pub quarantined_playbooks: Vec<QuarantinedPlaybookEntry>,
    pub sha256sum_manifest_text: String,
    pub migration_guide_steps_tr: Vec<String>,
}

impl CleanMigrationPlan {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            (
                "total_playbook_files_inspected".to_string(),
                JsonValue::Uint(self.total_playbook_files_inspected as u64),
            ),
            (
                "approved_clean_count".to_string(),
                JsonValue::Uint(self.approved_clean_count as u64),
            ),
            (
                "quarantined_count".to_string(),
                JsonValue::Uint(self.quarantined_count as u64),
            ),
            (
                "approved_clean_manifest".to_string(),
                JsonValue::Array(
                    self.approved_clean_manifest
                        .iter()
                        .map(|e| e.to_json())
                        .collect(),
                ),
            ),
            (
                "quarantined_playbooks".to_string(),
                JsonValue::Array(
                    self.quarantined_playbooks
                        .iter()
                        .map(|q| q.to_json())
                        .collect(),
                ),
            ),
            (
                "sha256sum_manifest_text".to_string(),
                JsonValue::str(&self.sha256sum_manifest_text),
            ),
            (
                "migration_guide_steps_tr".to_string(),
                JsonValue::Array(
                    self.migration_guide_steps_tr
                        .iter()
                        .map(|s| JsonValue::str(s.as_str()))
                        .collect(),
                ),
            ),
        ])
    }
}

/// Scans Playbook exports under `effective_root` and `extra_playbook_paths`, separating
/// clean workflows (with a cryptographic SHA-256 import manifest) from injected/tainted ones.
pub fn build_clean_migration_plan(
    effective_root: Option<&Path>,
    extra_playbook_paths: &[PathBuf],
    known_hostile_ips: &BTreeSet<Ipv4Addr>,
    actively_skimmed_connectors: &BTreeSet<String>,
) -> CleanMigrationPlan {
    let mut candidate_files: Vec<PathBuf> = Vec::new();

    if let Some(root) = effective_root {
        for rel in [
            "opt/cyops-workflow",
            "opt/cyops/playbooks",
            "etc/cyops-workflow",
            "var/tmp/playbooks",
        ] {
            let dir = join_rooted(root, rel);
            if dir.is_dir() {
                collect_playbook_files(&dir, 6, &mut candidate_files);
            }
        }
    }

    for extra in extra_playbook_paths {
        if extra.is_dir() {
            collect_playbook_files(extra, 6, &mut candidate_files);
        } else if extra.is_file() {
            candidate_files.push(extra.clone());
        }
    }

    candidate_files.sort();
    candidate_files.dedup();

    let mut approved_clean_manifest = Vec::new();
    let mut quarantined_playbooks = Vec::new();

    for path in &candidate_files {
        let Ok(raw_bytes) = fs::read(path) else {
            continue;
        };
        if raw_bytes.len() > 8 * 1024 * 1024 {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&raw_bytes) else {
            continue;
        };

        let display_path = match effective_root {
            Some(r) => display_under_root(r, path),
            None => path.to_string_lossy().into_owned(),
        };
        let digest = sha256_hex(&raw_bytes);
        let size_bytes = raw_bytes.len() as u64;

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let (workflow_names, total_steps, hazards) = if ext == "json" {
            inspect_playbook_json(&display_path, text, known_hostile_ips, actively_skimmed_connectors)
        } else {
            let mut hz = Vec::new();
            inspect_expression_for_hazards(
                &display_path,
                "<template>",
                text,
                known_hostile_ips,
                &mut hz,
            );
            (vec![display_path.clone()], 1, hz)
        };

        // Ignore JSON files under `opt/cyops-workflow` that are unrelated system config/schema
        // unless they were explicitly supplied via `extra_playbook_paths` or look like workflows
        if workflow_names.is_empty() && hazards.is_empty() && !extra_playbook_paths.contains(path) {
            continue;
        }

        if hazards.is_empty() {
            let wf_names = if workflow_names.is_empty() {
                vec![display_path.clone()]
            } else {
                workflow_names
            };
            approved_clean_manifest.push(ApprovedPlaybookManifestEntry {
                path: display_path,
                sha256_hex: digest,
                size_bytes,
                workflow_names: wf_names,
                total_steps_verified: total_steps,
            });
        } else {
            quarantined_playbooks.push(QuarantinedPlaybookEntry {
                path: display_path,
                sha256_hex: digest,
                size_bytes,
                hazards,
            });
        }
    }

    let mut sha256sum_manifest_text = String::new();
    for entry in &approved_clean_manifest {
        let _ = writeln!(
            sha256sum_manifest_text,
            "{}  {}",
            entry.sha256_hex, entry.path
        );
    }

    let total_playbook_files_inspected =
        approved_clean_manifest.len() + quarantined_playbooks.len();
    let approved_clean_count = approved_clean_manifest.len();
    let quarantined_count = quarantined_playbooks.len();

    let migration_guide_steps_tr = build_migration_guide_steps(
        approved_clean_count,
        quarantined_count,
        !actively_skimmed_connectors.is_empty(),
    );

    CleanMigrationPlan {
        total_playbook_files_inspected,
        approved_clean_count,
        quarantined_count,
        approved_clean_manifest,
        quarantined_playbooks,
        sha256sum_manifest_text,
        migration_guide_steps_tr,
    }
}

fn collect_playbook_files(dir: &Path, depth_left: usize, out: &mut Vec<PathBuf>) {
    if depth_left == 0 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        let p = entry.path();
        if ft.is_dir() && !ft.is_symlink() {
            let dname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if dname == "__pycache__" || dname == "node_modules" || dname == "migrations" {
                continue;
            }
            collect_playbook_files(&p, depth_left - 1, out);
        } else if ft.is_file() {
            let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(
                fname,
                "info.json" | "package.json" | "package-lock.json" | "tsconfig.json" | "MANIFEST.json"
            ) {
                continue;
            }
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if matches!(ext.as_str(), "json" | "jinja" | "jinja2" | "j2") {
                out.push(p);
            }
        }
    }
}

fn inspect_playbook_json(
    file_label: &str,
    raw_text: &str,
    known_hostile_ips: &BTreeSet<Ipv4Addr>,
    actively_skimmed_connectors: &BTreeSet<String>,
) -> (Vec<String>, usize, Vec<PlaybookHazardFlag>) {
    let Ok(doc) = parse_json_str(raw_text) else {
        let mut hz = vec![PlaybookHazardFlag {
            workflow_name: file_label.to_string(),
            step_name: "<json_parser>".to_string(),
            rule_code: "MALFORMED_PLAYBOOK_JSON",
            reason_tr: "Bozuk veya geçersiz JSON sözdizimi — güvenli göç manifestosuna dahil edilmedi".to_string(),
            expression_preview: truncate_preview(raw_text, 100),
        }];
        inspect_expression_for_hazards(file_label, "<raw>", raw_text, known_hostile_ips, &mut hz);
        return (vec![file_label.to_string()], 0, hz);
    };

    let mut workflow_nodes: Vec<&JsonValue> = Vec::new();
    collect_workflow_objects(&doc, &mut workflow_nodes);

    if workflow_nodes.is_empty() {
        return (Vec::new(), 0, Vec::new());
    }

    let mut workflow_names = Vec::with_capacity(workflow_nodes.len());
    let mut total_steps = 0usize;
    let mut hazards = Vec::new();

    for wf in workflow_nodes {
        let wf_name = json_get(wf, "name")
            .and_then(json_as_str)
            .unwrap_or(file_label)
            .to_string();
        workflow_names.push(wf_name.clone());

        if let Some(steps) = json_get(wf, "steps").and_then(json_as_array) {
            for (idx, step) in steps.iter().enumerate() {
                total_steps += 1;
                let default_step_name = format!("step_{}", idx + 1);
                let step_name = json_get(step, "name")
                    .and_then(json_as_str)
                    .unwrap_or(&default_step_name)
                    .to_string();

                // Check if this step calls an actively skimmed connector
                let step_conn = json_get(step, "connector")
                    .and_then(json_as_str)
                    .or_else(|| {
                        json_get(step, "arguments")
                            .and_then(|a| json_get(a, "connector"))
                            .and_then(json_as_str)
                    });
                if let Some(c_slug) = step_conn {
                    if actively_skimmed_connectors.contains(&c_slug.to_ascii_lowercase()) {
                        hazards.push(PlaybookHazardFlag {
                            workflow_name: wf_name.clone(),
                            step_name: step_name.clone(),
                            rule_code: "QUARANTINE_TAINTED_CONNECTOR_STEP",
                            reason_tr: format!(
                                "Adım, kimlik bilgisi sızdırdığı kanıtlanan `{}` konnektörünü çağırıyor — konnektör resmi Content Hub sürümüyle sıfırdan kurulmadan içe aktarılamaz",
                                c_slug
                            ),
                            expression_preview: format!("connector={}", c_slug),
                        });
                    }
                }

                // Walk all strings inside the step (`arguments`, `config`, `script`, etc.)
                let mut step_strings = Vec::new();
                collect_all_strings(step, &mut step_strings);
                for expr in &step_strings {
                    inspect_expression_for_hazards(
                        &wf_name,
                        &step_name,
                        expr,
                        known_hostile_ips,
                        &mut hazards,
                    );
                }
            }
        } else {
            let mut wf_strings = Vec::new();
            collect_all_strings(wf, &mut wf_strings);
            for expr in &wf_strings {
                inspect_expression_for_hazards(
                    &wf_name,
                    "<workflow_root>",
                    expr,
                    known_hostile_ips,
                    &mut hazards,
                );
            }
        }
    }

    (workflow_names, total_steps, hazards)
}

/// Recursively locates FortiSOAR Workflow objects inside single exports, `workflows` arrays,
/// `playbooks` arrays, or `workflow_collections` (`data[*].workflows[*]`).
fn collect_workflow_objects<'a>(node: &'a JsonValue, out: &mut Vec<&'a JsonValue>) {
    let is_wf = json_get(node, "@type")
        .and_then(json_as_str)
        .map(|t| t.eq_ignore_ascii_case("Workflow") || t.eq_ignore_ascii_case("Playbook"))
        .unwrap_or(false)
        || (json_get(node, "steps").and_then(json_as_array).is_some()
            && json_get(node, "name").and_then(json_as_str).is_some());

    if is_wf {
        out.push(node);
        return;
    }

    for container_key in ["data", "workflows", "playbooks", "collections"] {
        if let Some(arr) = json_get(node, container_key).and_then(json_as_array) {
            for item in arr {
                collect_workflow_objects(item, out);
            }
        }
    }
}

fn collect_all_strings(node: &JsonValue, out: &mut Vec<String>) {
    match node {
        JsonValue::Str(s) => out.push(s.clone()),
        JsonValue::Array(arr) => {
            for v in arr {
                collect_all_strings(v, out);
            }
        }
        JsonValue::OrderedObject(fields) => {
            for (_, v) in fields {
                collect_all_strings(v, out);
            }
        }
        _ => {}
    }
}

fn inspect_expression_for_hazards(
    workflow_name: &str,
    step_name: &str,
    expr: &str,
    known_hostile_ips: &BTreeSet<Ipv4Addr>,
    hazards: &mut Vec<PlaybookHazardFlag>,
) {
    let lower = expr.to_ascii_lowercase();

    // 1. Jinja2 SSTI & Object Graph Sandbox Escapes
    for gadget in [
        "__subclasses__",
        "__globals__",
        "__builtins__",
        "__mro__",
        "__import__",
        "cycler.__init__",
        "joiner.__init__",
        "namespace.__init__",
        "lipsum.__globals__",
        "request.application",
    ] {
        if lower.contains(gadget) {
            hazards.push(PlaybookHazardFlag {
                workflow_name: workflow_name.to_string(),
                step_name: step_name.to_string(),
                rule_code: "CRITICAL_PLAYBOOK_JINJA2_SANDBOX_ESCAPE",
                reason_tr: format!(
                    "Playbook ifadesinde Jinja2 kum havuzu kaçışı (SSTI gadget `{}`) tespit edildi",
                    gadget
                ),
                expression_preview: truncate_preview(expr, 110),
            });
            return;
        }
    }

    // 2. Arbitrary Python / Shell Code Execution & Obfuscation Sinks
    for py_sink in [
        "os.system(",
        "os.popen(",
        "subprocess.popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_output",
        "eval(",
        "exec(",
        "marshal.loads",
        "pickle.loads",
        "pty.spawn",
        "base64.b64decode",
        "urlsafe_b64decode",
        "zlib.decompress",
        "bytes.fromhex(",
        "/dev/tcp/",
        "| sh",
        "| bash",
    ] {
        if lower.contains(py_sink) {
            hazards.push(PlaybookHazardFlag {
                workflow_name: workflow_name.to_string(),
                step_name: step_name.to_string(),
                rule_code: "CRITICAL_PLAYBOOK_CODE_EXEC_OR_OBFUSCATION",
                reason_tr: format!(
                    "Playbook adımında gizlenmiş yük veya doğrudan işletim sistemi/Python kod yürütme çağrısı (`{}`) tespit edildi",
                    py_sink
                ),
                expression_preview: truncate_preview(expr, 110),
            });
            return;
        }
    }

    // 3. Appliance Secret / Host File Access
    for secret_path in [
        "sealab/settings.py",
        "/etc/shadow",
        "/etc/ld.so.preload",
        "/proc/self/environ",
        "secret_key",
    ] {
        if lower.contains(secret_path) && (lower.contains("open(") || lower.contains("{{") || lower.contains("{%")) {
            hazards.push(PlaybookHazardFlag {
                workflow_name: workflow_name.to_string(),
                step_name: step_name.to_string(),
                rule_code: "CRITICAL_PLAYBOOK_APPLIANCE_SECRET_READ",
                reason_tr: format!(
                    "Playbook ifadesi cihazın iç sırlarını veya sistem dosyalarını (`{}`) okumaya çalışıyor",
                    secret_path
                ),
                expression_preview: truncate_preview(expr, 110),
            });
            return;
        }
    }

    // 4. Hardcoded External IP URLs or Known Hostile C2 IPs
    if lower.contains("http://") || lower.contains("https://") || lower.contains("tftp://") {
        for tok in expr.split(|c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '(' | ')')) {
            if let Some((_, rest)) = tok.split_once("://") {
                let host_port = rest.split('/').next().unwrap_or(rest);
                let host = host_port.split(':').next().unwrap_or(host_port);
                if let Ok(ip) = host.parse::<Ipv4Addr>() {
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        let is_known_c2 = known_hostile_ips.contains(&ip);
                        hazards.push(PlaybookHazardFlag {
                            workflow_name: workflow_name.to_string(),
                            step_name: step_name.to_string(),
                            rule_code: if is_known_c2 {
                                "CRITICAL_PLAYBOOK_KNOWN_C2_ENDPOINT"
                            } else {
                                "HIGH_PLAYBOOK_HARDCODED_IP_URL"
                            },
                            reason_tr: format!(
                                "Playbook adımı doğrudan IP adresli dış hedefe (`{}`) bağlanıyor{}",
                                ip,
                                if is_known_c2 {
                                    " (ihlal bulgularındaki C2 IP'si ile eşleşti!)"
                                } else {
                                    ""
                                }
                            ),
                            expression_preview: truncate_preview(expr, 110),
                        });
                        return;
                    }
                }
            }
        }
    }
}

fn truncate_preview(s: &str, max_chars: usize) -> String {
    let single_line: String = s
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    let trimmed = single_line.trim();
    if trimmed.chars().count() <= max_chars {
        trimmed.to_string()
    } else {
        let prefix: String = trimmed.chars().take(max_chars).collect();
        format!("{}...", prefix)
    }
}

fn build_migration_guide_steps(
    approved_count: usize,
    quarantined_count: usize,
    has_skimmed_connectors: bool,
) -> Vec<String> {
    let mut steps = vec![
        "1. VERİTABANI İMAJINI VEYA TAM YEDEĞİ (`pg_dump` / OVA) ASLA TAŞIMAYIN: Klonlanmış `pg_control` kimliği, PostgreSQL tetikleyicileri ve kırık `SECRET_KEY` yeni cihaza taşınmamalıdır; yalnızca bu raporda onaylanan JSON Playbook tanımları taşınmalıdır.".to_string(),
        format!(
            "2. KRİPTOGRAFİK MANİFESTO DOĞRULAMASI ({} Onaylı / {} Karantinada): Onaylı Playbook dosyalarını yeni FortiSOAR yönetim istasyonuna aktardıktan sonra içe aktarma (Import) öncesinde `sha256sum -c clean_playbooks.sha256` komutuyla özetlerin birebir eşleştiğini doğrulayın.",
            approved_count, quarantined_count
        ),
        "3. ÖNCE RESMİ KONNEKTÖRLERİ KURUN: Yeni lisanslı FortiSOAR cihazında konnektörleri eski cihazdan dışa AKTARMAYIN; tüm konnektörleri doğrudan resmi Fortinet Content Hub (`yum.fortisoar.fortinet.com`) üzerinden GPG/RSA imzalı olarak kurun.".to_string(),
    ];
    if has_skimmed_connectors {
        steps.push(
            "4. KARANTİNADAKİ KONNEKTÖR ADIMLARI: `QUARANTINE_TAINTED_CONNECTOR_STEP` ile işaretlenen iş akışlarını, ilgili konnektör resmi depodan temiz kurulduktan ve yeni API anahtarı tanımlandıktan sonra manuel kod gözden geçirmesiyle devreye alın.".to_string(),
        );
    }
    if quarantined_count > 0 {
        steps.push(
            "5. KARANTİNADAKİ PLAYBOOK'LARIN TEMİZLENMESİ: `QUARANTINED_DO_NOT_IMPORT` statüsündeki Playbook'ları doğrudan yeni cihaza yüklemeyin; raporda belirtilen `step_name` içindeki Jinja2 SSTI / Python `eval`/`b64decode` ifadelerini izole bir metin editöründe temizleyip `fsr-remediation-advisor` ile yeniden taratın.".to_string(),
        );
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_clean_playbooks_with_sha256_manifest_from_jinja2_and_python_injections() {
        let tmp = std::env::temp_dir().join(format!("fsr_mig_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let wf_dir = tmp.join("opt/cyops-workflow/exports");
        fs::create_dir_all(&wf_dir).unwrap();

        let clean_pb = r#"{
          "type": "workflow_collections",
          "data": [{
            "@type": "WorkflowCollection",
            "name": "SOC Phishing Triage",
            "workflows": [{
              "@type": "Workflow",
              "name": "Enrich Sender Domain",
              "steps": [
                {
                  "name": "Lookup Domain Reputation",
                  "connector": "virustotal",
                  "arguments": {
                    "domain": "{{ vars.input.records[0].sender_domain }}"
                  }
                }
              ]
            }]
          }]
        }"#;
        let clean_path = wf_dir.join("01_clean_phishing_triage.json");
        fs::write(&clean_path, clean_pb).unwrap();
        let expected_clean_sha = sha256_hex(clean_pb.as_bytes());

        let dirty_pb = r#"{
          "@type": "Workflow",
          "name": "Backdoored Alert Handler",
          "steps": [
            {
              "name": "Stealth Jinja Escape",
              "arguments": {
                "payload": "{{ ''.__class__.__mro__[1].__subclasses__()[132] }}"
              }
            },
            {
              "name": "Python Eval Dropper",
              "arguments": {
                "code": "eval(base64.b64decode('aW1wb3J0IG9z'))"
              }
            }
          ]
        }"#;
        fs::write(wf_dir.join("02_backdoored_handler.json"), dirty_pb).unwrap();

        let hostile_ips = BTreeSet::new();
        let skimmed = BTreeSet::new();
        let plan = build_clean_migration_plan(Some(&tmp), &[], &hostile_ips, &skimmed);

        assert_eq!(plan.total_playbook_files_inspected, 2);
        assert_eq!(plan.approved_clean_count, 1);
        assert_eq!(plan.quarantined_count, 1);

        assert_eq!(plan.approved_clean_manifest[0].sha256_hex, expected_clean_sha);
        assert_eq!(
            plan.approved_clean_manifest[0].workflow_names,
            vec!["Enrich Sender Domain".to_string()]
        );
        assert!(plan.sha256sum_manifest_text.contains(&expected_clean_sha));

        let hz_codes: Vec<&str> = plan.quarantined_playbooks[0]
            .hazards
            .iter()
            .map(|h| h.rule_code)
            .collect();
        assert!(hz_codes.contains(&"CRITICAL_PLAYBOOK_JINJA2_SANDBOX_ESCAPE"));
        assert!(hz_codes.contains(&"CRITICAL_PLAYBOOK_CODE_EXEC_OR_OBFUSCATION"));

        let _ = fs::remove_dir_all(&tmp);
    }
}
