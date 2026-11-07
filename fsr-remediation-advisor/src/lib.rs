//! `fsr-remediation-advisor`: Deterministic DFIR Incident Response, Compromised SOAR
//! Vault Credential Rotation, Non-Destructive Network Containment, Clean Playbook
//! Migration Sanitizer, and Air-Gapped Auditor Self-Integrity Armor.
//!
//! Ingests a sealed `ForensicVerdictBundle` JSON envelope produced by `fsr-forensic-verdict`
//! alongside read-only connector/playbook metadata, producing four operational deliverables:
//!   1. `compromised_vault_inventory` — Emergency enterprise API key & service account
//!      revocation/rotation matrix (strictly metadata-only, zero password reading).
//!   2. `containment_commands` — Live non-destructive `nftables`, `iptables`, FortiOS CLI,
//!      and `/proc/<pid>/maps` volatile-evidence preservation commands (zero reboot).
//!   3. `clean_migration_sanitizer` — FortiSOAR Playbook Jinja2/Python injection quarantine
//!      and cryptographic `sha256sum -c` Clean Playbook Migration Manifest.
//!   4. `self_integrity` — Field USB/ISO `/proc/self/exe` dual-path SHA-256 & runtime
//!      `LD_PRELOAD` / `LD_LIBRARY_PATH` anti-subversion armor with Safe Hardened Mode.

pub mod clean_migration_sanitizer;
pub mod compromised_vault_inventory;
pub mod containment_commands;
pub mod self_integrity;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use fsr_clone_cluster_audit::json_parser::{
    json_as_str, json_as_u64, json_get_path, parse_json_str,
};
use fsr_deep_audit::schema::JsonValue;

use crate::clean_migration_sanitizer::{build_clean_migration_plan, CleanMigrationPlan};
use crate::compromised_vault_inventory::{
    build_compromised_vault_inventory, CompromisedVaultInventory,
};
use crate::containment_commands::{build_containment_command_suite, ContainmentCommandSuite};
use crate::self_integrity::{run_startup_self_integrity_guard, SelfIntegrityReport};

/// Supported output formats for the generated Incident Response & Clean Migration Plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemediationOutputFormat {
    Json,
    Markdown,
    Html,
}

impl RemediationOutputFormat {
    pub fn parse_label(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" | "ndjson" => Some(RemediationOutputFormat::Json),
            "md" | "markdown" => Some(RemediationOutputFormat::Markdown),
            "html" | "htm" => Some(RemediationOutputFormat::Html),
            _ => None,
        }
    }
}

/// Configuration for generating a deterministic remediation & migration plan from a
/// `ForensicVerdictBundle` JSON file or in-memory JSON string.
#[derive(Debug, Clone, Default)]
pub struct RemediationAdvisorConfig {
    pub bundle_path: Option<PathBuf>,
    pub bundle_raw_json: Option<String>,
    pub override_root_path: Option<PathBuf>,
    pub extra_playbook_paths: Vec<PathBuf>,
    pub expected_self_sha256: Option<String>,
    pub check_host_ld_so_preload: bool,
}

/// Unified Incident Response, Vault Re-Keying & Clean Migration Plan.
#[derive(Debug, Clone)]
pub struct RemediationPlan {
    pub bundle_source: String,
    pub bundle_merkle_root_hex: String,
    pub target_hostname: String,
    pub target_root_path: String,
    pub verdict_status: String,
    pub composite_risk_score: u32,
    pub self_integrity: SelfIntegrityReport,
    pub compromised_vault_inventory: CompromisedVaultInventory,
    pub containment_commands: ContainmentCommandSuite,
    pub clean_migration_plan: CleanMigrationPlan,
}

impl RemediationPlan {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("schema_version".to_string(), JsonValue::str("1.0.0")),
            (
                "generator".to_string(),
                JsonValue::OrderedObject(vec![
                    (
                        "name".to_string(),
                        JsonValue::str("fsr-remediation-advisor"),
                    ),
                    (
                        "version".to_string(),
                        JsonValue::str(env!("CARGO_PKG_VERSION")),
                    ),
                ]),
            ),
            (
                "source_bundle".to_string(),
                JsonValue::OrderedObject(vec![
                    (
                        "bundle_source".to_string(),
                        JsonValue::str(&self.bundle_source),
                    ),
                    (
                        "bundle_merkle_root_hex".to_string(),
                        JsonValue::str(&self.bundle_merkle_root_hex),
                    ),
                    (
                        "target_hostname".to_string(),
                        JsonValue::str(&self.target_hostname),
                    ),
                    (
                        "target_root_path".to_string(),
                        JsonValue::str(&self.target_root_path),
                    ),
                    (
                        "verdict_status".to_string(),
                        JsonValue::str(&self.verdict_status),
                    ),
                    (
                        "composite_risk_score".to_string(),
                        JsonValue::Uint(self.composite_risk_score as u64),
                    ),
                ]),
            ),
            ("self_integrity".to_string(), self.self_integrity.to_json()),
            (
                "compromised_vault_inventory".to_string(),
                self.compromised_vault_inventory.to_json(),
            ),
            (
                "containment_commands".to_string(),
                self.containment_commands.to_json(),
            ),
            (
                "clean_migration_plan".to_string(),
                self.clean_migration_plan.to_json(),
            ),
        ])
    }
}

/// Executes all 4 remediation modules deterministically over a `ForensicVerdictBundle`.
pub fn generate_remediation_plan(cfg: &RemediationAdvisorConfig) -> Result<RemediationPlan, String> {
    // Module 4 first: verify auditor's own `/proc/self/exe` & runtime environment at startup
    let self_integrity = run_startup_self_integrity_guard(
        "fsr-remediation-advisor",
        cfg.expected_self_sha256.as_deref(),
        cfg.check_host_ld_so_preload,
    );

    let (bundle_source, raw_json) = if let Some(raw) = &cfg.bundle_raw_json {
        (
            cfg.bundle_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| "<in-memory-bundle>".to_string()),
            raw.clone(),
        )
    } else if let Some(p) = &cfg.bundle_path {
        let content = fs::read_to_string(p).map_err(|e| {
            format!(
                "failed to read ForensicVerdictBundle '{}': {}",
                p.display(),
                e
            )
        })?;
        (p.to_string_lossy().into_owned(), content)
    } else {
        return Err(
            "no ForensicVerdictBundle JSON file or payload provided to generate_remediation_plan"
                .to_string(),
        );
    };

    let doc = parse_json_str(raw_json.trim())
        .map_err(|e| format!("invalid ForensicVerdictBundle JSON ({}): {}", bundle_source, e))?;

    let bundle_merkle_root_hex =
        json_get_path(&doc, &["merkle_envelope", "merkle_root_hex"])
            .and_then(json_as_str)
            .unwrap_or("unsealed")
            .to_string();
    let target_hostname = json_get_path(&doc, &["scan_context", "hostname"])
        .and_then(json_as_str)
        .unwrap_or("unknown-appliance")
        .to_string();
    let bundle_root_str = json_get_path(&doc, &["scan_context", "root_path"])
        .and_then(json_as_str)
        .unwrap_or("")
        .to_string();
    let verdict_status = json_get_path(&doc, &["verdict", "status"])
        .and_then(json_as_str)
        .unwrap_or("UNKNOWN")
        .to_string();
    let composite_risk_score = json_get_path(&doc, &["verdict", "composite_risk_score"])
        .or_else(|| json_get_path(&doc, &["verdict", "risk_score"]))
        .and_then(json_as_u64)
        .unwrap_or(0) as u32;

    // Resolve effective `--root` directory (explicit override > bundle's `scan_context.root_path` if mounted)
    let effective_root_buf: Option<PathBuf> = if let Some(ov) = &cfg.override_root_path {
        Some(ov.clone())
    } else if !bundle_root_str.is_empty() && bundle_root_str != "/" {
        let cand = PathBuf::from(&bundle_root_str);
        if cand.is_dir() {
            Some(cand)
        } else {
            None
        }
    } else {
        None
    };
    let effective_root: Option<&Path> = effective_root_buf.as_deref();
    let target_root_path = effective_root
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or(bundle_root_str);

    // Module 1: Compromised SOAR Vault & Enterprise Integration Credential Rotation Inventory
    let compromised_vault_inventory = build_compromised_vault_inventory(&doc, effective_root);

    // Module 2: Live Non-Destructive Network Isolation & Volatile Evidence Preservation Suite
    let containment_commands = build_containment_command_suite(&doc, effective_root);

    // Module 3: Clean Playbook & Workflow Migration Sanitizer (informed by Modules 1 & 2)
    let hostile_ips: BTreeSet<Ipv4Addr> = containment_commands
        .hostile_endpoints
        .iter()
        .map(|e| e.ipv4)
        .collect();
    let skimmed_connectors: BTreeSet<String> = compromised_vault_inventory
        .emergency_revocation_list
        .iter()
        .filter(|e| e.actively_skimmed)
        .map(|e| e.connector_id.to_ascii_lowercase())
        .collect();

    let clean_migration_plan = build_clean_migration_plan(
        effective_root,
        &cfg.extra_playbook_paths,
        &hostile_ips,
        &skimmed_connectors,
    );

    Ok(RemediationPlan {
        bundle_source,
        bundle_merkle_root_hex,
        target_hostname,
        target_root_path,
        verdict_status,
        composite_risk_score,
        self_integrity,
        compromised_vault_inventory,
        containment_commands,
        clean_migration_plan,
    })
}

/// Renders a [`RemediationPlan`] into JSON/NDJSON, Markdown, or self-contained print HTML.
pub fn emit_remediation_plan(
    plan: &RemediationPlan,
    format: RemediationOutputFormat,
    pretty: bool,
) -> String {
    match format {
        RemediationOutputFormat::Json => plan.to_json().to_json_string(pretty),
        RemediationOutputFormat::Markdown => render_remediation_markdown(plan),
        RemediationOutputFormat::Html => render_remediation_html(plan),
    }
}

pub fn render_remediation_markdown(plan: &RemediationPlan) -> String {
    let mut out = String::with_capacity(16384);
    let _ = writeln!(
        out,
        "# Olay Müdahale, Kasa Anahtarı Rotasyonu (Vault Re-Keying) ve Temiz Göç Planı"
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- **Kaynak Kanıt Zarfı:** `{}` (RFC 6962 Merkle Kökü: `{}`)",
        plan.bundle_source, plan.bundle_merkle_root_hex
    );
    let _ = writeln!(
        out,
        "- **Hedef Cihaz:** `{}` (`{}`) | **Adli Hüküm:** **`{}`** (`{}/100`)",
        plan.target_hostname, plan.target_root_path, plan.verdict_status, plan.composite_risk_score
    );
    let _ = writeln!(
        out,
        "- **Denetçi Öz-Doğrulama Zırhı (`/proc/self/exe`):** `{}` (Güvenli Mod: `{}`)",
        plan.self_integrity.self_sha256_libc_hex,
        plan.self_integrity.safe_mode_policy.safe_mode_active
    );
    let _ = writeln!(out);

    // Section 1: Compromised Vault Inventory
    let _ = writeln!(
        out,
        "## 1. Acil İptal Edilmesi ve Yenilenmesi Gereken Kurumsal API Anahtarları ve Servis Hesapları"
    );
    let inv = &plan.compromised_vault_inventory;
    if !inv.emergency_rotation_required {
        let _ = writeln!(
            out,
            "Kasa anahtarı paylaşımı veya konnektör kimlik sızdırma bulgusu tespit edilmedi (Acil rotasyon gerekmiyor)."
        );
    } else {
        let _ = writeln!(
            out,
            "- **Tetikleyici Bulgular:** `{}` (Okunan Parola Sayısı: `{}` — yalnızca yapısal konnektör meta verisi tarandı)",
            inv.triggering_finding_codes.join(", "),
            inv.secrets_read_count
        );
        let _ = writeln!(out);
        for item in &inv.emergency_revocation_list {
            let _ = writeln!(
                out,
                "### [{}] {} (`{}` v`{}`)",
                item.urgency.as_str(),
                item.display_label,
                item.connector_id,
                item.version
            );
            let _ = writeln!(out, "- **Kategori:** {} | **Hedef SLA:** {}", item.enterprise_system_category, item.urgency.sla_window_tr());
            let _ = writeln!(out, "- **İhlal Nedeni:** {}", item.exposure_reason);
            let _ = writeln!(
                out,
                "- **Risk Altındaki Kimlik Alanları:** `{}`",
                item.credential_fields_at_risk.join("`, `")
            );
            for step in &item.revocation_and_rotation_steps_tr {
                let _ = writeln!(out, "  - {}", step);
            }
            let _ = writeln!(out);
        }

        let _ = writeln!(out, "### Kasa Yeniden Anahtarlama (Vault Re-Keying) Prosedürü");
        for s in &inv.vault_rekey_procedure_tr {
            let _ = writeln!(out, "- {}", s);
        }
    }
    let _ = writeln!(out);

    // Section 2: Containment & Evidence Preservation
    let _ = writeln!(
        out,
        "## 2. Canlı Kanıt Koruma ve Ağ İzolasyonu Komut Seti (Sıfır Reboot)"
    );
    let cc = &plan.containment_commands;
    let _ = writeln!(out, "> {}", cc.zero_reboot_mandate_tr);
    let _ = writeln!(out);

    if !cc.volatile_evidence_preservation_commands.is_empty() {
        let _ = writeln!(out, "### 2.1 Uçucu Bellek (`/proc/<pid>/maps`) Koruma Komutları");
        let _ = writeln!(out, "```bash");
        for cmd in &cc.volatile_evidence_preservation_commands {
            let _ = writeln!(out, "{}", cmd);
        }
        let _ = writeln!(out, "```");
    }

    let _ = writeln!(out, "### 2.2 Atomik `nftables` Karantina Kuralları");
    let _ = writeln!(out, "```nft");
    let _ = write!(out, "{}", cc.nftables_quarantine_script);
    let _ = writeln!(out, "```");

    let _ = writeln!(out, "### 2.3 Alternatif `iptables` Karantina Kuralları");
    let _ = writeln!(out, "```bash");
    let _ = write!(out, "{}", cc.iptables_quarantine_script);
    let _ = writeln!(out, "```");

    let _ = writeln!(out, "### 2.4 FortiOS Sınır Güvenlik Duvarı Karantina Komutları");
    let _ = writeln!(out, "```text");
    let _ = write!(out, "{}", cc.fortios_cli_quarantine_script);
    let _ = writeln!(out, "```");
    let _ = writeln!(out);

    // Section 3: Clean Playbook Migration
    let _ = writeln!(
        out,
        "## 3. Güvenli Playbook / İş Akışı Göç Denetimi ve SHA-256 Manifestosu"
    );
    let mp = &plan.clean_migration_plan;
    let _ = writeln!(
        out,
        "- **İncelenen Dosya:** `{}` | **Göçe Onaylı (Temiz):** `{}` | **Karantinaya Alınan (Enjeksiyonlu):** `{}`",
        mp.total_playbook_files_inspected, mp.approved_clean_count, mp.quarantined_count
    );
    if !mp.sha256sum_manifest_text.is_empty() {
        let _ = writeln!(out, "### Onaylı Temiz Playbook `sha256sum -c` Manifestosu");
        let _ = writeln!(out, "```text");
        let _ = write!(out, "{}", mp.sha256sum_manifest_text);
        let _ = writeln!(out, "```");
    }
    if !mp.quarantined_playbooks.is_empty() {
        let _ = writeln!(out, "### Karantinaya Alınan Zararlı / Enjeksiyonlu Playbook'lar");
        for q in &mp.quarantined_playbooks {
            let _ = writeln!(out, "- **`{}`** (SHA-256: `{}`):", q.path, q.sha256_hex);
            for h in &q.hazards {
                let _ = writeln!(
                    out,
                    "  - `[{}]` İş Akışı `{}` -> Adım `{}`: {} (`{}`)",
                    h.rule_code, h.workflow_name, h.step_name, h.reason_tr, h.expression_preview
                );
            }
        }
    }
    let _ = writeln!(out, "### Güvenli Göç Adımları");
    for s in &mp.migration_guide_steps_tr {
        let _ = writeln!(out, "- {}", s);
    }
    let _ = writeln!(out);

    // Section 4: Self-Integrity Armor
    let _ = writeln!(
        out,
        "## 4. Saha Dağıtım ve Denetçi Öz-Doğrulama (Self-Integrity) Zırhı"
    );
    let si = &plan.self_integrity;
    let _ = writeln!(out, "- **Çalıştırılabilir İkili:** `{}`", si.executable_path);
    let _ = writeln!(out, "- **SHA-256 (libc):** `{}`", si.self_sha256_libc_hex);
    if let Some(raw_h) = &si.self_sha256_raw_syscall_hex {
        let _ = writeln!(out, "- **SHA-256 (Raw x86_64 Syscall):** `{}`", raw_h);
    }
    let _ = writeln!(
        out,
        "- **Kanca Girişimi Tespit Edildi:** `{}` | **Güvenli Mod Aktif:** `{}`",
        si.compromise_attempt_detected, si.safe_mode_policy.safe_mode_active
    );
    for a in &si.alerts {
        let _ = writeln!(
            out,
            "  - **[{}]** `{}`: {} (`{}`)",
            a.severity, a.code, a.detail, a.indicator
        );
    }

    out
}

pub fn render_remediation_html(plan: &RemediationPlan) -> String {
    let mut html = String::with_capacity(16384);
    let _ = writeln!(
        html,
        "<!DOCTYPE html><html lang=\"tr\"><head><meta charset=\"utf-8\">\
         <title>FSR Olay Müdahale ve Temiz Göç Planı — {}</title>\
         <style>\
         body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:24px;color:#0f172a;background:#f8fafc;line-height:1.5}}\
         .card{{background:#fff;border:1px solid #cbd5e1;border-radius:8px;padding:18px 22px;margin-bottom:18px}}\
         .alert{{background:#fef2f2;border-left:5px solid #dc2626;padding:12px 16px;margin:12px 0}}\
         .ok{{background:#f0fdf4;border-left:5px solid #16a34a;padding:12px 16px;margin:12px 0}}\
         pre{{background:#0f172a;color:#f8fafc;padding:14px;border-radius:6px;overflow-x:auto;font-size:12.5px}}\
         code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}}\
         table{{width:100%;border-collapse:collapse;margin-top:10px}}\
         th,td{{border:1px solid #cbd5e1;padding:8px 10px;text-align:left;vertical-align:top;font-size:13px}}\
         th{{background:#f1f5f9}}\
         @media print{{body{{background:#fff;margin:0}}.card{{break-inside:avoid}}}}\
         </style></head><body>",
        escape_html(&plan.target_hostname)
    );

    let _ = writeln!(
        html,
        "<div class=\"card\"><h1>Olay Müdahale, Kimlik Bilgisi Rotasyonu ve Temiz Göç Planı</h1>\
         <p><strong>Hedef:</strong> <code>{}</code> (<code>{}</code>) | \
         <strong>Adli Durum:</strong> <code>{}</code> (<strong>{}/100</strong>) | \
         <strong>Kanıt Merkle Kökü:</strong> <code>{}</code></p></div>",
        escape_html(&plan.target_hostname),
        escape_html(&plan.target_root_path),
        escape_html(&plan.verdict_status),
        plan.composite_risk_score,
        escape_html(&plan.bundle_merkle_root_hex)
    );

    // 1. Vault Inventory
    let _ = writeln!(
        html,
        "<div class=\"card\"><h2>1. Acil İptal Edilecek Kurumsal API Anahtarları ve Servis Hesapları</h2>"
    );
    if !plan.compromised_vault_inventory.emergency_rotation_required {
        let _ = writeln!(
            html,
            "<div class=\"ok\">Acil kasa kimlik bilgisi rotasyonu gerektiren bulgu yok.</div>"
        );
    } else {
        let _ = writeln!(
            html,
            "<table><thead><tr><th>Öncelik / SLA</th><th>Entegrasyon</th><th>Risk Altındaki Alanlar</th><th>Müdahale Adımları</th></tr></thead><tbody>"
        );
        for e in &plan.compromised_vault_inventory.emergency_revocation_list {
            let _ = writeln!(
                html,
                "<tr><td><strong>{}</strong><br>{}</td><td><strong>{}</strong><br><code>{}</code> v{}</td><td><code>{}</code></td><td>{}</td></tr>",
                escape_html(e.urgency.as_str()),
                escape_html(e.urgency.sla_window_tr()),
                escape_html(&e.display_label),
                escape_html(&e.connector_id),
                escape_html(&e.version),
                escape_html(&e.credential_fields_at_risk.join(", ")),
                escape_html(&e.revocation_and_rotation_steps_tr.join(" "))
            );
        }
        let _ = writeln!(html, "</tbody></table>");
    }
    let _ = writeln!(html, "</div>");

    // 2. Containment
    let _ = writeln!(
        html,
        "<div class=\"card\"><h2>2. Canlı Kanıt Koruma ve Ağ İzolasyonu (Sıfır Reboot)</h2>\
         <div class=\"alert\">{}</div>\
         <h3>nftables Karantina Betiği</h3><pre>{}</pre>\
         <h3>FortiOS Karantina Betiği</h3><pre>{}</pre></div>",
        escape_html(&plan.containment_commands.zero_reboot_mandate_tr),
        escape_html(&plan.containment_commands.nftables_quarantine_script),
        escape_html(&plan.containment_commands.fortios_cli_quarantine_script)
    );

    // 3. Clean Migration
    let _ = writeln!(
        html,
        "<div class=\"card\"><h2>3. Güvenli Playbook Göç Denetimi ve SHA-256 Manifestosu</h2>\
         <p>Onaylı: <strong>{}</strong> | Karantinada: <strong>{}</strong></p>\
         <pre>{}</pre></div>",
        plan.clean_migration_plan.approved_clean_count,
        plan.clean_migration_plan.quarantined_count,
        escape_html(&plan.clean_migration_plan.sha256sum_manifest_text)
    );

    // 4. Self-Integrity
    let _ = writeln!(
        html,
        "<div class=\"card\"><h2>4. Saha Dağıtım Öz-Doğrulama (Self-Integrity) Zırhı</h2>\
         <p>İkili: <code>{}</code> | SHA-256: <code>{}</code> | Güvenli Mod: <code>{}</code></p></div></body></html>",
        escape_html(&plan.self_integrity.executable_path),
        escape_html(&plan.self_integrity.self_sha256_libc_hex),
        plan.self_integrity.safe_mode_policy.safe_mode_active
    );

    html
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}
