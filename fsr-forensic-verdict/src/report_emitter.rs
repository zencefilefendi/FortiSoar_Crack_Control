//! Engine 4: Multi-Format DFIR, Legal Expert & CISO Executive Report Emitter.
//!
//! Renders a [`ForensicVerdictBundle`] into three self-contained formats:
//!   1. `OutputFormat::Json` (`--format json`, plus `--compact` single-line NDJSON):
//!      Canonical Forensic Evidence Envelope (`schema_version: "1.0.0"` compatible)
//!      carrying all 19 engine summaries, `non_mutation_attestation`, `verdict_summary`,
//!      `findings`, and `merkle_envelope` (RFC 6962 root + per-finding inclusion proofs).
//!   2. `OutputFormat::Markdown` (`--format markdown`):
//!      Court/expert-witness & compliance-ready Markdown report.
//!   3. `OutputFormat::Html` (`--format html`):
//!      Zero-external-asset (inline CSS, zero external JS/fonts, `@media print` A4/PDF
//!      ready) executive CISO & Board forensic breach report.

use std::fmt::Write as _;

use fsr_clone_cluster_audit::birthmark_extractor::DeviceBirthmarks;
use fsr_deep_audit::schema::{EngineId, JsonValue, ScanContext, Severity};
use fsr_remediation_advisor::self_integrity::SelfIntegrityReport;

use crate::merkle_evidence::MerkleTreeEnvelope;
use crate::readonly_attestation::NonMutationAttestation;
use crate::verdict_classifier::VerdictSummary;

/// Supported report output formats for `fsr-forensic-verdict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Markdown,
    Html,
    DenetimTutanagi,
}

impl OutputFormat {
    pub fn parse_label(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" | "ndjson" => Some(OutputFormat::Json),
            "md" | "markdown" => Some(OutputFormat::Markdown),
            "html" | "htm" => Some(OutputFormat::Html),
            "denetim-tutanagi" | "tutanak" | "acceptance-report" => {
                Some(OutputFormat::DenetimTutanagi)
            }
            _ => None,
        }
    }
}

/// Complete sealed forensic bundle produced by the 5-phase command center.
#[derive(Debug, Clone)]
pub struct ForensicVerdictBundle {
    pub tool_name: &'static str,
    pub tool_version: &'static str,
    pub context: ScanContext,
    pub self_integrity: SelfIntegrityReport,
    pub verdict_summary: VerdictSummary,
    pub non_mutation_attestation: NonMutationAttestation,
    pub birthmarks: Option<DeviceBirthmarks>,
    pub engines: Vec<(String, JsonValue)>,
    pub merkle_envelope: MerkleTreeEnvelope,
}

impl ForensicVerdictBundle {
    /// Builds the canonical `schema_version: "1.0.0"` JSON AST envelope.
    pub fn to_canonical_json_value(&self) -> JsonValue {
        let raw_backend = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            "linux-x86_64-raw-syscall-asm"
        } else {
            "portable-fallback-non-linux-x86_64"
        };

        let serialized_findings: Vec<JsonValue> = self
            .merkle_envelope
            .sealed_findings
            .iter()
            .map(|sf| sf.finding_json.clone())
            .collect();

        JsonValue::OrderedObject(vec![
            ("schema_version".to_string(), JsonValue::str("1.0.0")),
            (
                "tool".to_string(),
                JsonValue::OrderedObject(vec![
                    ("name".to_string(), JsonValue::str(self.tool_name)),
                    ("version".to_string(), JsonValue::str(self.tool_version)),
                    (
                        "target_arch".to_string(),
                        JsonValue::str(std::env::consts::ARCH),
                    ),
                    (
                        "target_os".to_string(),
                        JsonValue::str(std::env::consts::OS),
                    ),
                    ("syscall_backend".to_string(), JsonValue::str(raw_backend)),
                ]),
            ),
            (
                "scan_context".to_string(),
                JsonValue::OrderedObject(vec![
                    (
                        "root_path".to_string(),
                        JsonValue::str(&self.context.root_path),
                    ),
                    (
                        "hostname".to_string(),
                        JsonValue::str(&self.context.hostname),
                    ),
                    (
                        "kernel_release".to_string(),
                        JsonValue::str(&self.context.kernel_release),
                    ),
                    (
                        "scan_timestamp_unix".to_string(),
                        JsonValue::Uint(self.context.scan_timestamp_unix),
                    ),
                    (
                        "scanner_pid".to_string(),
                        JsonValue::Uint(self.context.scanner_pid as u64),
                    ),
                    (
                        "effective_uid".to_string(),
                        JsonValue::Uint(self.context.effective_uid as u64),
                    ),
                ]),
            ),
            (
                "verdict".to_string(),
                self.verdict_summary.to_legacy_compatible_verdict_json(),
            ),
            (
                "verdict_summary".to_string(),
                self.verdict_summary.to_detailed_json(),
            ),
            (
                "non_mutation_attestation".to_string(),
                self.non_mutation_attestation.to_json(),
            ),
            ("self_integrity".to_string(), self.self_integrity.to_json()),
            (
                "engines".to_string(),
                JsonValue::OrderedObject(self.engines.clone()),
            ),
            ("findings".to_string(), JsonValue::Array(serialized_findings)),
            (
                "merkle_envelope".to_string(),
                self.merkle_envelope.to_json(),
            ),
        ])
    }
}

/// Renders `bundle` into the requested [`OutputFormat`]. When `format == OutputFormat::Json`,
/// `pretty == false` emits single-line NDJSON (`--compact`).
pub fn emit_forensic_report(
    bundle: &ForensicVerdictBundle,
    format: OutputFormat,
    pretty: bool,
) -> String {
    match format {
        OutputFormat::Json => bundle.to_canonical_json_value().to_json_string(pretty),
        OutputFormat::Markdown => render_markdown_report(bundle),
        OutputFormat::Html => render_html_report(bundle),
        OutputFormat::DenetimTutanagi => render_denetim_kabul_tutanagi_html(bundle),
    }
}

// ============================================================================
// 4B. Expert-Witness & Legal Compliance Markdown Report (`--format markdown`)
// ============================================================================

pub fn render_markdown_report(bundle: &ForensicVerdictBundle) -> String {
    let mut out = String::with_capacity(16384);
    let vs = &bundle.verdict_summary;
    let att = &bundle.non_mutation_attestation;
    let me = &bundle.merkle_envelope;

    let _ = writeln!(
        out,
        "# Adli Bilişim, Lisans Bütünlüğü ve Tedarik Zinciri İhlal Raporu"
    );
    let _ = writeln!(out);
    let baseline_label = extract_baseline_profile_label(bundle);
    let _ = writeln!(
        out,
        "- **Denetim Aracı:** `{}` v`{}` (`schema_version: 1.0.0`, `19 Çekirdek + 3 OVA/Atıf Motoru`)",
        bundle.tool_name, bundle.tool_version
    );
    let _ = writeln!(
        out,
        "- **Referans Baseline Manifest Profili:** `{}`",
        escape_md_inline(&baseline_label)
    );
    let _ = writeln!(
        out,
        "- **İncelenen Hedef Kök Dizin:** `{}` (Host: `{}`, Çekirdek: `{}`)",
        escape_md_inline(&bundle.context.root_path),
        escape_md_inline(&bundle.context.hostname),
        escape_md_inline(&bundle.context.kernel_release)
    );
    let _ = writeln!(
        out,
        "- **Denetim Zaman Damgası (Unix UTC):** `{}`",
        bundle.context.scan_timestamp_unix
    );
    let _ = writeln!(
        out,
        "- **Genel Adli Durum:** **`{}`** | **Bileşik Risk Skoru:** **`{}/100`**",
        vs.status, vs.composite_risk_score
    );
    let _ = writeln!(
        out,
        "- **RFC 6962 İkili Merkle Kök Özeti (`merkle_root_hex`):** `{}`",
        me.merkle_root_hex
    );
    let _ = writeln!(
        out,
        "- **Salt-Okunur Müdahalesizlik Durumu:** `{}` (`verified_artifact_count = {}`)",
        if att.target_mutated {
            "İHLAL / DEĞİŞİM SAPTANDI"
        } else {
            "DOĞRULANDI (target_mutated: false — Sıfır Bayt Değişim)"
        },
        att.verified_artifact_count
    );
    let _ = writeln!(out);

    // 1. Executive Summary
    let _ = writeln!(out, "## 1. Yönetici Özeti");
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", vs.executive_conclusion_tr);
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Kritik (`CRITICAL`) | Yüksek (`HIGH`) | Orta (`MEDIUM`) | Düşük (`LOW`) | Bilgi (`INFO`) | Toplam Bulgu | Etkilenen Motor |"
    );
    let _ = writeln!(
        out,
        "| :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    );
    let _ = writeln!(
        out,
        "| **{}** | **{}** | **{}** | {} | {} | **{}** | **{}/{}** |",
        vs.critical_count,
        vs.high_count,
        vs.medium_count,
        vs.low_count,
        vs.info_count,
        vs.total_findings,
        vs.distinct_compromised_engines,
        bundle.engines.len()
    );
    let _ = writeln!(out);

    let (das_crack_status, fgt_lic_status, vault_status) = summarize_instant_enterprise_checks(bundle);
    let overall_instant_banner = if vs.critical_count > 0 || vs.high_count > 0 {
        "KRİTİK UYARI: LİSANSSIZ / KIRILMIŞ (CRACKLİ) VEYA ARKA KAPILI SİSTEM TESPİT EDİLDİ"
    } else {
        "DOĞRULANDI: ORİJİNAL FABRİKA BÜTÜNLÜĞÜ (CRACK VEYA ARKA KAPI BULUNMADI)"
    };
    let _ = writeln!(
        out,
        "### Kurumsal Denetim — Anlık Orijinallik Doğrulama Kartı"
    );
    let _ = writeln!(out, "- **Anlık Karar:** **`{}`**", overall_instant_banner);
    let _ = writeln!(
        out,
        "- **FortiSOAR `cyops-auth` / `/server/csdassrv.py` Denetimi:** {}",
        das_crack_status
    );
    let _ = writeln!(
        out,
        "- **FortiGate / FortiSOAR Lisans, Seri Numarası ve Golden Image Klon Denetimi:** {}",
        fgt_lic_status
    );
    let _ = writeln!(
        out,
        "- **Tedarik Zinciri, Kasa (Vault) Anahtarı ve Konnektör Güvenliği:** {}",
        vault_status
    );
    let _ = writeln!(out);

    // 2. Causal Breach Synthesis Table
    let _ = writeln!(
        out,
        "## 2. Nedensel İhlal Sentezi ve \"Yanlış Yapılandırma Savunması\" Çürütme Matrisi"
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Hüküm Kodu | Durum | Güven Seviyesi | Kategori Skoru | Destekleyen Bulgular |"
    );
    let _ = writeln!(out, "| :--- | :---: | :--- | :---: | :---: |");
    for v in &vs.verdicts {
        let state_str = if v.triggered {
            "TETİKLENDİ"
        } else {
            "TEMİZ"
        };
        let _ = writeln!(
            out,
            "| `{}` | **{}** | `{}` | `{}/100` | {} |",
            v.verdict_code,
            state_str,
            v.confidence.as_str(),
            v.category_score,
            v.supporting_finding_ids.len()
        );
    }
    let _ = writeln!(out);

    for v in &vs.verdicts {
        let _ = writeln!(out, "### {} (`{}`)", v.title_tr, v.verdict_code);
        let _ = writeln!(out, "- **Nedensel Sentez:** {}", v.causal_synthesis_tr);
        let _ = writeln!(
            out,
            "- **Yanlış Yapılandırma Savunmasının Reddi:** {}",
            v.misconfig_refutation_tr
        );
        let _ = writeln!(
            out,
            "- **Hukuki ve Uyumluluk Etkisi:** {}",
            v.legal_and_compliance_impact_tr
        );
        if !v.supporting_finding_ids.is_empty() {
            let _ = writeln!(
                out,
                "- **Dayanak Kanıt Kayıtları:** `{}`",
                v.supporting_finding_ids.join("`, `")
            );
        }
        let _ = writeln!(out);
    }

    // 3. Non-Mutation Attestation
    let _ = writeln!(
        out,
        "## 3. Salt-Okunur Müdahalesizlik ve Kanıt Bütünlüğü Tutanağı"
    );
    let _ = writeln!(out);
    let mount_desc = match &att.mount_status {
        Some(m) => format!(
            "`{}` (`{}` — salt-okunur bağlama: `{}`)",
            escape_md_inline(&m.mount_point),
            escape_md_inline(&m.fs_type),
            m.is_read_only
        ),
        None => "`/proc/self/mountinfo` mevcut değil (taşınabilir SHA-256 doğrulama modu)".to_string(),
    };
    let _ = writeln!(out, "- **Hedef Değişimi (`target_mutated`):** `{}`", att.target_mutated);
    let _ = writeln!(out, "- **Doğrulanan Kritik Kanıt Dosyası:** `{}`", att.verified_artifact_count);
    let _ = writeln!(out, "- **Denetim Öncesi Durum Özeti (`pre_state_digest_hex`):** `{}`", att.pre_state_digest_hex);
    let _ = writeln!(out, "- **Denetim Sonrası Durum Özeti (`post_state_digest_hex`):** `{}`", att.post_state_digest_hex);
    let _ = writeln!(out, "- **Dosya Sistemi Bağlama Durumu:** {}", mount_desc);
    let _ = writeln!(
        out,
        "- **Çekirdek I/O Sayaç Farkı (`delta_syscr` / `delta_syscw` / `delta_storage_write_bytes`):** `{}` / `{}` / `{}`",
        att.delta_syscr, att.delta_syscw, att.delta_storage_write_bytes
    );
    let _ = writeln!(out);

    // 4. Cryptographic Birthmarks & Clone Evidence
    let _ = writeln!(
        out,
        "## 4. Kriptografik Doğum Lekesi ve Klonlama Kanıtları"
    );
    let _ = writeln!(out);
    if let Some(bm) = &bundle.birthmarks {
        let _ = writeln!(
            out,
            "- **Makine Kimliği (`/etc/machine-id`):** `{}`",
            bm.machine_id.as_deref().unwrap_or("yok")
        );
        for pg in &bm.pg_controls {
            let _ = writeln!(
                out,
                "- **PostgreSQL `pg_control` (`{}`):** `system_identifier = {}` (`{}`), CRC32C Geçerli: `{}`",
                escape_md_inline(&pg.path),
                pg.system_identifier,
                pg.system_identifier_hex,
                pg.crc32c_valid
            );
        }
        for sb in &bm.superblocks {
            let _ = writeln!(
                out,
                "- **Süperblok Kimliği (`{}` / `{}`):** `UUID = {}`",
                escape_md_inline(&sb.source_path),
                escape_md_inline(&sb.fs_type),
                escape_md_inline(&sb.uuid)
            );
        }
        for seed in &bm.crypto_seeds {
            let _ = writeln!(
                out,
                "- **Uygulama Kriptografik Tohumu (`{}` -> `{}`):** HMAC-SHA256 = `{}`",
                escape_md_inline(&seed.file_path),
                escape_md_inline(&seed.parameter_name),
                seed.hmac_sha256_fingerprint
            );
        }
    } else {
        let _ = writeln!(out, "_Doğum lekesi çıkarıcı bu çalışmada veri üretmedi._");
    }
    let _ = writeln!(out);

    // 5. Detected Supply-Chain Backdoors & Persistence
    let _ = writeln!(
        out,
        "## 5. Tespit Edilen Tedarik Zinciri Arka Kapıları ve Kalıcılık İmplantları"
    );
    let _ = writeln!(out);
    let backdoor_findings: Vec<_> = me
        .sealed_findings
        .iter()
        .filter(|sf| {
            matches!(
                sf.finding.engine,
                EngineId::ConnectorSkimmerAudit
                    | EngineId::WebAuthBackdoor
                    | EngineId::PostgresPersistence
                    | EngineId::OsPersistenceAudit
                    | EngineId::FortigateBackdoorAudit
            )
        })
        .collect();
    if backdoor_findings.is_empty() {
        let _ = writeln!(out, "_Faz-4 kapsamında arka kapı veya kalıcılık bulgusuna rastlanmadı._");
    } else {
        let _ = writeln!(out, "| Bulgu ID | Motor | Şiddet | Kod | Hedef | Özet |");
        let _ = writeln!(out, "| :--- | :--- | :---: | :--- | :--- | :--- |");
        for sf in backdoor_findings {
            let _ = writeln!(
                out,
                "| `{}` | `{}` | **{}** | `{}` | `{}` | {} |",
                sf.id,
                sf.finding.engine.as_str(),
                sf.finding.severity.as_str(),
                escape_md_table(&sf.finding.code),
                escape_md_table(&sf.finding.target),
                escape_md_table(&sf.finding.summary)
            );
        }
    }
    let _ = writeln!(out);

    // 6. Full RFC 6962 Merkle Verification Table
    let _ = writeln!(
        out,
        "## 6. Tüm Bulgular ve RFC 6962 Merkle Dahiliyet Doğrulama Sicili"
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- **Standart:** `{}` (`Leaf = SHA256(0x00 || JCS_Bytes)`, `Node = SHA256(0x01 || L || R)`)",
        me.rfc_standard
    );
    let _ = writeln!(out, "- **Toplam Yaprak (`leaf_count`):** `{}` | **Ağaç Derinliği:** `{}`", me.leaf_count, me.tree_depth);
    let _ = writeln!(out, "- **Mühürlü Kök Özet (`merkle_root_hex`):** `{}`", me.merkle_root_hex);
    let _ = writeln!(out);
    if me.sealed_findings.is_empty() {
        let _ = writeln!(out, "_Sistem temiz: Mühürlenecek ihlal bulgusu bulunmadı (Boş ağaç özeti: SHA-256(\"\"))._");
    } else {
        let _ = writeln!(
            out,
            "| Yaprak # | Bulgu ID | Şiddet | Motor | Kod | Yaprak Özeti (`leaf_hash_hex`) | Kanıt Adımı |"
        );
        let _ = writeln!(
            out,
            "| :---: | :--- | :---: | :--- | :--- | :--- | :---: |"
        );
        for (sf, proof_rec) in me.sealed_findings.iter().zip(me.proofs.iter()) {
            let _ = writeln!(
                out,
                "| {} | `{}` | `{}` | `{}` | `{}` | `{}` | {} |",
                sf.leaf_index,
                sf.id,
                sf.finding.severity.as_str(),
                sf.finding.engine.as_str(),
                escape_md_table(&sf.finding.code),
                sf.leaf_hash_hex,
                proof_rec.inclusion_proof.len()
            );
        }
    }

    out
}

// ============================================================================
// 4C. Self-Contained Print-Ready Executive HTML Report (`--format html`)
// ============================================================================

pub fn render_html_report(bundle: &ForensicVerdictBundle) -> String {
    let mut out = String::with_capacity(32768);
    let vs = &bundle.verdict_summary;
    let att = &bundle.non_mutation_attestation;
    let me = &bundle.merkle_envelope;

    let status_badge_class = match vs.status {
        "COMPROMISED_OR_CRACKED" => "badge-critical",
        "SUSPICIOUS_ANOMALIES" => "badge-high",
        _ => "badge-clean",
    };

    let _ = write!(
        out,
        r#"<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Adli Bilişim İhlal ve Bütünlük Raporu — {hostname}</title>
<style>
  :root {{
    --bg: #f8fafc;
    --surface: #ffffff;
    --ink: #0f172a;
    --muted: #475569;
    --border: #cbd5e1;
    --navy: #0b192c;
    --critical: #b91c1c;
    --critical-bg: #fef2f2;
    --high: #c2410c;
    --high-bg: #fff7ed;
    --clean: #15803d;
    --clean-bg: #f0fdf4;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 28px;
    background: var(--bg);
    color: var(--ink);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.55;
  }}
  .container {{
    max-width: 1180px;
    margin: 0 auto;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    box-shadow: 0 4px 18px rgba(15, 23, 42, 0.06);
  }}
  header.dossier-header {{
    background: var(--navy);
    color: #f8fafc;
    padding: 28px 32px;
    border-bottom: 4px solid #dc2626;
  }}
  header.dossier-header h1 {{
    margin: 0 0 8px 0;
    font-size: 22px;
    letter-spacing: 0.2px;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 10px 20px;
    margin-top: 14px;
    font-size: 12.5px;
    color: #cbd5e1;
  }}
  .meta-grid code {{
    color: #ffffff;
    font-family: var(--mono);
    word-break: break-all;
  }}
  main {{ padding: 28px 32px; }}
  h2 {{
    margin: 28px 0 12px 0;
    padding-bottom: 6px;
    border-bottom: 2px solid #e2e8f0;
    font-size: 17px;
    color: var(--navy);
  }}
  .summary-banner {{
    display: flex;
    flex-wrap: wrap;
    gap: 20px;
    align-items: center;
    justify-content: space-between;
    padding: 18px 22px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: #f1f5f9;
  }}
  .score-box {{
    min-width: 180px;
    text-align: center;
    padding: 12px 16px;
    border-radius: 8px;
    background: var(--surface);
    border: 1px solid var(--border);
  }}
  .score-num {{
    font-size: 32px;
    font-weight: 800;
    font-family: var(--mono);
  }}
  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 11.5px;
    font-weight: 700;
    font-family: var(--mono);
    letter-spacing: 0.3px;
  }}
  .badge-critical {{ background: var(--critical-bg); color: var(--critical); border: 1px solid #fecaca; }}
  .badge-high {{ background: var(--high-bg); color: var(--high); border: 1px solid #fed7aa; }}
  .badge-clean {{ background: var(--clean-bg); color: var(--clean); border: 1px solid #bbf7d0; }}
  .verdict-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 16px;
    margin-top: 14px;
  }}
  .verdict-card {{
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    background: var(--surface);
    page-break-inside: avoid;
  }}
  .verdict-card.triggered {{
    border-left: 5px solid var(--critical);
    background: #fffafa;
  }}
  .verdict-card.clean {{
    border-left: 5px solid var(--clean);
  }}
  .verdict-card h3 {{
    margin: 6px 0 8px 0;
    font-size: 14.5px;
  }}
  .seal-box {{
    font-family: var(--mono);
    font-size: 12px;
    padding: 14px 16px;
    background: #0f172a;
    color: #e2e8f0;
    border-radius: 8px;
    overflow-x: auto;
    page-break-inside: avoid;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
    font-size: 12.5px;
  }}
  th, td {{
    border: 1px solid var(--border);
    padding: 8px 10px;
    text-align: left;
    vertical-align: top;
  }}
  th {{
    background: #f1f5f9;
    font-weight: 700;
    color: var(--navy);
  }}
  tr {{ page-break-inside: avoid; }}
  code, .hash {{
    font-family: var(--mono);
    font-size: 11.5px;
    word-break: break-all;
  }}
  footer {{
    padding: 16px 32px;
    background: #f1f5f9;
    border-top: 1px solid var(--border);
    font-size: 12px;
    color: var(--muted);
  }}
  @media print {{
    body {{ background: #ffffff; padding: 0; font-size: 11.5px; }}
    .container {{ box-shadow: none; border: none; max-width: 100%; }}
    header.dossier-header {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .seal-box {{ background: #f8fafc; color: #0f172a; border: 1px solid #94a3b8; }}
    h2 {{ page-break-after: avoid; }}
  }}
</style>
</head>
<body>
<div class="container">
  <header class="dossier-header">
    <h1>ADLİ BİLİŞİM İHLAL, LİSANS BÜTÜNLÜĞÜ VE TEDARİK ZİNCİRİ KARAR RAPORU</h1>
    <div>CISO / Yönetim Kurulu / Adli Bilirkişi Kanıt Dosyası — Sıfır Harici Bağımlılıklı Kriptografik Mühür</div>
    <div class="meta-grid">
      <div><strong>Araç:</strong> <code>{tool} v{ver}</code></div>
      <div><strong>Hedef Dizin:</strong> <code>{root}</code></div>
      <div><strong>Sistem / Çekirdek:</strong> <code>{hostname} ({kernel})</code></div>
      <div><strong>Denetim Zamanı (UTC Unix):</strong> <code>{ts}</code></div>
      <div><strong>Baseline Manifest:</strong> <code>{baseline_lbl}</code></div>
      <div><strong>Taranan Motor:</strong> <code>{engine_cnt} Aktif Motor (19 Çekirdek + 3 OVA/Atıf)</code></div>
    </div>
  </header>
  <main>
    <div class="summary-banner">
      <div style="flex: 1 1 520px;">
        <div style="margin-bottom: 8px;">
          <span class="badge {badge_cls}">{status}</span>
          <span class="badge {mut_cls}" style="margin-left: 6px;">{mut_label}</span>
        </div>
        <div>{exec_summary}</div>
      </div>
      <div class="score-box">
        <div style="font-size: 11.5px; color: var(--muted); text-transform: uppercase;">Bileşik Risk Skoru</div>
        <div class="score-num">{score}/100</div>
        <div style="font-size: 12px;">Kritik: <strong>{crit}</strong> | Yüksek: <strong>{high}</strong> | Toplam: <strong>{total}</strong></div>
      </div>
    </div>
"#,
        hostname = escape_html(&bundle.context.hostname),
        tool = escape_html(bundle.tool_name),
        ver = escape_html(bundle.tool_version),
        root = escape_html(&bundle.context.root_path),
        kernel = escape_html(&bundle.context.kernel_release),
        ts = bundle.context.scan_timestamp_unix,
        baseline_lbl = escape_html(&extract_baseline_profile_label(bundle)),
        engine_cnt = bundle.engines.len(),
        badge_cls = status_badge_class,
        status = escape_html(vs.status),
        mut_cls = if att.target_mutated {
            "badge-critical"
        } else {
            "badge-clean"
        },
        mut_label = if att.target_mutated {
            "HEDEF DEĞİŞİM UYARISI"
        } else {
            "SALT-OKUNUR MÜDAHALESİZLİK DOĞRULANDI"
        },
        exec_summary = escape_html(&vs.executive_conclusion_tr),
        score = vs.composite_risk_score,
        crit = vs.critical_count,
        high = vs.high_count,
        total = vs.total_findings,
    );

    // Causal Verdicts Section
    let (das_crack_status, fgt_lic_status, vault_status) = summarize_instant_enterprise_checks(bundle);
    let instant_title = if vs.critical_count > 0 || vs.high_count > 0 {
        "KRİTİK UYARI: LİSANSSIZ / KIRILMIŞ (CRACKLİ) VEYA ARKA KAPILI SİSTEM TESPİT EDİLDİ"
    } else {
        "DOĞRULANDI: ORİJİNAL FABRİKA BÜTÜNLÜĞÜ (CRACK VEYA ARKA KAPI BULUNMADI)"
    };
    let _ = write!(
        out,
        r#"    <h2>0. Kurumsal Denetim — Anlık Crack / Orijinallik Doğrulama Kartı</h2>
    <table>
      <thead><tr><th>Denetim Boyutu</th><th>Anlık Tespit ve Teknik Sonuç</th></tr></thead>
      <tbody>
        <tr><td><strong>Genel Orijinallik Kararı</strong></td><td><span class="badge {badge_cls}">{instant_title}</span></td></tr>
        <tr><td><strong>FortiSOAR <code>cyops-auth</code> / <code>/server/csdassrv.py</code></strong></td><td>{das_status}</td></tr>
        <tr><td><strong>FortiGate / FortiSOAR Lisans, Seri No ve Klon Denetimi</strong></td><td>{lic_status}</td></tr>
        <tr><td><strong>Tedarik Zinciri, Kasa (Vault) ve Konnektör Güvenliği</strong></td><td>{vault_status}</td></tr>
      </tbody>
    </table>
"#,
        badge_cls = status_badge_class,
        instant_title = escape_html(instant_title),
        das_status = escape_html(&das_crack_status),
        lic_status = escape_html(&fgt_lic_status),
        vault_status = escape_html(&vault_status),
    );

    let _ = writeln!(
        out,
        "    <h2>1. Nedensel İhlal Sentezi ve Yanlış Yapılandırma Savunmasının Reddi</h2>"
    );
    let _ = writeln!(out, "    <div class=\"verdict-grid\">");
    for v in &vs.verdicts {
        let card_cls = if v.triggered { "triggered" } else { "clean" };
        let badge_cls = if v.triggered {
            "badge-critical"
        } else {
            "badge-clean"
        };
        let badge_txt = if v.triggered {
            "HÜKÜM TETİKLENDİ"
        } else {
            "BULGU YOK"
        };
        let _ = write!(
            out,
            r#"      <div class="verdict-card {card_cls}">
        <div><span class="badge {badge_cls}">{badge_txt}</span> <code>{code}</code></div>
        <h3>{title}</h3>
        <p><strong>Güven:</strong> <code>{conf}</code> | <strong>Skor:</strong> <code>{cscore}/100</code></p>
        <p><strong>Teknik Nedensellik:</strong> {synth}</p>
        <p><strong>Savunma Reddi:</strong> {refut}</p>
        <p><strong>Uyumluluk / Hukuk:</strong> {legal}</p>
      </div>
"#,
            card_cls = card_cls,
            badge_cls = badge_cls,
            badge_txt = badge_txt,
            code = escape_html(v.verdict_code),
            title = escape_html(v.title_tr),
            conf = escape_html(v.confidence.as_str()),
            cscore = v.category_score,
            synth = escape_html(&v.causal_synthesis_tr),
            refut = escape_html(&v.misconfig_refutation_tr),
            legal = escape_html(&v.legal_and_compliance_impact_tr),
        );
    }
    let _ = writeln!(out, "    </div>");

    // Non-Mutation & Merkle Cryptographic Seal Box
    let _ = write!(
        out,
        r#"    <h2>2. Kriptografik Mühür (RFC 6962 Merkle Kökü) ve Müdahalesizlik Tutanağı</h2>
    <div class="seal-box">
      <div><strong>RFC 6962 Merkle Root (SHA-256):</strong> {merkle_root}</div>
      <div><strong>Yaprak Sayısı / Derinlik:</strong> {leaf_count} yaprak / {depth} seviye (Alan Ayrımı: Leaf=0x00, Node=0x01)</div>
      <div><strong>Ön Durum Özeti (Pre-Audit SHA-256):</strong>  {pre_hash}</div>
      <div><strong>Son Durum Özeti (Post-Audit SHA-256):</strong> {post_hash}</div>
      <div><strong>Doğrulanan Kanıt Dosyası:</strong> {art_count} adet | <strong>Hedef Değişimi (target_mutated):</strong> {mutated} | <strong>syscr / syscw farkı:</strong> {syscr} / {syscw}</div>
    </div>
"#,
        merkle_root = escape_html(&me.merkle_root_hex),
        leaf_count = me.leaf_count,
        depth = me.tree_depth,
        pre_hash = escape_html(&att.pre_state_digest_hex),
        post_hash = escape_html(&att.post_state_digest_hex),
        art_count = att.verified_artifact_count,
        mutated = att.target_mutated,
        syscr = att.delta_syscr,
        syscw = att.delta_syscw,
    );

    // Birthmarks Table
    let _ = writeln!(out, "    <h2>3. Kriptografik Doğum Lekesi ve Klon Kimlikleri</h2>");
    if let Some(bm) = &bundle.birthmarks {
        let _ = writeln!(
            out,
            "    <table><thead><tr><th>Kategori</th><th>Kaynak</th><th>Kriptografik Parmak İzi / Kimlik</th></tr></thead><tbody>"
        );
        if let Some(mid) = &bm.machine_id {
            let _ = writeln!(
                out,
                "      <tr><td>Machine-ID</td><td><code>/etc/machine-id</code></td><td class=\"hash\">{}</td></tr>",
                escape_html(mid)
            );
        }
        for pg in &bm.pg_controls {
            let _ = writeln!(
                out,
                "      <tr><td>PostgreSQL pg_control</td><td><code>{}</code></td><td class=\"hash\">ID={} ({}) | CRC32C={}</td></tr>",
                escape_html(&pg.path),
                pg.system_identifier,
                escape_html(&pg.system_identifier_hex),
                pg.crc32c_valid
            );
        }
        for sb in &bm.superblocks {
            let _ = writeln!(
                out,
                "      <tr><td>Dosya Sistemi ({})</td><td><code>{}</code></td><td class=\"hash\">UUID={}</td></tr>",
                escape_html(&sb.fs_type),
                escape_html(&sb.source_path),
                escape_html(&sb.uuid)
            );
        }
        for seed in &bm.crypto_seeds {
            let _ = writeln!(
                out,
                "      <tr><td>Kasa / Uygulama Tohumu</td><td><code>{} :: {}</code></td><td class=\"hash\">HMAC-SHA256={}</td></tr>",
                escape_html(&seed.file_path),
                escape_html(&seed.parameter_name),
                escape_html(&seed.hmac_sha256_fingerprint)
            );
        }
        let _ = writeln!(out, "    </tbody></table>");
    } else {
        let _ = writeln!(out, "    <p>Doğum lekesi verisi bulunmuyor.</p>");
    }

    // Full Findings + Merkle Leaf Hashes Table
    let _ = writeln!(
        out,
        "    <h2>4. Mühürlenmiş Adli Bulgular ve RFC 6962 Yaprak Özetleri ({} Kayıt)</h2>",
        me.sealed_findings.len()
    );
    if me.sealed_findings.is_empty() {
        let _ = writeln!(
            out,
            "    <p>İncelenen 19 motorun tamamında herhangi bir ihlal bulgusuna rastlanmadı.</p>"
        );
    } else {
        let _ = writeln!(
            out,
            "    <table><thead><tr><th>Bulgu ID</th><th>Şiddet</th><th>Motor</th><th>Kod &amp; Hedef</th><th>Teknik Açıklama</th><th>RFC 6962 Yaprak SHA-256</th></tr></thead><tbody>"
        );
        for sf in &me.sealed_findings {
            let sev_cls = match sf.finding.severity {
                Severity::Critical => "badge-critical",
                Severity::High | Severity::Medium => "badge-high",
                _ => "badge-clean",
            };
            let _ = writeln!(
                out,
                "      <tr><td><code>{}</code></td><td><span class=\"badge {}\">{}</span></td><td><code>{}</code></td><td><code>{}</code><br><code>{}</code></td><td>{}</td><td class=\"hash\">{}</td></tr>",
                escape_html(&sf.id),
                sev_cls,
                escape_html(sf.finding.severity.as_str()),
                escape_html(sf.finding.engine.as_str()),
                escape_html(&sf.finding.code),
                escape_html(&sf.finding.target),
                escape_html(&sf.finding.summary),
                escape_html(&sf.leaf_hash_hex),
            );
        }
        let _ = writeln!(out, "    </tbody></table>");
    }

    let _ = write!(
        out,
        r#"  </main>
  <footer>
    Bu rapor <code>{tool} v{ver}</code> tarafından tamamen çevrimdışı ve salt-okunur modda üretilmiştir.
    Kanıt zarfının bütünlüğü <code>fsr-forensic-verdict --verify-bundle &lt;bundle.json&gt;</code> komutu ile hedef sisteme erişmeksizin bağımsız olarak doğrulanabilir.
  </footer>
</div>
</body>
</html>
"#,
        tool = escape_html(bundle.tool_name),
        ver = escape_html(bundle.tool_version),
    );

    out
}

/// Strict HTML5 entity escaping so malicious filenames/strings in a compromised image
/// can never inject scripts or break HTML structure.
pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn escape_md_inline(input: &str) -> String {
    input.replace('`', "'").replace(['\r', '\n'], " ")
}

fn escape_md_table(input: &str) -> String {
    input
        .replace('|', "\\|")
        .replace('`', "'")
        .replace(['\r', '\n'], " ")
}

/// Extracts the active FortiSOAR structural baseline manifest profile from `web_auth_backdoor` engine summary.
pub fn extract_baseline_profile_label(bundle: &ForensicVerdictBundle) -> String {
    for (name, val) in &bundle.engines {
        if name == "web_auth_backdoor" {
            if let JsonValue::OrderedObject(entries) = val {
                let mut profile = None;
                let mut ref_rel = None;
                let mut det_ver = None;
                let mut source = None;
                for (k, v) in entries {
                    if let JsonValue::Str(s) = v {
                        match k.as_str() {
                            "baseline_profile_id" => profile = Some(s.as_str()),
                            "baseline_reference_release" => ref_rel = Some(s.as_str()),
                            "detected_target_version" => det_ver = Some(s.as_str()),
                            "baseline_source" => source = Some(s.as_str()),
                            _ => {}
                        }
                    }
                }
                if let Some(p) = profile {
                    return format!(
                        "{} (Ref: {}, Hedef Sürüm: {}, Kaynak: {})",
                        p,
                        ref_rel.unwrap_or("belirsiz"),
                        det_ver.unwrap_or("belirsiz"),
                        source.unwrap_or("embedded")
                    );
                }
            }
        }
    }
    "fortisoar-7.6.x (Yapısal Değişmez Temelli Varsayılan Profil)".to_string()
}

/// Synthesizes a 3-axis plain-Turkish authenticity summary for enterprise inspection boards and CISOs.
pub fn summarize_instant_enterprise_checks(
    bundle: &ForensicVerdictBundle,
) -> (String, String, String) {
    let mut das_hits = Vec::new();
    let mut das_drift_hits = Vec::new();
    let mut lic_hits = Vec::new();
    let mut vault_hits = Vec::new();

    for sf in &bundle.merkle_envelope.sealed_findings {
        let code = sf.finding.code.as_str();
        if code == "MEDIUM_CYOPS_ENTRYPOINT_IMPORT_VERSION_DRIFT"
            && !das_drift_hits.contains(&code)
        {
            das_drift_hits.push(code);
        }
        if matches!(
            code,
            "CRITICAL_PYTHON_STARTUP_HOOK_LICENSE_BYPASS"
                | "CRITICAL_DAS_RUNTIME_MONKEYPATCH_BYPASS"
                | "CRITICAL_CYOPS_SERVER_UNAUTHORIZED_IMPORT_HOOK"
                | "CRITICAL_CYOPS_SERVER_ROGUE_SCRIPT_DROP"
                | "CRITICAL_PYTHON_PTH_STARTUP_HOOK"
                | "HIGH_CYOPS_INIT_PY_CODE_INJECTION"
                | "CRITICAL_COMPILED_STARTUP_PYC_HOOK"
                | "CRITICAL_PYC_MARSHAL_FORGED_LICENSE_PAYLOAD"
                | "CRITICAL_LIVE_CYTHON_SO_SYS_MODULES_GHOSTING"
                | "CRITICAL_VMDK_CARVED_DAS_RUNTIME_BYPASS"
                | "CRITICAL_LIVE_DAS_TORNADO_LICENSE_INTERCEPT_ACTIVE"
                | "CRITICAL_CYOPS_FDNCLIENT_JAR_TAMPERED"
                | "CRITICAL_CYOPS_DAS_INI_AUTH_BYPASS"
                | "CRITICAL_CYOPS_VENV_INTERPRETER_HIJACK"
                | "CRITICAL_CYOPS_UTILITY_SCRIPT_TAMPERED"
                | "CRITICAL_CYOPS_SQL_SEED_OR_MIGRATION_TAMPER"
                | "CRITICAL_CYOPS_CYTHON_SO_BINARY_REPLACED"
        ) && !das_hits.contains(&code)
        {
            das_hits.push(code);
        }

        if matches!(
            sf.finding.engine,
            EngineId::HwIntegrity
                | EngineId::ElfVmaDiff
                | EngineId::PycInspector
                | EngineId::RpmForensics
                | EngineId::CaTrustAudit
                | EngineId::SslBypassCheck
                | EngineId::FortigateCfgAudit
                | EngineId::FgvmLicenseInspect
                | EngineId::ClusterCorrelator
                | EngineId::OvaStreamInspector
                | EngineId::VmdkCarver
                | EngineId::CrackerAttribution
        ) && !lic_hits.contains(&code)
        {
            lic_hits.push(code);
        }

        if matches!(
            sf.finding.engine,
            EngineId::ConnectorSkimmerAudit
                | EngineId::WebAuthBackdoor
                | EngineId::PostgresPersistence
                | EngineId::OsPersistenceAudit
                | EngineId::FortigateBackdoorAudit
        ) && code != "MEDIUM_CYOPS_ENTRYPOINT_IMPORT_VERSION_DRIFT"
            && !vault_hits.contains(&code)
        {
            vault_hits.push(code);
        }
        if code == "CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY" && !vault_hits.contains(&code) {
            vault_hits.push(code);
        }
    }

    let das_str = if !das_hits.is_empty() {
        format!(
            "CRACK TESPİT EDİLDİ — `cyops-auth` / `/server/csdassrv.py` çalışma zamanı lisans baypası aktif ({})",
            das_hits.join(", ")
        )
    } else if !das_drift_hits.is_empty() {
        format!(
            "SÜRÜM SAPMASI UYARISI — Yeni FortiSOAR sürümünde tanımlanmamış import saptandı; baseline manifest güncellenmelidir ({})",
            das_drift_hits.join(", ")
        )
    } else {
        "TEMİZ — `/server/csdassrv.py` import kancası veya `sys.modules` Cython `.so` gölgelemesi saptanmadı.".to_string()
    };

    let lic_str = if lic_hits.is_empty() {
        "TEMİZ — FortiGate / FortiSOAR lisans, seri numarası, ELF64 ve Golden Image bütünlüğü doğrulandı.".to_string()
    } else {
        format!(
            "İHLAL TESPİT EDİLDİ — Sahte/korsan lisans, ELF64/bytecode yaması veya klonlanmış Golden Image bulgusu ({})",
            lic_hits.join(", ")
        )
    };

    let vault_str = if vault_hits.is_empty() {
        "TEMİZ — Kasa (Vault) anahtar paylaşımı, konnektör skimmer veya arka kapı saptanmadı.".to_string()
    } else {
        format!(
            "TEHLİKEDE — Tedarik zinciri arka kapısı, paylaşılan Vault anahtarı veya yetki baypası ({})",
            vault_hits.join(", ")
        )
    };

    (das_str, lic_str, vault_str)
}

// ============================================================================
// 4D. Enterprise Inspection & Acceptance Certificate (`--format denetim-tutanagi`)
// ============================================================================

/// Renders a print-ready A4 Enterprise Inspection Certificate
/// ("KURUMSAL SİBER GÜVENLİK DENETİMİ — TEKNİK BÜTÜNLÜK VE KABUL TUTANAĞI").
pub fn render_denetim_kabul_tutanagi_html(bundle: &ForensicVerdictBundle) -> String {
    let mut out = String::with_capacity(20480);
    let vs = &bundle.verdict_summary;
    let att = &bundle.non_mutation_attestation;
    let me = &bundle.merkle_envelope;
    let (das_crack_status, fgt_lic_status, vault_status) =
        summarize_instant_enterprise_checks(bundle);

    let is_rejected = vs.status == "COMPROMISED_OR_CRACKED" || vs.critical_count > 0;
    let decision_banner_class = if is_rejected {
        "decision-rejected"
    } else if vs.high_count > 0 || vs.medium_count > 0 {
        "decision-suspicious"
    } else {
        "decision-approved"
    };

    let decision_title = if is_rejected {
        "KABUL EDİLEMEZ (REDDEDİLDİ) — CRACKLİ / LİSANS BAYPASLI VEYA MÜDAHALE EDİLMİŞ SİSTEM TESPİT EDİLDİ"
    } else if vs.high_count > 0 || vs.medium_count > 0 {
        "ŞARTLI İNCELEME GEREKLİ — ŞÜPHELİ BÜTÜNLÜK ANOMALİLERİ TESPİT EDİLDİ"
    } else {
        "KABUL EDİLEBİLİR (ONAYLANDI) — ORİJİNAL FABRİKA BÜTÜNLÜĞÜ DOĞRULANDI (CRACK / ARKA KAPI YOK)"
    };

    let _ = write!(
        out,
        r#"<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kurumsal Siber Güvenlik ve Teknik Bütünlük Denetim Tutanağı — {hostname}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 24px;
    font-family: "Times New Roman", Georgia, -apple-system, BlinkMacSystemFont, serif;
    color: #0f172a;
    background: #f8fafc;
    line-height: 1.5;
    font-size: 13.5px;
  }}
  .page {{
    max-width: 1000px;
    margin: 0 auto;
    background: #ffffff;
    border: 2px solid #0f172a;
    padding: 28px 34px;
  }}
  .official-header {{
    text-align: center;
    border-bottom: 2px double #0f172a;
    padding-bottom: 14px;
    margin-bottom: 18px;
  }}
  .official-header h1 {{
    margin: 0 0 6px 0;
    font-size: 18px;
    letter-spacing: 0.4px;
    text-transform: uppercase;
  }}
  .official-header h2 {{
    margin: 0;
    font-size: 14px;
    font-weight: 600;
    color: #334155;
  }}
  .decision-box {{
    padding: 16px 20px;
    margin: 16px 0 20px 0;
    border: 2px solid;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }}
  .decision-rejected {{
    background: #fef2f2;
    border-color: #b91c1c;
    color: #7f1d1d;
  }}
  .decision-suspicious {{
    background: #fffbeb;
    border-color: #b45309;
    color: #78350f;
  }}
  .decision-approved {{
    background: #ecfdf5;
    border-color: #047857;
    color: #064e3b;
  }}
  .decision-title {{
    font-size: 16px;
    font-weight: 800;
    margin-bottom: 6px;
  }}
  h3.sec-title {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px;
    text-transform: uppercase;
    background: #0f172a;
    color: #ffffff;
    padding: 6px 10px;
    margin: 20px 0 10px 0;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 14px;
    font-size: 12.5px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }}
  th, td {{
    border: 1px solid #475569;
    padding: 7px 9px;
    text-align: left;
    vertical-align: top;
  }}
  th {{
    background: #f1f5f9;
    font-weight: 700;
  }}
  code, .mono {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 11.5px;
    word-break: break-all;
  }}
  .sig-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 18px;
    margin-top: 28px;
    page-break-inside: avoid;
  }}
  .sig-box {{
    border: 1px solid #334155;
    padding: 12px;
    min-height: 125px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 12px;
  }}
  .sig-role {{
    font-weight: 700;
    border-bottom: 1px solid #cbd5e1;
    padding-bottom: 4px;
    margin-bottom: 8px;
  }}
  @media print {{
    body {{ background: #ffffff; padding: 0; }}
    .page {{ border: none; max-width: 100%; padding: 10mm; }}
  }}
</style>
</head>
<body>
<div class="page">
  <div class="official-header">
    <h1>KURUMSAL SİBER GÜVENLİK VE YAZILIM BÜTÜNLÜK DENETİMİ</h1>
    <h2>FORTISOAR / FORTIGATE SANAL CİHAZ VE OVA İMAJI TEKNİK BÜTÜNLÜK VE KABUL TUTANAĞI</h2>
  </div>

  <div class="decision-box {decision_cls}">
    <div class="decision-title">KOMİSYON TEKNİK KARARI: {decision_title}</div>
    <div><strong>Bileşik Adli Risk Skoru:</strong> <code>{score}/100</code> &nbsp;|&nbsp; <strong>Kritik Bulgu:</strong> <code>{crit}</code> &nbsp;|&nbsp; <strong>Yüksek Bulgu:</strong> <code>{high}</code> &nbsp;|&nbsp; <strong>Toplam Bulgu:</strong> <code>{total}</code></div>
    <div style="margin-top: 6px;">{exec_summary}</div>
  </div>

  <h3 class="sec-title">1. İncelenen Cihaz / Kurulum İmajı ve Denetim Kimlik Bilgileri</h3>
  <table>
    <tbody>
      <tr><th style="width: 28%;">İncelenen Hedef Dizin / OVA İmajı</th><td><code>{root}</code></td></tr>
      <tr><th>Sistem Hostname / Çekirdek</th><td><code>{hostname} ({kernel})</code></td></tr>
      <tr><th>Denetim Zaman Damgası (UTC Unix)</th><td><code>{ts}</code></td></tr>
      <tr><th>Referans Baseline Manifest Profili</th><td><code>{baseline_lbl}</code></td></tr>
      <tr><th>Denetim Aracı ve Öz-Bütünlük</th><td><code>{tool} v{ver}</code> — SHA-256: <span class="mono">{self_sha}</span></td></tr>
      <tr><th>Salt-Okunur Müdahalesizlik Garantisi</th><td><code>target_mutated = {mutated}</code> | Pre-SHA256 = Post-SHA256: <span class="mono">{pre_hash}</span></td></tr>
    </tbody>
  </table>

  <h3 class="sec-title">2. Üç Eksenli Anlık Crack, Lisans ve Tedarik Zinciri Doğrulama Tablosu</h3>
  <table>
    <thead>
      <tr><th style="width: 34%;">Kontrol Ekseni</th><th>Teknik Tespit ve Muayene Sonucu</th></tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>1. FortiSOAR <code>cyops-auth</code> / <code>/server/csdassrv.py</code> Çalışma Zamanı Lisans Kancası</strong></td>
        <td>{das_status}</td>
      </tr>
      <tr>
        <td><strong>2. FortiGate / FortiSOAR Lisans, Seri Numarası, ELF64 ve Golden Image Klon Denetimi</strong></td>
        <td>{lic_status}</td>
      </tr>
      <tr>
        <td><strong>3. Tedarik Zinciri, Kasa (Vault Master Key) ve Konnektör Arka Kapı Denetimi</strong></td>
        <td>{vault_status}</td>
      </tr>
    </tbody>
  </table>
"#,
        hostname = escape_html(&bundle.context.hostname),
        decision_cls = decision_banner_class,
        decision_title = escape_html(decision_title),
        score = vs.composite_risk_score,
        crit = vs.critical_count,
        high = vs.high_count,
        total = vs.total_findings,
        exec_summary = escape_html(&vs.executive_conclusion_tr),
        root = escape_html(&bundle.context.root_path),
        kernel = escape_html(&bundle.context.kernel_release),
        ts = bundle.context.scan_timestamp_unix,
        baseline_lbl = escape_html(&extract_baseline_profile_label(bundle)),
        tool = escape_html(bundle.tool_name),
        ver = escape_html(bundle.tool_version),
        self_sha = escape_html(&bundle.self_integrity.self_sha256_libc_hex),
        mutated = att.target_mutated,
        pre_hash = escape_html(&att.pre_state_digest_hex),
        das_status = escape_html(&das_crack_status),
        lic_status = escape_html(&fgt_lic_status),
        vault_status = escape_html(&vault_status),
    );

    let _ = writeln!(
        out,
        "  <h3 class=\"sec-title\">3. Tespit Edilen Adli Bulgular ve RFC 6962 Kanıt Özeti</h3>"
    );
    if me.sealed_findings.is_empty() {
        let _ = writeln!(
            out,
            "  <p>19 çekirdek (+ 3 OVA/atıf) adli bilişim motorunun tamamında hiçbir lisans doğrulama müdahalesi (crack), <code>cyops-auth</code> / <code>csdassrv.py</code> kancası, klonlama veya arka kapı bulgusuna rastlanmamıştır.</p>"
        );
    } else {
        let _ = writeln!(
            out,
            "  <table><thead><tr><th>No</th><th>Önem</th><th>Motor</th><th>Kural Kodu ve Açıklama</th><th>Hedef Dosya</th><th>RFC 6962 Yaprak SHA-256</th></tr></thead><tbody>"
        );
        for sf in &me.sealed_findings {
            let f = &sf.finding;
            let _ = writeln!(
                out,
                "    <tr><td><code>{}</code></td><td><strong>{}</strong></td><td><code>{}</code></td><td><code>{}</code><br>{}</td><td><code>{}</code></td><td class=\"mono\">{}</td></tr>",
                escape_html(&sf.id),
                escape_html(f.severity.as_str()),
                escape_html(f.engine.as_str()),
                escape_html(&f.code),
                escape_html(&f.summary),
                escape_html(&f.target),
                escape_html(&sf.leaf_hash_hex),
            );
        }
        let _ = writeln!(out, "  </tbody></table>");
    }

    let _ = write!(
        out,
        r#"  <h3 class="sec-title">4. Kriptografik Mühür ve Muayene Kabul Komisyonu İmza Bloğu</h3>
  <table>
    <tbody>
      <tr><th style="width: 28%;">RFC 6962 Merkle Root (SHA-256)</th><td class="mono">{merkle_root}</td></tr>
      <tr><th>Ağaç Yaprak Sayısı / Derinlik</th><td><code>{leaf_count}</code> yaprak / <code>{depth}</code> seviye</td></tr>
      <tr><th>Teknik Kapsam ve Hukuki Sınır</th><td>İşbu tutanak, sıfır harici bağımlılıklı deterministik adli bilişim motoru tarafından salt-okunur modda üretilmiş ve RFC 6962 İkili Merkle Ağacı ile kriptografik olarak mühürlenmiştir. Araç yalnızca teknik bulgu ve yapısal anomali korelasyonu sunar; nihai hukuki nitelendirme ilgili hukuk müşavirliği ve yargı mercilerine aittir.</td></tr>
    </tbody>
  </table>

  <div class="sig-grid">
    <div class="sig-box">
      <div class="sig-role">Muayene ve Kabul Komisyonu Başkanı</div>
      <div>Adı Soyadı: ________________________</div>
      <div>Unvanı / Sicil: _____________________</div>
      <div style="margin-top: 22px;">İmza / Tarih:</div>
    </div>
    <div class="sig-box">
      <div class="sig-role">Siber Güvenlik / Teknik Denetim Üyesi</div>
      <div>Adı Soyadı: ________________________</div>
      <div>Unvanı / Sicil: _____________________</div>
      <div style="margin-top: 22px;">İmza / Tarih:</div>
    </div>
    <div class="sig-box">
      <div class="sig-role">Birim / Sistem Yönetimi Üyesi</div>
      <div>Adı Soyadı: ________________________</div>
      <div>Unvanı / Sicil: _____________________</div>
      <div style="margin-top: 22px;">İmza / Tarih:</div>
    </div>
  </div>
</div>
</body>
</html>
"#,
        merkle_root = escape_html(&me.merkle_root_hex),
        leaf_count = me.leaf_count,
        depth = me.tree_depth,
    );

    out
}
