//! Engine 3: Causal Breach Synthesis & Legal/Technical Verdict Classifier.
//!
//! Cross-correlates findings from all 19 forensic engines across Phases 1–4 to
//! synthesize 3 deterministic DFIR / legal-compliance causal verdicts that refute
//! the "accidental misconfiguration" defense, alongside a 0–100 composite risk score:
//!   1. `VERDICT_WILFUL_LICENSE_CRACK_AND_CLONE`
//!   2. `VERDICT_ACTIVE_SUPPLY_CHAIN_IMPLANT`
//!   3. `VERDICT_DECEPTIVE_SECURITY_BLINDNESS`

use std::collections::BTreeSet;

use fsr_deep_audit::schema::{EngineId, JsonValue, Severity};

use crate::merkle_evidence::SealedFinding;

pub const CODE_WILFUL_CRACK_AND_CLONE: &str = "VERDICT_WILFUL_LICENSE_CRACK_AND_CLONE";
pub const CODE_ACTIVE_SUPPLY_CHAIN_IMPLANT: &str = "VERDICT_ACTIVE_SUPPLY_CHAIN_IMPLANT";
pub const CODE_DECEPTIVE_SECURITY_BLINDNESS: &str = "VERDICT_DECEPTIVE_SECURITY_BLINDNESS";

/// Confidence tier of a synthesized causal verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictConfidence {
    NotTriggered,
    CorroboratedIndicator,
    ConfirmedMultiLayerBeyondDoubt,
}

impl VerdictConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            VerdictConfidence::NotTriggered => "NOT_TRIGGERED",
            VerdictConfidence::CorroboratedIndicator => "HIGH_CONFIDENCE_INDICATOR",
            VerdictConfidence::ConfirmedMultiLayerBeyondDoubt => {
                "CONFIRMED_MULTI_LAYER_BEYOND_DOUBT"
            }
        }
    }
}

/// One of the 3 primary causal forensic & legal verdicts.
#[derive(Debug, Clone)]
pub struct CausalVerdict {
    pub verdict_code: &'static str,
    pub title_tr: &'static str,
    pub triggered: bool,
    pub confidence: VerdictConfidence,
    pub category_score: u32,
    pub corroborated_layers: Vec<String>,
    pub supporting_finding_ids: Vec<String>,
    pub causal_synthesis_tr: String,
    pub misconfig_refutation_tr: String,
    pub legal_and_compliance_impact_tr: String,
}

impl CausalVerdict {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            (
                "verdict_code".to_string(),
                JsonValue::str(self.verdict_code),
            ),
            ("title_tr".to_string(), JsonValue::str(self.title_tr)),
            ("triggered".to_string(), JsonValue::Bool(self.triggered)),
            (
                "confidence".to_string(),
                JsonValue::str(self.confidence.as_str()),
            ),
            (
                "category_score".to_string(),
                JsonValue::Uint(self.category_score as u64),
            ),
            (
                "corroborated_layers".to_string(),
                JsonValue::Array(
                    self.corroborated_layers
                        .iter()
                        .map(JsonValue::str)
                        .collect(),
                ),
            ),
            (
                "supporting_finding_ids".to_string(),
                JsonValue::Array(
                    self.supporting_finding_ids
                        .iter()
                        .map(JsonValue::str)
                        .collect(),
                ),
            ),
            (
                "causal_synthesis_tr".to_string(),
                JsonValue::str(&self.causal_synthesis_tr),
            ),
            (
                "misconfig_refutation_tr".to_string(),
                JsonValue::str(&self.misconfig_refutation_tr),
            ),
            (
                "legal_and_compliance_impact_tr".to_string(),
                JsonValue::str(&self.legal_and_compliance_impact_tr),
            ),
        ])
    }
}

/// Complete synthesized verdict matrix across all 19 engines.
#[derive(Debug, Clone)]
pub struct VerdictSummary {
    pub status: &'static str,
    pub composite_risk_score: u32,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub distinct_compromised_engines: usize,
    pub triggered_verdict_codes: Vec<&'static str>,
    pub executive_conclusion_tr: String,
    pub verdicts: [CausalVerdict; 3],
}

impl VerdictSummary {
    /// Legacy-compatible `verdict` JSON object (`schema_version: "1.0.0"` superset).
    pub fn to_legacy_compatible_verdict_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("status".to_string(), JsonValue::str(self.status)),
            (
                "risk_score".to_string(),
                JsonValue::Uint(self.composite_risk_score as u64),
            ),
            (
                "composite_risk_score".to_string(),
                JsonValue::Uint(self.composite_risk_score as u64),
            ),
            (
                "total_findings".to_string(),
                JsonValue::Uint(self.total_findings as u64),
            ),
            (
                "critical_count".to_string(),
                JsonValue::Uint(self.critical_count as u64),
            ),
            (
                "high_count".to_string(),
                JsonValue::Uint(self.high_count as u64),
            ),
            (
                "medium_count".to_string(),
                JsonValue::Uint(self.medium_count as u64),
            ),
            (
                "low_count".to_string(),
                JsonValue::Uint(self.low_count as u64),
            ),
            (
                "info_count".to_string(),
                JsonValue::Uint(self.info_count as u64),
            ),
            (
                "distinct_compromised_engines".to_string(),
                JsonValue::Uint(self.distinct_compromised_engines as u64),
            ),
            (
                "triggered_verdicts".to_string(),
                JsonValue::Array(
                    self.triggered_verdict_codes
                        .iter()
                        .copied()
                        .map(JsonValue::str)
                        .collect(),
                ),
            ),
        ])
    }

    /// Detailed Phase-5 `verdict_summary` JSON matrix.
    pub fn to_detailed_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("overall_status".to_string(), JsonValue::str(self.status)),
            (
                "composite_risk_score".to_string(),
                JsonValue::Uint(self.composite_risk_score as u64),
            ),
            (
                "distinct_compromised_engines".to_string(),
                JsonValue::Uint(self.distinct_compromised_engines as u64),
            ),
            (
                "triggered_verdict_codes".to_string(),
                JsonValue::Array(
                    self.triggered_verdict_codes
                        .iter()
                        .copied()
                        .map(JsonValue::str)
                        .collect(),
                ),
            ),
            (
                "executive_conclusion_tr".to_string(),
                JsonValue::str(&self.executive_conclusion_tr),
            ),
            (
                "causal_verdicts".to_string(),
                JsonValue::Array(self.verdicts.iter().map(|v| v.to_json()).collect()),
            ),
        ])
    }
}

/// Evaluates all sealed findings across the 19 engines and produces the deterministic
/// [`VerdictSummary`] and 3 causal verdicts.
pub fn classify_forensic_verdicts(sealed: &[SealedFinding]) -> VerdictSummary {
    let mut critical_count = 0usize;
    let mut high_count = 0usize;
    let mut medium_count = 0usize;
    let mut low_count = 0usize;
    let mut info_count = 0usize;
    let mut base_severity_points = 0u32;
    let mut active_engines: BTreeSet<EngineId> = BTreeSet::new();

    for sf in sealed {
        match sf.finding.severity {
            Severity::Critical => {
                critical_count += 1;
                active_engines.insert(sf.finding.engine);
            }
            Severity::High => {
                high_count += 1;
                active_engines.insert(sf.finding.engine);
            }
            Severity::Medium => {
                medium_count += 1;
                active_engines.insert(sf.finding.engine);
            }
            Severity::Low => low_count += 1,
            Severity::Info => info_count += 1,
        }
        base_severity_points =
            base_severity_points.saturating_add(sf.finding.severity.risk_weight());
    }

    let v_crack = evaluate_wilful_crack_and_clone(sealed);
    let v_supply = evaluate_active_supply_chain_implant(sealed);
    let v_blind = evaluate_deceptive_security_blindness(sealed);

    let mut triggered_codes = Vec::new();
    let mut synergy_bonus = 0u32;
    if v_crack.triggered {
        triggered_codes.push(v_crack.verdict_code);
        synergy_bonus = synergy_bonus.saturating_add(15);
    }
    if v_supply.triggered {
        triggered_codes.push(v_supply.verdict_code);
        synergy_bonus = synergy_bonus.saturating_add(20);
    }
    if v_blind.triggered {
        triggered_codes.push(v_blind.verdict_code);
        synergy_bonus = synergy_bonus.saturating_add(10);
    }

    let composite_risk_score = if sealed.is_empty() || base_severity_points == 0 {
        0
    } else {
        base_severity_points.saturating_add(synergy_bonus).min(100)
    };

    let status = if critical_count > 0 || !triggered_codes.is_empty() {
        "COMPROMISED_OR_CRACKED"
    } else if high_count > 0 || medium_count > 0 {
        "SUSPICIOUS_ANOMALIES"
    } else {
        "CLEAN"
    };

    let executive_conclusion_tr = build_executive_conclusion_tr(
        status,
        composite_risk_score,
        active_engines.len(),
        &v_crack,
        &v_supply,
        &v_blind,
    );

    VerdictSummary {
        status,
        composite_risk_score,
        total_findings: sealed.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
        distinct_compromised_engines: active_engines.len(),
        triggered_verdict_codes: triggered_codes,
        executive_conclusion_tr,
        verdicts: [v_crack, v_supply, v_blind],
    }
}

// ============================================================================
// Verdict 1: VERDICT_WILFUL_LICENSE_CRACK_AND_CLONE
// ============================================================================

fn evaluate_wilful_crack_and_clone(sealed: &[SealedFinding]) -> CausalVerdict {
    let mut layers: BTreeSet<String> = BTreeSet::new();
    let mut major_phases: BTreeSet<u8> = BTreeSet::new();
    let mut supporting_ids: Vec<String> = Vec::new();

    for sf in sealed {
        if matches!(sf.finding.severity, Severity::Low | Severity::Info) {
            continue;
        }
        let code = sf.finding.code.as_str();
        let matched_layer = match sf.finding.engine {
            EngineId::HwIntegrity => {
                major_phases.insert(1);
                Some("FAZ1_DONANIM_KIMLIGI_SYSCALL_SPOOF")
            }
            EngineId::ElfVmaDiff => {
                major_phases.insert(1);
                Some("FAZ1_ELF64_BELLEK_VE_GOT_YAMASI")
            }
            EngineId::PycInspector => {
                major_phases.insert(1);
                Some("FAZ1_PYTHON_PEP552_BYTECODE_MANIPULASYONU")
            }
            EngineId::RpmForensics => {
                major_phases.insert(1);
                Some("FAZ1_RPM_PAKET_VE_PGP_BUTUNLUK_IHLALI")
            }
            EngineId::CaTrustAudit => {
                major_phases.insert(2);
                Some("FAZ2_SAHTE_KOK_SERTIFIKA_ENJEKSIYONU")
            }
            EngineId::SslBypassCheck => {
                major_phases.insert(2);
                Some("FAZ2_LIBSSL_X509_DOGRULAMA_YAMASI")
            }
            EngineId::NetHijack | EngineId::FdnLiveProbe | EngineId::FortigateCfgAudit => {
                if code != "HIGH_FGT_CONFIG_UNREADABLE" && code != "HIGH_FGT_RATING_UNREADABLE" {
                    major_phases.insert(2);
                    Some("FAZ2_FDN_FDS_LISANS_EMULATOR_YONLENDIRMESI")
                } else {
                    None
                }
            }
            EngineId::TimeFreezeAudit => {
                major_phases.insert(3);
                Some("FAZ3_ZAMAN_DONDURMA_VE_DENEME_SURUMU_ISTISMARI")
            }
            EngineId::FgvmLicenseInspect | EngineId::RemoteFingerprinter => {
                major_phases.insert(3);
                Some("FAZ3_SAHTE_VEYA_KORSAN_FGVM_LISANS_DOSYASI")
            }
            EngineId::ClusterCorrelator => {
                if matches!(
                    code,
                    "CRITICAL_CLONED_GOLDEN_IMAGE_PG_CLUSTER"
                        | "CRITICAL_DUPLICATE_FGVM_SERIAL_CLONE"
                        | "HIGH_CLONED_VM_FILESYSTEM_UUID"
                ) {
                    major_phases.insert(3);
                    Some("FAZ3_KLONLANMIS_GOLDEN_IMAGE_DOGUMLARI")
                } else {
                    None
                }
            }
            EngineId::BirthmarkExtractor => {
                if code == "HIGH_PG_CONTROL_CRC32C_MISMATCH" {
                    major_phases.insert(3);
                    Some("FAZ3_PG_CONTROL_IKILI_MUDAHALE")
                } else {
                    None
                }
            }
            EngineId::OvaStreamInspector => {
                major_phases.insert(8);
                Some("FAZ8_OVA_MANIFEST_VE_OVF_DONANIM_MUDAHALESI")
            }
            EngineId::VmdkCarver => {
                major_phases.insert(8);
                Some("FAZ8_VMDK_SIFIR_MOUNT_IMZA_VE_ELF_OYMA")
            }
            EngineId::CrackerAttribution => {
                major_phases.insert(8);
                Some("FAZ8_CRACK_KIT_DNA_VE_KIRICI_GRUP_ATFI")
            }
            EngineId::WebAuthBackdoor => {
                if matches!(
                    code,
                    "CRITICAL_PYTHON_STARTUP_HOOK_LICENSE_BYPASS"
                        | "CRITICAL_DAS_RUNTIME_MONKEYPATCH_BYPASS"
                        | "CRITICAL_CYOPS_SERVER_UNAUTHORIZED_IMPORT_HOOK"
                        | "CRITICAL_CYOPS_SERVER_ROGUE_SCRIPT_DROP"
                        | "CRITICAL_PYTHON_PTH_STARTUP_HOOK"
                        | "HIGH_CYOPS_INIT_PY_CODE_INJECTION"
                        | "CRITICAL_LIVE_DAS_TORNADO_LICENSE_INTERCEPT_ACTIVE"
                        | "CRITICAL_CYOPS_FDNCLIENT_JAR_TAMPERED"
                        | "CRITICAL_CYOPS_DAS_INI_AUTH_BYPASS"
                        | "CRITICAL_CYOPS_VENV_INTERPRETER_HIJACK"
                        | "CRITICAL_CYOPS_UTILITY_SCRIPT_TAMPERED"
                        | "CRITICAL_CYOPS_SQL_SEED_OR_MIGRATION_TAMPER"
                        | "CRITICAL_CYOPS_CYTHON_SO_BINARY_REPLACED"
                ) {
                    major_phases.insert(1);
                    major_phases.insert(4);
                    layers.insert("FAZ1_PYTHON_STARTUP_CYTHON_SO_GOLGELEME".to_string());
                    Some("FAZ4_CYOPS_AUTH_SERVER_CSDASSRV_IMPORT_CRACK")
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(layer_tag) = matched_layer {
            layers.insert(layer_tag.to_string());
            supporting_ids.push(sf.id.clone());
        }
    }

    let corroborated_layers: Vec<String> = layers.into_iter().collect();
    // Multi-layer threshold: >= 2 distinct cracking sub-layers across Phases 1/2/3
    let triggered = corroborated_layers.len() >= 2;
    let confidence = if major_phases.len() >= 2 && corroborated_layers.len() >= 2 {
        VerdictConfidence::ConfirmedMultiLayerBeyondDoubt
    } else if triggered {
        VerdictConfidence::CorroboratedIndicator
    } else {
        VerdictConfidence::NotTriggered
    };

    let category_score = if !triggered {
        (corroborated_layers.len() as u32) * 20
    } else {
        (40 + (corroborated_layers.len() as u32) * 12).min(100)
    };

    let (causal_synthesis_tr, misconfig_refutation_tr) = if triggered {
        (
            format!(
                "{} ayrı teknik katmanda ({}) eşzamanlı ve birbirini tamamlayan lisans doğrulama \
                 atlatma, ikili yamalama veya Golden Image klonlama bulgusu saptandı ({} adet kanıtlanmış bulgu).",
                corroborated_layers.len(),
                corroborated_layers.join(", "),
                supporting_ids.len()
            ),
            "Rutin bir sistem yönetimi veya standart yapılandırma hatasıyla x86_64 ELF/libssl makine kodu yaması, \
             Python PEP 552 bytecode değişikliği, sahte X.509 kök sertifika eklenmesi, donanım kimliği \
             (UUID/MAC) kancalaması veya 64-bit PostgreSQL pg_control klonlamasının eşzamanlı oluşması \
             teknik olarak açıklanamaz; bulgular çok katmanlı sistem dışı müdahale göstergesidir. \
             (Not: Araç yalnızca teknik bulgu ve yapısal korelasyon üretir; hukuki nitelendirme yargı mercilerine aittir.)"
                .to_string(),
        )
    } else {
        (
            "Çok katmanlı lisans doğrulama atlatma veya klonlama eşiği tetiklenmedi.".to_string(),
            "Çok katmanlı sistem dışı müdahaleye işaret eden eşzamanlı katman korelasyonu bulunmadı."
                .to_string(),
        )
    };

    CausalVerdict {
        verdict_code: CODE_WILFUL_CRACK_AND_CLONE,
        title_tr: "Çok Katmanlı Lisans Doğrulama Müdahalesi ve Golden Image Klonlama Korelasyonu",
        triggered,
        confidence,
        category_score,
        corroborated_layers,
        supporting_finding_ids: supporting_ids,
        causal_synthesis_tr,
        misconfig_refutation_tr,
        legal_and_compliance_impact_tr:
            "Yazılım lisans sözleşmesi uyumluluğu, FSEK ve bilişim mevzuatı kapsamında hukuk müşavirliği \
             tarafından değerlendirilmesi önerilen teknik bulgular; kurumsal iç denetim ve tedarikçi kabul kriterleri."
                .to_string(),
    }
}

// ============================================================================
// Verdict 2: VERDICT_ACTIVE_SUPPLY_CHAIN_IMPLANT
// ============================================================================

fn evaluate_active_supply_chain_implant(sealed: &[SealedFinding]) -> CausalVerdict {
    let mut layers: BTreeSet<String> = BTreeSet::new();
    let mut supporting_ids: Vec<String> = Vec::new();
    let mut has_critical_implant = false;

    for sf in sealed {
        if matches!(sf.finding.severity, Severity::Low | Severity::Info) {
            continue;
        }
        let code = sf.finding.code.as_str();
        let matched_layer = match sf.finding.engine {
            EngineId::ClusterCorrelator if code == "CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY" => {
                has_critical_implant = true;
                Some("FAZ3_ORTAK_SOAR_KASA_ANAHTARI_IFSA")
            }
            EngineId::BirthmarkExtractor if code == "HIGH_WEAK_HARDCODED_CRYPTO_SEED" => {
                Some("FAZ3_SABIT_KRIPTOGRAFIK_KASA_TOHUMU")
            }
            EngineId::ConnectorSkimmerAudit => {
                if sf.finding.severity == Severity::Critical {
                    has_critical_implant = true;
                }
                Some("FAZ4_SOAR_KONNEKTOR_KIMLIK_SIZDIRICI_VE_OBFUSCATION")
            }
            EngineId::WebAuthBackdoor => {
                if sf.finding.severity == Severity::Critical {
                    has_critical_implant = true;
                }
                Some("FAZ4_NGINX_TRAFIK_IKIZLEME_VE_DJANGO_AUTH_BAYPAS")
            }
            EngineId::PostgresPersistence => {
                if sf.finding.severity == Severity::Critical {
                    has_critical_implant = true;
                }
                Some("FAZ4_POSTGRESQL_PRELOAD_HBA_TRIGGER_ARKA_KAPISI")
            }
            EngineId::OsPersistenceAudit => {
                if sf.finding.severity == Severity::Critical {
                    has_critical_implant = true;
                }
                Some("FAZ4_OS_SYSTEMD_PAM_UID0_SSH_KALICILIK_IMPLANTI")
            }
            EngineId::FortigateBackdoorAudit => {
                has_critical_implant = true;
                Some("FAZ4_FORTIGATE_SAHTE_SUPER_ADMIN_VE_OTOMASYON_SIZINTISI")
            }
            EngineId::CrackerAttribution
                if code == "CRITICAL_SAME_CRACKER_TOOLKIT_ATTRIBUTION" =>
            {
                has_critical_implant = true;
                Some("FAZ8_ORTAK_KIRICI_ARAC_SETI_TEDARIK_ZINCIRI_ATFI")
            }
            EngineId::VmdkCarver if code == "CRITICAL_VMDK_CARVED_ROGUE_CA" => {
                has_critical_implant = true;
                Some("FAZ8_VMDK_ICINDE_GOMULU_SAHTE_KOK_SERTIFIKA")
            }
            _ => None,
        };

        if let Some(layer_tag) = matched_layer {
            layers.insert(layer_tag.to_string());
            supporting_ids.push(sf.id.clone());
        }
    }

    let corroborated_layers: Vec<String> = layers.into_iter().collect();
    let triggered = has_critical_implant || corroborated_layers.len() >= 2;
    let confidence = if has_critical_implant && corroborated_layers.len() >= 2 {
        VerdictConfidence::ConfirmedMultiLayerBeyondDoubt
    } else if triggered {
        VerdictConfidence::CorroboratedIndicator
    } else {
        VerdictConfidence::NotTriggered
    };

    let category_score = if !triggered {
        0
    } else {
        (55 + (corroborated_layers.len() as u32) * 10).min(100)
    };

    let (causal_synthesis_tr, misconfig_refutation_tr) = if triggered {
        (
            format!(
                "Cihaz imajına üçüncü şahıslar tarafından yerleştirilmiş {} farklı arka kapı/kalıcılık \
                 veya paylaşımlı kasa şifreleme anahtarı vektörü ({}) tespit edildi ({} bulgu). \
                 SOAR kasasında tutulan Active Directory, EDR, SIEM ve Güvenlik Duvarı API anahtarları \
                 doğrudan ele geçirilmeye açıktır.",
                corroborated_layers.len(),
                corroborated_layers.join(", "),
                supporting_ids.len()
            ),
            "SOAR konnektörleri içinde gizlenmiş payload zincirleri, PAM pam_unix.so ikili kimlik \
             doğrulama yamaları, hayalet UID=0 hesapları, Django sihirli başlık baypasları veya \
             başka kurumlarla paylaşılan kasa şifreleme anahtarları hiçbir standart yönetici hatasıyla \
             açıklanamaz; doğrudan tedarik zinciri arka kapısıdır."
                .to_string(),
        )
    } else {
        (
            "Tedarik zinciri arka kapısı, kimlik bilgisi sızdıran konnektör veya kalıcılık implantı tespit edilmedi."
                .to_string(),
            "Arka kapı veya yetkisiz erişim implantı bulgusuna rastlanmadı.".to_string(),
        )
    };

    CausalVerdict {
        verdict_code: CODE_ACTIVE_SUPPLY_CHAIN_IMPLANT,
        title_tr: "Aktif Tedarik Zinciri İhlali, Arka Kapı ve Kasa Anahtarı Tehlikesi",
        triggered,
        confidence,
        category_score,
        corroborated_layers,
        supporting_finding_ids: supporting_ids,
        causal_synthesis_tr,
        misconfig_refutation_tr,
        legal_and_compliance_impact_tr:
            "KVKK m.12 veri güvenliği ve ihlal bildirimi yükümlülüğü, GDPR Art.32/33, NIS2 tedarik \
             zinciri güvenliği, ISO/IEC 27001 A.5.19–A.8.28 ve acil kurumsal parola/anahtar rotasyonu gerekliliği."
                .to_string(),
    }
}

// ============================================================================
// Verdict 3: VERDICT_DECEPTIVE_SECURITY_BLINDNESS
// ============================================================================

fn evaluate_deceptive_security_blindness(sealed: &[SealedFinding]) -> CausalVerdict {
    let mut fdn_severance_layers: BTreeSet<String> = BTreeSet::new();
    let mut ui_masking_layers: BTreeSet<String> = BTreeSet::new();
    let mut supporting_ids: Vec<String> = Vec::new();

    for sf in sealed {
        if matches!(sf.finding.severity, Severity::Low | Severity::Info) {
            continue;
        }
        let code = sf.finding.code.as_str();
        match sf.finding.engine {
            EngineId::NetHijack => {
                fdn_severance_layers.insert("FDN_AG_DNAT_DNS_EBPF_KARARTMASI".to_string());
                supporting_ids.push(sf.id.clone());
            }
            EngineId::FdnLiveProbe => {
                fdn_severance_layers.insert("FDN_CANLI_DNS_TLS_SAHTE_UC_NOKTA".to_string());
                supporting_ids.push(sf.id.clone());
            }
            EngineId::FortigateCfgAudit => {
                if code != "HIGH_FGT_CONFIG_UNREADABLE" && code != "HIGH_FGT_RATING_UNREADABLE" {
                    fdn_severance_layers.insert("FDS_FORTIGUARD_SAHTE_EMULATOR_YONLENDIRMESI".to_string());
                    supporting_ids.push(sf.id.clone());
                }
            }
            EngineId::CaTrustAudit | EngineId::SslBypassCheck => {
                ui_masking_layers.insert("TLS_SERTIFIKA_DOGRULAMA_MASKESI".to_string());
                supporting_ids.push(sf.id.clone());
            }
            EngineId::PycInspector => {
                ui_masking_layers.insert("ARAYUZ_LISANS_DURUMU_BYTECODE_MASKESI".to_string());
                supporting_ids.push(sf.id.clone());
            }
            EngineId::TimeFreezeAudit | EngineId::FgvmLicenseInspect | EngineId::RemoteFingerprinter => {
                ui_masking_layers.insert("SAHTE_LISANS_VE_ZAMAN_DONDURMA_MASKESI".to_string());
                supporting_ids.push(sf.id.clone());
            }
            _ => {}
        }
    }

    let triggered = !fdn_severance_layers.is_empty();
    let confidence = if !fdn_severance_layers.is_empty() && !ui_masking_layers.is_empty() {
        VerdictConfidence::ConfirmedMultiLayerBeyondDoubt
    } else if triggered {
        VerdictConfidence::CorroboratedIndicator
    } else {
        VerdictConfidence::NotTriggered
    };

    let mut corroborated_layers: Vec<String> = fdn_severance_layers.into_iter().collect();
    corroborated_layers.extend(ui_masking_layers);

    let category_score = if !triggered {
        0
    } else {
        (50 + (corroborated_layers.len() as u32) * 10).min(100)
    };

    let (causal_synthesis_tr, misconfig_refutation_tr) = if triggered {
        (
            format!(
                "Cihaz yönetim arayüzünde aktif/lisanslı görünmeye devam ederken resmi FortiGuard (FDN/FDS) \
                 tehdit istihbaratı ve imza güncelleme kanalları kesilmiş veya sahte emülatöre yönlendirilmiştir \
                 ({}). Kurum güncel IPS, Web Filtreleme, Antivirüs ve sıfırıncı-gün istihbaratından mahrumdur.",
                corroborated_layers.join(", ")
            ),
            "Fortinet resmi ASN bloklarına (AS40934) veya *.fortiguard.net alan adlarına yönelik hedefli \
             DNS/DNAT/eBPF yönlendirmelerinin, lisans doğrulama yamalarıyla birlikte bulunması geçici bir \
             güvenlik duvarı/DNS hatası değil, sahte lisansın iptal edilmesini önlemek için kasıtlı oluşturulmuş \
             güvenlik körlüğüdür."
                .to_string(),
        )
    } else {
        (
            "FortiGuard (FDN/FDS) tehdit istihbaratı beslemesini karartan veya sahte emülatöre yönlendiren bulgu saptanmadı."
                .to_string(),
            "Tehdit istihbaratı karartması bulgusuna rastlanmadı.".to_string(),
        )
    };

    CausalVerdict {
        verdict_code: CODE_DECEPTIVE_SECURITY_BLINDNESS,
        title_tr: "Aldatıcı Güvenlik Körlüğü ve Sahte Tehdit İstihbaratı Beslemesi",
        triggered,
        confidence,
        category_score,
        corroborated_layers,
        supporting_finding_ids: supporting_ids,
        causal_synthesis_tr,
        misconfig_refutation_tr,
        legal_and_compliance_impact_tr:
            "Siber sigorta poliçesi geçersizliği (etkin olmayan güvenlik kontrolü beyanı), BDDK/EPDK/SPK \
             veya sektörel regülasyon denetimlerinde yanıltıcı güvenlik kontrolü görünümü ve operasyonel ihmal riski."
                .to_string(),
    }
}

fn build_executive_conclusion_tr(
    status: &str,
    composite_risk_score: u32,
    compromised_engines: usize,
    v_crack: &CausalVerdict,
    v_supply: &CausalVerdict,
    v_blind: &CausalVerdict,
) -> String {
    if status == "CLEAN" {
        return "19 çekirdek (+ 3 OVA/atıf) adli bilişim motorunun tamamında lisans doğrulama müdahalesi, klonlama, \
                tedarik zinciri arka kapısı veya FortiGuard yönlendirmesine dair herhangi bir teknik bulguya rastlanmadı (Bileşik Risk: 0/100)."
            .to_string();
    }

    let mut clauses = Vec::new();
    if v_crack.triggered {
        clauses.push("çok katmanlı lisans doğrulama ve klonlama müdahalesi");
    }
    if v_supply.triggered {
        clauses.push("tedarik zinciri arka kapısı ve kurumsal kimlik bilgisi sızıntısı riski");
    }
    if v_blind.triggered {
        clauses.push("FortiGuard tehdit istihbaratı karartmasına dayalı güvenlik körlüğü");
    }

    if clauses.is_empty() {
        format!(
            "İncelenen sistemde {} farklı motorda şüpheli bütünlük anomalileri tespit edildi \
             (Bileşik Risk Skoru: {}/100). İlgili kanıt kayıtlarının teknik incelemeye alınması önerilir.",
            compromised_engines, composite_risk_score
        )
    } else {
        format!(
            "KRİTİK TEKNİK DENETİM BULGUSU (Bileşik Risk Skoru: {}/100, Etkilenen Motor: {}): İncelenen cihazda {} \
             kriptografik ve yapısal kanıtlarla tespit edilmiştir. Sistem ağdan izole edilmeli, \
             SOAR kasası ve entegre kurumsal sistemlerdeki kimlik bilgileri yenilenmeli; hukuki değerlendirme \
             için bulgular kurum hukuk müşavirliğine iletilmelidir.",
            composite_risk_score,
            compromised_engines,
            clauses.join(", ")
        )
    }
}
