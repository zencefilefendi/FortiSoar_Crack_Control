//! Engine 3: FortiGate VM (`FGVM`) Serial Number & License Blob Analyzer.
//!
//! Inspects FortiGate VM `.lic` files (PEM `FGT VM LICENSE` armor, Base64, ASN.1 DER
//! PKCS#7/CMS `SignedData`, embedded X.509 certificates, and key-value headers),
//! FortiOS configurations, and hardware resource allocations to detect:
//!   a) `FGVMEV` evaluation/trial abuse in production deployments and pirated/keygen
//!      `FGVM` serial numbers (`FGVM00...`, invalid 16-char structure, hex/non-digit
//!      serial counters, monotonic/repeated keygen runs, failed Luhn check, or
//!      unsigned `.lic` payloads),
//!   b) Patched-kernel vCPU / RAM limit bypasses where allocated hardware exceeds the
//!      licensed `FGVM01` / `FGVM02` / `FGVM04` / `FGVM08` / `FGVM16` / `FGVM32` /
//!      `FGVMEV` model cap.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use fsr_deep_audit::crypto::sha256_hex;
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};
use fsr_net_crypto_audit::asn1_x509::{
    base64_decode, decode_oid_dotted, extract_pem_certificates, parse_der_tlv, parse_x509_der,
    X509CertInfo,
};

use crate::birthmark_extractor::{display_under_root, join_rooted};

/// Known leaked/keygen FGVM serial numbers & synthetic counter suffixes seen in cracked OVAs.
const KNOWN_PIRATED_TAILS: &[&str] = &[
    "0000000000",
    "0000000001",
    "0000000002",
    "0000000003",
    "0000001234",
    "0123456789",
    "1234567890",
    "9876543210",
    "1111111111",
    "2222222222",
    "5555555555",
    "8888888888",
    "9999999999",
];

/// Parsed FGVM model tier and hardware licensing caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FgvmModelSpec {
    pub prefix: &'static str,
    pub max_vcpus: Option<u32>,
    pub max_ram_mb: Option<u64>,
    pub is_eval_trial: bool,
    pub is_unlicensed_zero: bool,
}

/// Structural & authenticity verdict for a single `FGVM` serial string.
#[derive(Debug, Clone)]
pub struct FgvmSerialAnalysis {
    pub raw_serial: String,
    pub normalized_serial: String,
    pub source: String,
    pub model_spec: Option<FgvmModelSpec>,
    pub format_valid: bool,
    pub luhn_digit_check: bool,
    pub keygen_or_pirated_reason: Option<String>,
}

/// Parsed `.lic` container forensic metadata.
#[derive(Debug, Clone)]
pub struct ParsedLicenseBlob {
    pub path: String,
    pub raw_sha256: String,
    pub container_format: String,
    pub has_asn1_cms_signature: bool,
    pub embedded_certs: Vec<X509CertInfo>,
    pub discovered_serials: Vec<String>,
    pub declared_cpus: Option<u32>,
    pub declared_ram_mb: Option<u64>,
}

/// Detected VM hardware allocation from config / `get hardware status` / `/proc/cpuinfo`.
#[derive(Debug, Clone, Default)]
pub struct DetectedVmHardware {
    pub allocated_vcpus: Option<u32>,
    pub allocated_ram_mb: Option<u64>,
    pub vcpu_source: Option<String>,
    pub ram_source: Option<String>,
    pub has_production_features: bool,
    pub production_indicators: Vec<String>,
}

/// Output of Engine 3 (`fgvm_license_inspect`).
pub struct FgvmLicenseInspectResult {
    pub discovered_serials: Vec<String>,
    pub license_cert_spkis: Vec<String>,
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Executes Engine 3 across optional `.lic` files, FortiGate config, hardware dump, and `root`.
pub fn run_fgvm_license_inspect(
    root: &Path,
    explicit_lic_files: &[PathBuf],
    fgt_config_path: Option<&Path>,
    fgt_hw_status_path: Option<&Path>,
) -> FgvmLicenseInspectResult {
    let mut findings = Vec::new();
    let mut serial_sources: Vec<(String, String)> = Vec::new();
    let mut license_cert_spkis: Vec<String> = Vec::new();
    let mut parsed_blobs: Vec<ParsedLicenseBlob> = Vec::new();

    // 1. Collect `.lic` files from explicit CLI flags and `<root>` (`/opt`, `/etc`, `/var`)
    let mut lic_paths: Vec<PathBuf> = explicit_lic_files.to_vec();
    for rel in ["etc", "opt", "var/lib"] {
        let dir = join_rooted(root, rel);
        collect_lic_files_bounded(&dir, 4, &mut lic_paths);
    }
    lic_paths.sort();
    lic_paths.dedup();

    for lp in &lic_paths {
        let Ok(raw) = fs::read(lp) else {
            continue;
        };
        let label = display_under_root(root, lp);
        let blob = parse_fgvm_license_blob(&label, &raw);

        for cert in &blob.embedded_certs {
            if !license_cert_spkis.contains(&cert.spki_sha256) {
                license_cert_spkis.push(cert.spki_sha256.clone());
            }
            if let Some(cn) = &cert.subject_cn {
                for tok in extract_fgvm_tokens(cn) {
                    serial_sources.push((tok, format!("{} (X.509 CN)", label)));
                }
            }
        }
        for s in &blob.discovered_serials {
            serial_sources.push((s.clone(), label.clone()));
        }

        // Flag unsigned / forged `.lic` files claiming an FGVM serial without cryptographic CMS/RSA envelope
        if !blob.discovered_serials.is_empty() && !blob.has_asn1_cms_signature {
            findings.push(
                Finding::new(
                    EngineId::FgvmLicenseInspect,
                    "CRITICAL_FGVM_UNSIGNED_OR_FORGED_LIC",
                    Severity::Critical,
                    &label,
                    format!(
                        "License file `{}` contains FGVM serial {:?} without a valid ASN.1 PKCS#7/RSA cryptographic signature envelope (format={})",
                        label, blob.discovered_serials, blob.container_format
                    ),
                )
                .with_evidence("license_file", JsonValue::str(&label))
                .with_evidence("sha256", JsonValue::str(&blob.raw_sha256))
                .with_evidence("container_format", JsonValue::str(&blob.container_format)),
            );
        }

        parsed_blobs.push(blob);
    }

    // 2. Parse FortiOS config & hardware status files for serials, production roles, and vCPU/RAM
    let mut hw = DetectedVmHardware::default();
    if let Some(cfg_p) = fgt_config_path {
        if let Ok(cfg_text) = fs::read_to_string(cfg_p) {
            let label = cfg_p.to_string_lossy().into_owned();
            for s in extract_fgvm_tokens(&cfg_text) {
                serial_sources.push((s, label.clone()));
            }
            for der in extract_pem_certificates(&cfg_text) {
                if let Ok(cert) = parse_x509_der(&der) {
                    if let Some(cn) = &cert.subject_cn {
                        for tok in extract_fgvm_tokens(cn) {
                            serial_sources.push((tok, format!("{} (cert CN)", label)));
                        }
                    }
                }
            }
            inspect_fortios_production_and_hw(&cfg_text, &label, &mut hw);
        }
    }

    if let Some(hw_p) = fgt_hw_status_path {
        if let Ok(hw_text) = fs::read_to_string(hw_p) {
            let label = hw_p.to_string_lossy().into_owned();
            for s in extract_fgvm_tokens(&hw_text) {
                serial_sources.push((s, label.clone()));
            }
            inspect_fortios_production_and_hw(&hw_text, &label, &mut hw);
        }
    }

    // Fallback to `<root>/proc/cpuinfo` & `<root>/proc/meminfo` when inspecting a VM image
    if hw.allocated_vcpus.is_none() {
        let cpuinfo_path = join_rooted(root, "proc/cpuinfo");
        if let Some(vcpus) = parse_proc_cpuinfo_count(&cpuinfo_path) {
            hw.allocated_vcpus = Some(vcpus);
            hw.vcpu_source = Some(display_under_root(root, &cpuinfo_path));
        }
    }
    if hw.allocated_ram_mb.is_none() {
        let meminfo_path = join_rooted(root, "proc/meminfo");
        if let Some(mb) = parse_proc_meminfo_mb(&meminfo_path) {
            hw.allocated_ram_mb = Some(mb);
            hw.ram_source = Some(display_under_root(root, &meminfo_path));
        }
    }

    // Deduplicate serials while preserving earliest authoritative source
    let mut seen_serials = BTreeSet::new();
    let mut unique_serials = Vec::new();
    for (ser, src) in serial_sources {
        let norm = ser.to_ascii_uppercase();
        if seen_serials.insert(norm) {
            unique_serials.push((ser, src));
        }
    }

    // 3. Evaluate every discovered `FGVM` serial against format, keygen, trial, and vCPU/RAM rules
    let mut analyzed_list = Vec::new();
    for (raw_ser, src) in &unique_serials {
        let analysis = analyze_fgvm_serial(raw_ser, src);

        if let Some(spec) = analysis.model_spec {
            // Rule 3a-1: Evaluation / Trial (`FGVMEV`) used in production or at all on audited appliance
            if spec.is_eval_trial {
                let is_prod = hw.has_production_features
                    || hw.allocated_vcpus.unwrap_or(1) > 1
                    || hw.allocated_ram_mb.unwrap_or(0) > 2048;
                let sev = if is_prod {
                    Severity::Critical
                } else {
                    Severity::High
                };
                findings.push(
                    Finding::new(
                        EngineId::FgvmLicenseInspect,
                        "CRITICAL_FGVM_EVAL_TRIAL_IN_PRODUCTION",
                        sev,
                        &analysis.normalized_serial,
                        format!(
                            "FortiGate VM Evaluation/Trial serial `{}` (`FGVMEV`) detected in {} (production_features={}, indicators={:?})",
                            analysis.normalized_serial,
                            src,
                            is_prod,
                            hw.production_indicators
                        ),
                    )
                    .with_evidence("serial_number", JsonValue::str(&analysis.normalized_serial))
                    .with_evidence("source", JsonValue::str(src.as_str()))
                    .with_evidence("production_environment", JsonValue::Bool(is_prod))
                    .with_evidence(
                        "production_indicators",
                        JsonValue::Array(
                            hw.production_indicators
                                .iter()
                                .map(|i| JsonValue::str(i.as_str()))
                                .collect(),
                        ),
                    ),
                );
            }

            // Rule 3b: vCPU / RAM allocation exceeds licensed FGVM model ceiling
            if let (Some(max_cpus), Some(actual_cpus)) = (spec.max_vcpus, hw.allocated_vcpus) {
                if actual_cpus > max_cpus {
                    findings.push(
                        Finding::new(
                            EngineId::FgvmLicenseInspect,
                            "CRITICAL_FGVM_HARDWARE_LIMIT_BYPASS",
                            Severity::Critical,
                            &analysis.normalized_serial,
                            format!(
                                "FGVM model `{}` (`{}`) licenses at most {} vCPU(s), but appliance is running with {} allocated vCPUs (source: {}) — kernel vCPU cap patched",
                                spec.prefix,
                                analysis.normalized_serial,
                                max_cpus,
                                actual_cpus,
                                hw.vcpu_source.as_deref().unwrap_or("unknown")
                            ),
                        )
                        .with_evidence("serial_number", JsonValue::str(&analysis.normalized_serial))
                        .with_evidence("model_prefix", JsonValue::str(spec.prefix))
                        .with_evidence("licensed_max_vcpus", JsonValue::Uint(max_cpus as u64))
                        .with_evidence("allocated_vcpus", JsonValue::Uint(actual_cpus as u64))
                        .with_evidence(
                            "vcpu_source",
                            JsonValue::str(hw.vcpu_source.as_deref().unwrap_or("unknown")),
                        ),
                    );
                }
            }

            if let (Some(max_ram), Some(actual_ram)) = (spec.max_ram_mb, hw.allocated_ram_mb) {
                // Allow 128 MB tolerance for BIOS/hypervisor memory reporting rounding
                if actual_ram > max_ram + 128 {
                    findings.push(
                        Finding::new(
                            EngineId::FgvmLicenseInspect,
                            "CRITICAL_FGVM_HARDWARE_LIMIT_BYPASS",
                            Severity::Critical,
                            &analysis.normalized_serial,
                            format!(
                                "FGVM model `{}` (`{}`) caps RAM at {} MB, but appliance has {} MB allocated (source: {}) — trial/tier memory restriction bypassed",
                                spec.prefix,
                                analysis.normalized_serial,
                                max_ram,
                                actual_ram,
                                hw.ram_source.as_deref().unwrap_or("unknown")
                            ),
                        )
                        .with_evidence("serial_number", JsonValue::str(&analysis.normalized_serial))
                        .with_evidence("licensed_max_ram_mb", JsonValue::Uint(max_ram))
                        .with_evidence("allocated_ram_mb", JsonValue::Uint(actual_ram)),
                    );
                }
            }
        }

        // Rule 3a-2: Pirated / keygen / structurally invalid FGVM serial
        if let Some(reason) = &analysis.keygen_or_pirated_reason {
            findings.push(
                Finding::new(
                    EngineId::FgvmLicenseInspect,
                    "CRITICAL_FGVM_PIRATED_OR_KEYGEN_SERIAL",
                    Severity::Critical,
                    &analysis.normalized_serial,
                    format!(
                        "Invalid, leaked, or keygen-generated FortiGate VM serial `{}` in {}: {}",
                        raw_ser, src, reason
                    ),
                )
                .with_evidence("raw_serial", JsonValue::str(raw_ser.as_str()))
                .with_evidence("normalized_serial", JsonValue::str(&analysis.normalized_serial))
                .with_evidence("source", JsonValue::str(src.as_str()))
                .with_evidence("anomaly_reason", JsonValue::str(reason.as_str()))
                .with_evidence("luhn_mod10_pass", JsonValue::Bool(analysis.luhn_digit_check)),
            );
        }

        analyzed_list.push(analysis);
    }

    let discovered_serials: Vec<String> = analyzed_list
        .iter()
        .map(|a| a.normalized_serial.clone())
        .collect();

    let serial_json: Vec<JsonValue> = analyzed_list
        .iter()
        .map(|a| {
            JsonValue::OrderedObject(vec![
                ("serial".to_string(), JsonValue::str(&a.normalized_serial)),
                ("source".to_string(), JsonValue::str(&a.source)),
                (
                    "model_prefix".to_string(),
                    match a.model_spec {
                        Some(ms) => JsonValue::str(ms.prefix),
                        None => JsonValue::Null,
                    },
                ),
                ("format_valid".to_string(), JsonValue::Bool(a.format_valid)),
                (
                    "luhn_digit_check".to_string(),
                    JsonValue::Bool(a.luhn_digit_check),
                ),
                (
                    "keygen_or_pirated_reason".to_string(),
                    match &a.keygen_or_pirated_reason {
                        Some(r) => JsonValue::str(r.as_str()),
                        None => JsonValue::Null,
                    },
                ),
            ])
        })
        .collect();

    let summary = JsonValue::OrderedObject(vec![
        (
            "license_blobs_parsed".to_string(),
            JsonValue::Uint(parsed_blobs.len() as u64),
        ),
        (
            "serials_inspected_count".to_string(),
            JsonValue::Uint(analyzed_list.len() as u64),
        ),
        (
            "allocated_vcpus".to_string(),
            match hw.allocated_vcpus {
                Some(c) => JsonValue::Uint(c as u64),
                None => JsonValue::Null,
            },
        ),
        (
            "allocated_ram_mb".to_string(),
            match hw.allocated_ram_mb {
                Some(m) => JsonValue::Uint(m),
                None => JsonValue::Null,
            },
        ),
        ("serials".to_string(), JsonValue::Array(serial_json)),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    FgvmLicenseInspectResult {
        discovered_serials,
        license_cert_spkis,
        summary,
        findings,
    }
}

/// Parses a `.lic` file (PEM armor, raw Base64, ASN.1 DER PKCS#7/CMS, or plaintext key-value).
pub fn parse_fgvm_license_blob(path_label: &str, raw: &[u8]) -> ParsedLicenseBlob {
    let raw_sha256 = sha256_hex(raw);
    let mut embedded_certs = Vec::new();
    let mut serials = Vec::new();
    let mut has_asn1_cms_signature = false;
    let mut container_format = "raw_binary_or_text".to_string();
    let mut declared_cpus = None;
    let mut declared_ram_mb = None;

    let mut candidate_payloads: Vec<Vec<u8>> = vec![raw.to_vec()];

    if let Ok(text) = std::str::from_utf8(raw) {
        // Extract standard X.509 PEM certificates if present
        for der in extract_pem_certificates(text) {
            if let Ok(cert) = parse_x509_der(&der) {
                has_asn1_cms_signature = true;
                embedded_certs.push(cert);
            }
        }

        // Extract `-----BEGIN FGT VM LICENSE-----` or generic `-----BEGIN ...-----` Base64 armor
        if let Some(b64_body) = extract_generic_pem_body(text) {
            container_format = "pem_armored_fgt_license".to_string();
            if let Ok(decoded) = base64_decode(&b64_body) {
                candidate_payloads.push(decoded);
            }
        } else {
            // Try decoding whole trimmed file as Base64
            let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.len() >= 32
                && compact
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
            {
                if let Ok(decoded) = base64_decode(&compact) {
                    container_format = "base64_blob".to_string();
                    candidate_payloads.push(decoded);
                }
            }
        }
    }

    for payload in &candidate_payloads {
        if payload.first() == Some(&0x30) {
            let mut cms_oids_seen = false;
            let mut inner_strings = Vec::new();
            walk_asn1_license_der(
                payload,
                0,
                &mut cms_oids_seen,
                &mut embedded_certs,
                &mut inner_strings,
            );
            if cms_oids_seen || !embedded_certs.is_empty() {
                has_asn1_cms_signature = true;
                container_format = "asn1_der_cms_signed".to_string();
            }
            for s in inner_strings {
                parse_kv_license_lines(&s, &mut serials, &mut declared_cpus, &mut declared_ram_mb);
                for tok in extract_fgvm_tokens(&s) {
                    if !serials.contains(&tok) {
                        serials.push(tok);
                    }
                }
            }
        }

        let ascii_scan = extract_printable_runs(payload, 6);
        for run in ascii_scan {
            parse_kv_license_lines(&run, &mut serials, &mut declared_cpus, &mut declared_ram_mb);
            for tok in extract_fgvm_tokens(&run) {
                if !serials.contains(&tok) {
                    serials.push(tok);
                }
            }
        }
    }

    ParsedLicenseBlob {
        path: path_label.to_string(),
        raw_sha256,
        container_format,
        has_asn1_cms_signature,
        embedded_certs,
        discovered_serials: serials,
        declared_cpus,
        declared_ram_mb,
    }
}

/// Validates an `FGVM` serial number against Fortinet's 16-char model grammar, Luhn Mod-10 digit
/// check, and known keygen / pirated serial heuristics.
pub fn analyze_fgvm_serial(raw_serial: &str, source: &str) -> FgvmSerialAnalysis {
    let trimmed = raw_serial.trim();
    let norm = trimmed.to_ascii_uppercase();
    let mut reasons: Vec<String> = Vec::new();

    if trimmed != norm {
        reasons.push("contains lowercase characters (non-factory serial encoding)".to_string());
    }
    if norm.len() != 16 {
        reasons.push(format!(
            "invalid length {} (authentic FGVM serials are exactly 16 characters)",
            norm.len()
        ));
    }
    if !norm.bytes().all(|b| b.is_ascii_alphanumeric()) {
        reasons.push("contains non-alphanumeric symbols".to_string());
    }

    let model_spec = if norm.len() >= 6 {
        lookup_fgvm_model_prefix(&norm[0..6])
    } else {
        None
    };

    if norm.starts_with("FGVM") && model_spec.is_none() {
        let pfx = &norm[0..norm.len().min(6)];
        reasons.push(format!("unrecognized FGVM model tier prefix `{}`", pfx));
    }

    if let Some(spec) = model_spec {
        if spec.is_unlicensed_zero {
            reasons.push(
                "uses unlicensed `FGVM00` zero-CPU prefix seen in cracked trial/keygen images"
                    .to_string(),
            );
        }
    }

    let mut luhn_pass = false;
    if norm.len() == 16 {
        let tail10 = &norm[6..16];
        let sub_code = &norm[6..8];
        let numeric8 = &norm[8..16];

        // Positions 6..8 in authentic FGVM serials are either two digits or subscription code (`TM`, `S0`..`S9`, `8V`)
        let valid_sub = sub_code.bytes().all(|b| b.is_ascii_digit())
            || sub_code == "TM"
            || (sub_code.starts_with('S') && sub_code.as_bytes()[1].is_ascii_digit())
            || sub_code == "8V";
        if !valid_sub {
            reasons.push(format!(
                "invalid sub-series code `{}` at positions 6..8 (hex/keygen string suspected)",
                sub_code
            ));
        }

        // Positions 8..16 in authentic FGVM serials are strictly decimal digits `0-9`
        if !numeric8.bytes().all(|b| b.is_ascii_digit()) {
            reasons.push(format!(
                "non-decimal characters in serial counter `{}` (hex/ASCII keygen pattern)",
                numeric8
            ));
        } else {
            luhn_pass = verify_luhn_mod10(numeric8);
        }

        // Check known pirated/placeholder tails on paid models (excluding legitimate `FGVMEV0000000000` which is handled by trial check)
        let is_eval = model_spec.is_some_and(|m| m.is_eval_trial);
        if !is_eval && KNOWN_PIRATED_TAILS.contains(&tail10) {
            reasons.push(format!(
                "matches known leaked/keygen placeholder serial tail `{}`",
                tail10
            ));
        }

        // Check sequential ascending/descending runs >= 7 chars (`1234567`, `7654321`)
        if has_monotonic_digit_run(tail10, 7) {
            reasons.push(format!(
                "contains synthetic monotonic digit sequence in `{}`",
                tail10
            ));
        }

        // Check >= 9 identical digits in the 10-char tail on non-eval paid tiers (e.g. `0000000005` or `7777777770`)
        if !is_eval && max_identical_char_count(tail10) >= 9 {
            reasons.push(format!(
                "implausible low-entropy repeated serial tail `{}` on paid FGVM tier",
                tail10
            ));
        }
    }

    let format_valid = reasons.is_empty();
    FgvmSerialAnalysis {
        raw_serial: trimmed.to_string(),
        normalized_serial: norm,
        source: source.to_string(),
        model_spec,
        format_valid,
        luhn_digit_check: luhn_pass,
        keygen_or_pirated_reason: if reasons.is_empty() {
            None
        } else {
            Some(reasons.join("; "))
        },
    }
}

pub fn lookup_fgvm_model_prefix(prefix6: &str) -> Option<FgvmModelSpec> {
    match prefix6 {
        "FGVMEV" => Some(FgvmModelSpec {
            prefix: "FGVMEV",
            max_vcpus: Some(1),
            max_ram_mb: Some(2048),
            is_eval_trial: true,
            is_unlicensed_zero: false,
        }),
        "FGVM00" => Some(FgvmModelSpec {
            prefix: "FGVM00",
            max_vcpus: Some(0),
            max_ram_mb: Some(2048),
            is_eval_trial: false,
            is_unlicensed_zero: true,
        }),
        "FGVM01" => Some(FgvmModelSpec {
            prefix: "FGVM01",
            max_vcpus: Some(1),
            max_ram_mb: None,
            is_eval_trial: false,
            is_unlicensed_zero: false,
        }),
        "FGVM02" => Some(FgvmModelSpec {
            prefix: "FGVM02",
            max_vcpus: Some(2),
            max_ram_mb: None,
            is_eval_trial: false,
            is_unlicensed_zero: false,
        }),
        "FGVM04" => Some(FgvmModelSpec {
            prefix: "FGVM04",
            max_vcpus: Some(4),
            max_ram_mb: None,
            is_eval_trial: false,
            is_unlicensed_zero: false,
        }),
        "FGVM08" => Some(FgvmModelSpec {
            prefix: "FGVM08",
            max_vcpus: Some(8),
            max_ram_mb: None,
            is_eval_trial: false,
            is_unlicensed_zero: false,
        }),
        "FGVM16" => Some(FgvmModelSpec {
            prefix: "FGVM16",
            max_vcpus: Some(16),
            max_ram_mb: None,
            is_eval_trial: false,
            is_unlicensed_zero: false,
        }),
        "FGVM32" => Some(FgvmModelSpec {
            prefix: "FGVM32",
            max_vcpus: Some(32),
            max_ram_mb: None,
            is_eval_trial: false,
            is_unlicensed_zero: false,
        }),
        "FGVM64" => Some(FgvmModelSpec {
            prefix: "FGVM64",
            max_vcpus: Some(64),
            max_ram_mb: None,
            is_eval_trial: false,
            is_unlicensed_zero: false,
        }),
        "FGVMUL" => Some(FgvmModelSpec {
            prefix: "FGVMUL",
            max_vcpus: None,
            max_ram_mb: None,
            is_eval_trial: false,
            is_unlicensed_zero: false,
        }),
        _ => None,
    }
}

/// Standard ISO/IEC 7812-1 Luhn Mod-10 check over an ASCII digit slice.
pub fn verify_luhn_mod10(digits: &str) -> bool {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for b in digits.bytes().rev() {
        let mut d = (b - b'0') as u32;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// Extracts all `FGVM*` serial tokens from arbitrary config, certificate CN, or license text.
pub fn extract_fgvm_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;

    while i + 6 <= bytes.len() {
        if bytes[i..i + 4].eq_ignore_ascii_case(b"FGVM") {
            let prev_is_word = i > 0 && bytes[i - 1].is_ascii_alphanumeric();
            if !prev_is_word {
                let start = i;
                let mut end = i + 4;
                while end < bytes.len() && bytes[end].is_ascii_alphanumeric() {
                    end += 1;
                }
                let candidate = &text[start..end];
                // Ignore generic identifiers like `FGVM` alone or `FGVM_LICENSE`; serials have >= 8 alnum chars
                let next_char = bytes.get(end).copied();
                if candidate.len() >= 8
                    && next_char != Some(b'_')
                    && next_char != Some(b'-')
                    && !out
                        .iter()
                        .any(|existing: &String| existing.eq_ignore_ascii_case(candidate))
                {
                    out.push(candidate.to_string());
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn inspect_fortios_production_and_hw(text: &str, source_label: &str, hw: &mut DetectedVmHardware) {
    let mut cpu_line_entries = 0u32;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        let lower = line.to_ascii_lowercase();

        // Detect production FortiOS features proving appliance is not an isolated lab sandbox
        for (needle, tag) in [
            ("config vpn ipsec phase1-interface", "ipsec_site_to_site_vpn"),
            ("config router bgp", "bgp_routing"),
            ("config router ospf", "ospf_routing"),
            ("config system ha", "ha_cluster"),
            ("config user ldap", "enterprise_ldap_auth"),
            ("config user radius", "radius_auth"),
            ("set vdom-mode multi-vdom", "multi_vdom"),
        ] {
            if lower.starts_with(needle) {
                hw.has_production_features = true;
                if !hw.production_indicators.iter().any(|s| s == tag) {
                    hw.production_indicators.push(tag.to_string());
                }
            }
        }

        // Parse vCPU counts from FortiOS / VMware / diagnostic lines:
        // e.g. `CPU(s): 8`, `vcpu-count: 8`, `numvcpus = "8"`, `set cpu-use-threshold`, `CPU0: Intel...`
        if (lower.starts_with("cpu") && line.contains(':') && lower.contains("intel"))
            || (lower.starts_with("cpu") && line.contains(':') && lower.contains("amd"))
        {
            let prefix = lower.split(':').next().unwrap_or("");
            if prefix.len() > 3 && prefix[3..].bytes().all(|b| b.is_ascii_digit()) {
                cpu_line_entries += 1;
            }
        } else if let Some(val) = parse_numeric_after_key(&lower, &[
            "cpu(s):",
            "vcpus:",
            "vcpu-count:",
            "allocated_vcpus:",
            "numvcpus =",
            "numvcpus=",
            "set vcpu-count ",
        ]) {
            if (1..=512).contains(&val) {
                hw.allocated_vcpus = Some(val as u32);
                hw.vcpu_source = Some(source_label.to_string());
            }
        }

        // Parse RAM in MB from `Total RAM: 16384 MB`, `Memory: 16384M`, `memsize = "16384"`
        if let Some(mb) = parse_numeric_after_key(&lower, &[
            "total ram:",
            "memory:",
            "memsize =",
            "memsize=",
            "allocated_ram_mb:",
        ]) {
            if (256..=4_194_304).contains(&mb) {
                hw.allocated_ram_mb = Some(mb);
                hw.ram_source = Some(source_label.to_string());
            }
        }
    }

    if cpu_line_entries > 0 && hw.allocated_vcpus.is_none() {
        hw.allocated_vcpus = Some(cpu_line_entries);
        hw.vcpu_source = Some(format!("{} (CPU enumeration)", source_label));
    }
}

fn parse_numeric_after_key(lower_line: &str, keys: &[&str]) -> Option<u64> {
    for &k in keys {
        if let Some(rest) = lower_line.strip_prefix(k) {
            let trimmed = rest.trim().trim_matches('"').trim_matches('\'').trim();
            let digits_end = trimmed
                .bytes()
                .position(|b| !b.is_ascii_digit())
                .unwrap_or(trimmed.len());
            if digits_end > 0 {
                if let Ok(n) = trimmed[..digits_end].parse::<u64>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

fn parse_proc_cpuinfo_count(path: &Path) -> Option<u32> {
    let text = fs::read_to_string(path).ok()?;
    let mut count = 0u32;
    for line in text.lines() {
        if let Some((lhs, _)) = line.split_once(':') {
            if lhs.trim() == "processor" {
                count += 1;
            }
        }
    }
    if count > 0 {
        Some(count)
    } else {
        None
    }
}

fn parse_proc_meminfo_mb(path: &Path) -> Option<u64> {
    let text = fs::read_to_string(path).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let num_str = rest.split_whitespace().next()?;
            let kb: u64 = num_str.parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

fn walk_asn1_license_der(
    mut buf: &[u8],
    depth: usize,
    cms_oids_seen: &mut bool,
    certs: &mut Vec<X509CertInfo>,
    strings: &mut Vec<String>,
) {
    if depth > 10 {
        return;
    }
    while !buf.is_empty() {
        let Ok((tlv, rest)) = parse_der_tlv(buf) else {
            break;
        };
        buf = rest;

        // Try parsing SEQUENCE as an X.509 certificate directly
        if tlv.tag == 0x30 && tlv.raw_tlv.len() >= 128 {
            if let Ok(cert) = parse_x509_der(tlv.raw_tlv) {
                certs.push(cert);
                continue;
            }
        }

        // OID `1.2.840.113549.1.7.2` = PKCS#7 / CMS `signedData`
        if tlv.tag == 0x06 {
            let oid = decode_oid_dotted(tlv.value);
            if oid.starts_with("1.2.840.113549.1.7.") {
                *cms_oids_seen = true;
            }
        } else if tlv.tag == 0x04 || tlv.tag == 0x0C || tlv.tag == 0x16 || tlv.tag == 0x13 {
            if let Ok(s) = std::str::from_utf8(tlv.value) {
                if s.len() >= 6 {
                    strings.push(s.to_string());
                }
            } else if tlv.value.first() == Some(&0x30) {
                walk_asn1_license_der(tlv.value, depth + 1, cms_oids_seen, certs, strings);
            }
        } else if (tlv.tag & 0x20) != 0 {
            // Constructed SEQUENCE / SET / context-specific `[0]`..`[3]`
            walk_asn1_license_der(tlv.value, depth + 1, cms_oids_seen, certs, strings);
        }
    }
}

fn parse_kv_license_lines(
    text: &str,
    serials: &mut Vec<String>,
    cpus: &mut Option<u32>,
    ram_mb: &mut Option<u64>,
) {
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=').or_else(|| line.split_once(':')) else {
            continue;
        };
        let key = k.trim().to_ascii_uppercase();
        let val = v.trim().trim_matches('"').trim_matches('\'').trim();
        if (key == "SERIALNO" || key == "SERIAL" || key == "SERIAL_NUMBER") && val.len() >= 6 {
            if !serials.iter().any(|s| s.eq_ignore_ascii_case(val)) {
                serials.push(val.to_string());
            }
        } else if key == "CPUS" || key == "VCPU" || key == "MAX_CPUS" {
            if let Ok(n) = val.parse::<u32>() {
                *cpus = Some(n);
            }
        } else if key == "RAM" || key == "MAX_RAM_MB" {
            if let Ok(n) = val.parse::<u64>() {
                *ram_mb = Some(n);
            }
        }
    }
}

fn extract_generic_pem_body(text: &str) -> Option<String> {
    let mut collecting = false;
    let mut body = String::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("-----BEGIN ") && t.ends_with("-----") && !t.contains("CERTIFICATE") {
            collecting = true;
            continue;
        }
        if collecting && t.starts_with("-----END ") && t.ends_with("-----") {
            if !body.is_empty() {
                return Some(body);
            }
            collecting = false;
        } else if collecting {
            body.push_str(t);
        }
    }
    None
}

fn extract_printable_runs(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in bytes {
        if (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
            cur.push(b);
        } else {
            if cur.len() >= min_len {
                if let Ok(s) = std::str::from_utf8(&cur) {
                    out.push(s.to_string());
                }
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len {
        if let Ok(s) = std::str::from_utf8(&cur) {
            out.push(s.to_string());
        }
    }
    out
}

fn has_monotonic_digit_run(s: &str, run_len: usize) -> bool {
    let b = s.as_bytes();
    if b.len() < run_len {
        return false;
    }
    let mut asc = 1usize;
    let mut desc = 1usize;
    for i in 1..b.len() {
        if b[i - 1].is_ascii_digit() && b[i].is_ascii_digit() {
            if b[i] == b[i - 1] + 1 {
                asc += 1;
            } else {
                asc = 1;
            }
            if b[i - 1] == b[i] + 1 {
                desc += 1;
            } else {
                desc = 1;
            }
            if asc >= run_len || desc >= run_len {
                return true;
            }
        } else {
            asc = 1;
            desc = 1;
        }
    }
    false
}

fn max_identical_char_count(s: &str) -> usize {
    let mut counts = [0usize; 256];
    let mut best = 0usize;
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
        if counts[b as usize] > best {
            best = counts[b as usize];
        }
    }
    best
}

fn collect_lic_files_bounded(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
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
            if name == "site-packages" || name == "__pycache__" || name == "ca-trust" {
                continue;
            }
            collect_lic_files_bounded(&entry.path(), depth - 1, out);
        } else if ft.is_file() && name.ends_with(".lic") {
            out.push(entry.path());
        }
    }
}
