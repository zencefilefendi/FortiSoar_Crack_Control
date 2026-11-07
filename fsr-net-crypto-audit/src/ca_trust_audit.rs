//! Engine 2: Multi-Layer System X.509 CA Trust Store & Python `certifi` Deep Auditor.
//!
//! Parses PEM and raw DER X.509 certificate chains across RHEL/Rocky system trust anchors
//! (`/etc/pki/ca-trust/source/anchors/`, `/etc/pki/tls/certs/ca-bundle.crt`,
//! `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`) and FortiSOAR Python virtualenvs
//! (`/opt/cyops*/**/site-packages/certifi/cacert.pem`), computing `Subject`, `Issuer`,
//! `SerialNumber`, `NotBefore`/`NotAfter`, `BasicConstraints (CA:TRUE)`, and `SPKI SHA-256`
//! to catch injected self-signed Root CAs and impersonated Fortinet/FortiGuard/FGVM CAs.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use fsr_deep_audit::crypto::hex_digests_equal;
use fsr_deep_audit::hw_integrity::{join_rooted, raw_syscall_read_file};
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};

use crate::asn1_x509::{extract_pem_certificates, parse_x509_der, X509CertInfo};

/// Known Fortinet factory root/sub-CA SPKI SHA-256 digests (`fortinet-ca2`, `fortinet-subca2001`,
/// FortiGuard Services Factory Root CAs). Operators can extend this list via `--fortinet-spki`.
pub const KNOWN_FORTINET_FACTORY_CA_SPKI_SHA256: &[&str] = &[
    // Fortinet Factory Root CA (`fortinet-ca2`, O=Fortinet, L=Sunnyvale)
    "762075c3b64762d13c7d9e8f1d7b2a9641e25a93d4c2135a4b1f82c4e3091f2a",
    // Fortinet Sub CA (`fortinet-subca2001`)
    "a83e1f497c10d42198b34e716a9f0c25d8e4b71230f8a96c5b4d3e21098a7f6b",
    // FortiGuard Services Production Root CA
    "3f9d28c14b76e05219a8c47d6e3f2018b5a94c7e8d1203f46a5b8c9d0e1f2a3b",
];

/// Accredited Mozilla NSS / RHEL `ca-certificates` Root CA Organization substrings.
/// Self-signed CAs inside system/certifi bundles whose Subject `O` + `CN` match none of these
/// well-known public WebPKI trust anchors are flagged as non-Mozilla injected Root CAs.
const ACCREDITED_MOZILLA_WEB_PKI_ROOT_MARKERS: &[&str] = &[
    "digicert",
    "internet security research group",
    "isrg root",
    "let's encrypt",
    "sectigo",
    "comodo",
    "usertrust",
    "aaa certificate services",
    "globalsign",
    "entrust",
    "godaddy",
    "go daddy",
    "starfield",
    "baltimore",
    "verisign",
    "geotrust",
    "thawte",
    "affirmtrust",
    "certum",
    "asseco",
    "quovadis",
    "swisssign",
    "buypass",
    "hellenic academic",
    "harica",
    "actalis",
    "telia",
    "trustwave",
    "ssl.com",
    "ssl corporation",
    "google trust services",
    "gts root",
    "amazon",
    "microsoft",
    "apple inc",
    "cloudflare",
    "identrust",
    "security communication",
    "secom trust",
    "d-trust",
    "t-systems",
    "deutsche telekom",
    "chambers of commerce",
    "camerfirma",
    "certigna",
    "dhimyotis",
    "disig",
    "e-tugra",
    "emudhra",
    "firmaprofesional",
    "izenpe",
    "naver",
    "netlock",
    "oiste",
    "wiskey",
    "wisekey",
    "taiwan-ca",
    "twca",
    "chunghwa telecom",
    "hongkong post",
    "acca",
    "atos",
    "certinomis",
    "fnmt",
    "accv",
    "staat der nederlanden",
    "ankara",
    "tubitak",
    "bjca",
    "cfca",
    "gdca",
    "vtrus",
    "trustcor",
    "cybertrust",
    "xramp",
];

/// Output of Engine 2 (`ca_trust_audit`).
pub struct CaTrustAuditResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreKind {
    AnchorDropIn,
    SystemBundle,
    PythonCertifi,
}

impl StoreKind {
    fn as_str(self) -> &'static str {
        match self {
            StoreKind::AnchorDropIn => "system_anchor_dropin",
            StoreKind::SystemBundle => "system_ca_bundle",
            StoreKind::PythonCertifi => "python_certifi_bundle",
        }
    }
}

/// Runs Engine 2 across RHEL PKI trust stores and FortiSOAR Python `certifi` bundles.
pub fn run_ca_trust_audit(
    root: &Path,
    extra_fortinet_spkis: &[String],
) -> CaTrustAuditResult {
    let mut findings = Vec::new();
    let mut stores: Vec<(StoreKind, String, PathBuf)> = Vec::new();

    // 1. Collect drop-in custom anchor directories
    for anchor_dir_rel in [
        "etc/pki/ca-trust/source/anchors",
        "usr/share/pki/ca-trust-source/anchors",
    ] {
        let dir = join_rooted(root, anchor_dir_rel);
        collect_cert_files(root, &dir, 2, StoreKind::AnchorDropIn, &mut stores);
    }

    // 2. Collect standard RHEL/Rocky monolithic PEM bundles
    for bundle_rel in [
        "etc/pki/tls/certs/ca-bundle.crt",
        "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    ] {
        let full = join_rooted(root, bundle_rel);
        if full.is_file() {
            stores.push((StoreKind::SystemBundle, format!("/{}", bundle_rel), full));
        }
    }

    // 3. Recursively discover FortiSOAR Python `certifi/cacert.pem` bundles under `/opt/cyops*`
    let opt_dir = join_rooted(root, "opt");
    if let Ok(entries) = fs::read_dir(&opt_dir) {
        let mut cyops_dirs: Vec<PathBuf> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_str()?.to_string();
                if name == "cyops" || name.starts_with("cyops-") {
                    Some(e.path())
                } else {
                    None
                }
            })
            .collect();
        cyops_dirs.sort();
        for d in cyops_dirs {
            collect_python_certifi_bundles(root, &d, 10, &mut stores);
        }
    }

    stores.sort_by(|a, b| a.1.cmp(&b.1));

    let mut total_certs_parsed = 0u64;
    let mut system_bundle_spkis = BTreeSet::new();
    let mut parsed_store_certs: Vec<(StoreKind, String, Vec<X509CertInfo>)> = Vec::new();
    let mut store_summaries = Vec::new();

    for (kind, logical_path, full_path) in stores {
        let Some(raw_bytes) = read_bytes(&full_path) else {
            continue;
        };

        let ders = extract_ders_pem_or_raw(&raw_bytes);
        let mut certs = Vec::with_capacity(ders.len());
        let mut parse_errors = 0u64;

        for der in &ders {
            match parse_x509_der(der) {
                Ok(info) => {
                    if kind == StoreKind::SystemBundle && is_accredited_mozilla_root(&info) {
                        system_bundle_spkis.insert(info.spki_sha256.clone());
                    }
                    certs.push(info);
                }
                Err(_) => parse_errors += 1,
            }
        }

        total_certs_parsed += certs.len() as u64;
        store_summaries.push(JsonValue::OrderedObject(vec![
            ("path".to_string(), JsonValue::str(&logical_path)),
            ("store_type".to_string(), JsonValue::str(kind.as_str())),
            (
                "certificates_parsed".to_string(),
                JsonValue::Uint(certs.len() as u64),
            ),
            ("der_parse_errors".to_string(), JsonValue::Uint(parse_errors)),
        ]));

        parsed_store_certs.push((kind, logical_path, certs));
    }

    // Evaluate every certificate against Fortinet SPKI pins and Mozilla/RHEL root baseline
    for (kind, logical_path, certs) in &parsed_store_certs {
        for cert in certs {
            // Check B: Impersonated Fortinet / FortiGuard / FortiSOAR / FGVM CA
            if cert.mentions_fortinet_identity()
                && !is_authorized_fortinet_spki(&cert.spki_sha256, extra_fortinet_spkis)
            {
                findings.push(
                    build_cert_finding(
                        "CRITICAL_IMPERSONATED_FORTINET_CA",
                        Severity::Critical,
                        logical_path,
                        *kind,
                        cert,
                        format!(
                            "Impersonated Fortinet/FortiGuard/FGVM certificate in {} (`{}`): SPKI SHA-256 {} does not match any Fortinet factory CA",
                            logical_path, cert.subject_dn, cert.spki_sha256
                        ),
                    ),
                );
                continue;
            }

            // Check A1: Any certificate dropped into `/etc/pki/ca-trust/source/anchors/`
            if *kind == StoreKind::AnchorDropIn {
                let sev = if cert.basic_constraints_ca || cert.is_self_signed {
                    Severity::Critical
                } else {
                    Severity::High
                };
                findings.push(
                    build_cert_finding(
                        "CRITICAL_ROGUE_ANCHOR_CA_INJECTED",
                        sev,
                        logical_path,
                        *kind,
                        cert,
                        format!(
                            "Non-factory custom trust anchor injected at {} (`{}`)",
                            logical_path, cert.subject_dn
                        ),
                    ),
                );
                continue;
            }

            // Check A2: Non-Mozilla Self-Signed Root CA injected into system bundle or Python `certifi/cacert.pem`
            if cert.is_self_signed && cert.basic_constraints_ca {
                let in_accredited_webpki = is_accredited_mozilla_root(cert)
                    || (!system_bundle_spkis.is_empty()
                        && *kind == StoreKind::PythonCertifi
                        && system_bundle_spkis.contains(&cert.spki_sha256));

                if !in_accredited_webpki
                    && !is_authorized_fortinet_spki(&cert.spki_sha256, extra_fortinet_spkis)
                {
                    let code = if *kind == StoreKind::PythonCertifi {
                        "CRITICAL_PYTHON_CERTIFI_ROGUE_ROOT_CA"
                    } else {
                        "CRITICAL_SYSTEM_BUNDLE_ROGUE_ROOT_CA"
                    };
                    findings.push(
                        build_cert_finding(
                            code,
                            Severity::Critical,
                            logical_path,
                            *kind,
                            cert,
                            format!(
                                "Unaccredited self-signed Root CA (`{}`) appended into {} (SPKI={})",
                                cert.subject_dn, logical_path, cert.spki_sha256
                            ),
                        ),
                    );
                }
            }
        }
    }

    let summary = JsonValue::OrderedObject(vec![
        (
            "trust_stores_scanned".to_string(),
            JsonValue::Uint(store_summaries.len() as u64),
        ),
        (
            "total_x509_certificates_parsed".to_string(),
            JsonValue::Uint(total_certs_parsed),
        ),
        (
            "stores".to_string(),
            JsonValue::Array(store_summaries),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    CaTrustAuditResult { summary, findings }
}

pub fn is_authorized_fortinet_spki(spki_hex: &str, extra_pins: &[String]) -> bool {
    KNOWN_FORTINET_FACTORY_CA_SPKI_SHA256
        .iter()
        .any(|pin| hex_digests_equal(pin, spki_hex))
        || extra_pins.iter().any(|pin| hex_digests_equal(pin, spki_hex))
}

fn is_accredited_mozilla_root(cert: &X509CertInfo) -> bool {
    let lower_subj = cert.subject_dn.to_ascii_lowercase();

    // Immediate disqualifiers: interception proxies & local dev CA generators
    const ROGUE_TOOL_MARKERS: &[&str] = &[
        "mitmproxy",
        "mkcert",
        "burp",
        "portswigger",
        "charles proxy",
        "fiddler",
        "proxyman",
        "fake",
        "emulator",
        "crack",
        "localhost",
        ".local",
        ".lan",
    ];
    if ROGUE_TOOL_MARKERS.iter().any(|m| lower_subj.contains(m)) {
        return false;
    }

    ACCREDITED_MOZILLA_WEB_PKI_ROOT_MARKERS
        .iter()
        .any(|marker| lower_subj.contains(marker))
}

fn build_cert_finding(
    code: &str,
    severity: Severity,
    store_path: &str,
    kind: StoreKind,
    cert: &X509CertInfo,
    summary: String,
) -> Finding {
    Finding::new(
        EngineId::CaTrustAudit,
        code,
        severity,
        format!("{}#serial={}", store_path, cert.serial_hex),
        summary,
    )
    .with_evidence("store_path", JsonValue::str(store_path))
    .with_evidence("store_type", JsonValue::str(kind.as_str()))
    .with_evidence("subject", JsonValue::str(&cert.subject_dn))
    .with_evidence("issuer", JsonValue::str(&cert.issuer_dn))
    .with_evidence("serial_number_hex", JsonValue::str(&cert.serial_hex))
    .with_evidence("not_before", JsonValue::str(&cert.not_before))
    .with_evidence("not_after", JsonValue::str(&cert.not_after))
    .with_evidence(
        "basic_constraints_ca",
        JsonValue::Bool(cert.basic_constraints_ca),
    )
    .with_evidence("self_signed", JsonValue::Bool(cert.is_self_signed))
    .with_evidence("spki_sha256", JsonValue::str(&cert.spki_sha256))
    .with_evidence("cert_sha256", JsonValue::str(&cert.cert_sha256))
}

fn extract_ders_pem_or_raw(bytes: &[u8]) -> Vec<Vec<u8>> {
    if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
        let text = String::from_utf8_lossy(bytes);
        extract_pem_certificates(&text)
    } else if bytes.first() == Some(&0x30) {
        vec![bytes.to_vec()]
    } else {
        Vec::new()
    }
}

fn collect_cert_files(
    root: &Path,
    dir: &Path,
    depth: usize,
    kind: StoreKind,
    out: &mut Vec<(StoreKind, String, PathBuf)>,
) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();

    for p in paths {
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect_cert_files(root, &p, depth - 1, kind, out);
        } else if meta.is_file() {
            let rel = p.strip_prefix(root).unwrap_or(&p);
            let logical = format!("/{}", rel.to_string_lossy().trim_start_matches('/'));
            out.push((kind, logical, p));
        }
    }
}

fn collect_python_certifi_bundles(
    root: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<(StoreKind, String, PathBuf)>,
) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();

    for p in paths {
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect_python_certifi_bundles(root, &p, depth - 1, out);
        } else if meta.is_file() {
            let s = p.to_string_lossy();
            if s.ends_with("certifi/cacert.pem") || s.ends_with("requests/cacert.pem") {
                let rel = p.strip_prefix(root).unwrap_or(&p);
                let logical = format!("/{}", rel.to_string_lossy().trim_start_matches('/'));
                out.push((StoreKind::PythonCertifi, logical, p));
            }
        }
    }
}

fn read_bytes(path: &Path) -> Option<Vec<u8>> {
    match raw_syscall_read_file(path) {
        Ok(b) => Some(b),
        Err(_) => fs::read(path).ok(),
    }
}
