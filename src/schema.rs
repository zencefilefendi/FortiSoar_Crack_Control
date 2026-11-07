//! Deterministic RFC 8259 JSON serialization and forensic report schema.
//!
//! Guarantees identical canonical field ordering and deterministic finding sorting
//! across runs without relying on `serde` or `serde_json`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Severity classification for forensic findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    pub fn risk_weight(self) -> u32 {
        match self {
            Severity::Critical => 45,
            Severity::High => 20,
            Severity::Medium => 8,
            Severity::Low => 3,
            Severity::Info => 0,
        }
    }
}

/// Core detection engine identifier across Phases 1–8 of the forensic suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EngineId {
    HwIntegrity,
    ElfVmaDiff,
    PycInspector,
    RpmForensics,
    NetHijack,
    CaTrustAudit,
    SslBypassCheck,
    FdnLiveProbe,
    FortigateCfgAudit,
    BirthmarkExtractor,
    TimeFreezeAudit,
    FgvmLicenseInspect,
    ClusterCorrelator,
    RemoteFingerprinter,
    ConnectorSkimmerAudit,
    WebAuthBackdoor,
    PostgresPersistence,
    OsPersistenceAudit,
    FortigateBackdoorAudit,
    OvaStreamInspector,
    VmdkCarver,
    CrackerAttribution,
}

impl EngineId {
    pub fn as_str(self) -> &'static str {
        match self {
            EngineId::HwIntegrity => "hw_integrity",
            EngineId::ElfVmaDiff => "elf_vma_diff",
            EngineId::PycInspector => "pyc_inspector",
            EngineId::RpmForensics => "rpm_forensics",
            EngineId::NetHijack => "net_hijack",
            EngineId::CaTrustAudit => "ca_trust_audit",
            EngineId::SslBypassCheck => "ssl_bypass_check",
            EngineId::FdnLiveProbe => "fdn_live_probe",
            EngineId::FortigateCfgAudit => "fortigate_cfg_audit",
            EngineId::BirthmarkExtractor => "birthmark_extractor",
            EngineId::TimeFreezeAudit => "time_freeze_audit",
            EngineId::FgvmLicenseInspect => "fgvm_license_inspect",
            EngineId::ClusterCorrelator => "cluster_correlator",
            EngineId::RemoteFingerprinter => "remote_fingerprinter",
            EngineId::ConnectorSkimmerAudit => "connector_skimmer_audit",
            EngineId::WebAuthBackdoor => "web_auth_backdoor",
            EngineId::PostgresPersistence => "postgres_persistence",
            EngineId::OsPersistenceAudit => "os_persistence_audit",
            EngineId::FortigateBackdoorAudit => "fortigate_backdoor_audit",
            EngineId::OvaStreamInspector => "ova_stream_inspector",
            EngineId::VmdkCarver => "vmdk_carver",
            EngineId::CrackerAttribution => "cracker_attribution",
        }
    }

    pub fn prefix(self) -> &'static str {
        match self {
            EngineId::HwIntegrity => "HW",
            EngineId::ElfVmaDiff => "ELF",
            EngineId::PycInspector => "PYC",
            EngineId::RpmForensics => "RPM",
            EngineId::NetHijack => "NET",
            EngineId::CaTrustAudit => "CA",
            EngineId::SslBypassCheck => "SSL",
            EngineId::FdnLiveProbe => "FDN",
            EngineId::FortigateCfgAudit => "FGT",
            EngineId::BirthmarkExtractor => "BMK",
            EngineId::TimeFreezeAudit => "TMF",
            EngineId::FgvmLicenseInspect => "LIC",
            EngineId::ClusterCorrelator => "CLS",
            EngineId::RemoteFingerprinter => "RMT",
            EngineId::ConnectorSkimmerAudit => "SKM",
            EngineId::WebAuthBackdoor => "WEB",
            EngineId::PostgresPersistence => "PGP",
            EngineId::OsPersistenceAudit => "OSP",
            EngineId::FortigateBackdoorAudit => "FGB",
            EngineId::OvaStreamInspector => "OVA",
            EngineId::VmdkCarver => "VDK",
            EngineId::CrackerAttribution => "ATT",
        }
    }
}

/// Canonical JSON AST value with deterministic serialization.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Str(String),
    Array(Vec<JsonValue>),
    /// Preserves canonical schema insertion order for top-level report structures.
    OrderedObject(Vec<(String, JsonValue)>),
    /// Lexicographically sorted key-value map for dynamic forensic evidence.
    MapObject(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    pub fn str<S: Into<String>>(s: S) -> Self {
        JsonValue::Str(s.into())
    }

    pub fn to_json_string(&self, pretty: bool) -> String {
        let mut out = String::with_capacity(4096);
        self.write_into(&mut out, pretty, 0);
        out
    }

    fn write_into(&self, out: &mut String, pretty: bool, depth: usize) {
        match self {
            JsonValue::Null => out.push_str("null"),
            JsonValue::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            JsonValue::Int(v) => {
                let _ = write!(out, "{}", v);
            }
            JsonValue::Uint(v) => {
                let _ = write!(out, "{}", v);
            }
            JsonValue::Str(s) => write_escaped_json_str(out, s),
            JsonValue::Array(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    if pretty {
                        out.push('\n');
                        push_indent(out, depth + 1);
                    }
                    item.write_into(out, pretty, depth + 1);
                }
                if pretty {
                    out.push('\n');
                    push_indent(out, depth);
                }
                out.push(']');
            }
            JsonValue::OrderedObject(entries) => {
                if entries.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push('{');
                for (idx, (k, v)) in entries.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    if pretty {
                        out.push('\n');
                        push_indent(out, depth + 1);
                    }
                    write_escaped_json_str(out, k);
                    out.push(':');
                    if pretty {
                        out.push(' ');
                    }
                    v.write_into(out, pretty, depth + 1);
                }
                if pretty {
                    out.push('\n');
                    push_indent(out, depth);
                }
                out.push('}');
            }
            JsonValue::MapObject(map) => {
                if map.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push('{');
                for (idx, (k, v)) in map.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    if pretty {
                        out.push('\n');
                        push_indent(out, depth + 1);
                    }
                    write_escaped_json_str(out, k);
                    out.push(':');
                    if pretty {
                        out.push(' ');
                    }
                    v.write_into(out, pretty, depth + 1);
                }
                if pretty {
                    out.push('\n');
                    push_indent(out, depth);
                }
                out.push('}');
            }
        }
    }
}

#[inline]
fn push_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

/// Escapes strings strictly per RFC 8259 Section 7.
pub fn write_escaped_json_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Normalized forensic finding emitted by any of the 4 core engines.
#[derive(Debug, Clone)]
pub struct Finding {
    pub engine: EngineId,
    pub code: String,
    pub severity: Severity,
    pub target: String,
    pub summary: String,
    pub evidence: BTreeMap<String, JsonValue>,
}

impl Finding {
    pub fn new(
        engine: EngineId,
        code: impl Into<String>,
        severity: Severity,
        target: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            engine,
            code: code.into(),
            severity,
            target: target.into(),
            summary: summary.into(),
            evidence: BTreeMap::new(),
        }
    }

    pub fn with_evidence(mut self, key: impl Into<String>, val: JsonValue) -> Self {
        self.evidence.insert(key.into(), val);
        self
    }

    pub fn insert_evidence(&mut self, key: impl Into<String>, val: JsonValue) {
        self.evidence.insert(key.into(), val);
    }

    pub fn to_json_with_id(&self, deterministic_id: &str) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("id".to_string(), JsonValue::str(deterministic_id)),
            ("engine".to_string(), JsonValue::str(self.engine.as_str())),
            ("code".to_string(), JsonValue::str(&self.code)),
            (
                "severity".to_string(),
                JsonValue::str(self.severity.as_str()),
            ),
            ("target".to_string(), JsonValue::str(&self.target)),
            ("summary".to_string(), JsonValue::str(&self.summary)),
            (
                "evidence".to_string(),
                JsonValue::MapObject(self.evidence.clone()),
            ),
        ])
    }
}

/// Scan context metadata included in every report.
#[derive(Debug, Clone)]
pub struct ScanContext {
    pub root_path: String,
    pub hostname: String,
    pub kernel_release: String,
    pub scan_timestamp_unix: u64,
    pub scanner_pid: u32,
    pub effective_uid: u32,
}

/// Complete deterministic forensic audit report across all 4 engines.
#[derive(Debug, Clone)]
pub struct AuditReport {
    pub context: ScanContext,
    pub hw_summary: JsonValue,
    pub elf_summary: JsonValue,
    pub pyc_summary: JsonValue,
    pub rpm_summary: JsonValue,
    pub findings: Vec<Finding>,
}

impl AuditReport {
    /// Sorts findings deterministically and serializes the complete JSON schema.
    pub fn into_canonical_json(self) -> JsonValue {
        build_canonical_report_json(
            "fsr-deep-audit",
            env!("CARGO_PKG_VERSION"),
            &self.context,
            vec![
                ("hw_integrity".to_string(), self.hw_summary),
                ("elf_vma_diff".to_string(), self.elf_summary),
                ("pyc_inspector".to_string(), self.pyc_summary),
                ("rpm_forensics".to_string(), self.rpm_summary),
            ],
            self.findings,
        )
    }
}

/// Shared canonical report builder ensuring Phase 1 (`fsr-deep-audit`) and Phase 2
/// (`fsr-net-crypto-audit`) emit an identical deterministic JSON/NDJSON schema.
pub fn build_canonical_report_json(
    tool_name: &str,
    tool_version: &str,
    context: &ScanContext,
    engines: Vec<(String, JsonValue)>,
    mut findings: Vec<Finding>,
) -> JsonValue {
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.engine.cmp(&b.engine))
            .then_with(|| a.code.cmp(&b.code))
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| a.summary.cmp(&b.summary))
    });

    let mut critical_count = 0u64;
    let mut high_count = 0u64;
    let mut medium_count = 0u64;
    let mut low_count = 0u64;
    let mut info_count = 0u64;
    let mut raw_score = 0u32;

    for f in &findings {
        raw_score = raw_score.saturating_add(f.severity.risk_weight());
        match f.severity {
            Severity::Critical => critical_count += 1,
            Severity::High => high_count += 1,
            Severity::Medium => medium_count += 1,
            Severity::Low => low_count += 1,
            Severity::Info => info_count += 1,
        }
    }

    let risk_score = raw_score.min(100) as u64;
    let status = if critical_count > 0 {
        "COMPROMISED_OR_CRACKED"
    } else if high_count > 0 || medium_count > 0 {
        "SUSPICIOUS_ANOMALIES"
    } else {
        "CLEAN"
    };

    let mut per_engine_seq: BTreeMap<EngineId, usize> = BTreeMap::new();
    let serialized_findings: Vec<JsonValue> = findings
        .iter()
        .map(|f| {
            let seq = per_engine_seq.entry(f.engine).or_insert(0);
            *seq += 1;
            let id = format!("FSR-{}-{:04}", f.engine.prefix(), *seq);
            f.to_json_with_id(&id)
        })
        .collect();

    let raw_backend = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "linux-x86_64-raw-syscall-asm"
    } else {
        "portable-fallback-non-linux-x86_64"
    };

    JsonValue::OrderedObject(vec![
        ("schema_version".to_string(), JsonValue::str("1.0.0")),
        (
            "tool".to_string(),
            JsonValue::OrderedObject(vec![
                ("name".to_string(), JsonValue::str(tool_name)),
                ("version".to_string(), JsonValue::str(tool_version)),
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
                ("root_path".to_string(), JsonValue::str(&context.root_path)),
                ("hostname".to_string(), JsonValue::str(&context.hostname)),
                (
                    "kernel_release".to_string(),
                    JsonValue::str(&context.kernel_release),
                ),
                (
                    "scan_timestamp_unix".to_string(),
                    JsonValue::Uint(context.scan_timestamp_unix),
                ),
                (
                    "scanner_pid".to_string(),
                    JsonValue::Uint(context.scanner_pid as u64),
                ),
                (
                    "effective_uid".to_string(),
                    JsonValue::Uint(context.effective_uid as u64),
                ),
            ]),
        ),
        (
            "verdict".to_string(),
            JsonValue::OrderedObject(vec![
                ("status".to_string(), JsonValue::str(status)),
                ("risk_score".to_string(), JsonValue::Uint(risk_score)),
                (
                    "total_findings".to_string(),
                    JsonValue::Uint(findings.len() as u64),
                ),
                (
                    "critical_count".to_string(),
                    JsonValue::Uint(critical_count),
                ),
                ("high_count".to_string(), JsonValue::Uint(high_count)),
                ("medium_count".to_string(), JsonValue::Uint(medium_count)),
                ("low_count".to_string(), JsonValue::Uint(low_count)),
                ("info_count".to_string(), JsonValue::Uint(info_count)),
            ]),
        ),
        ("engines".to_string(), JsonValue::OrderedObject(engines)),
        (
            "findings".to_string(),
            JsonValue::Array(serialized_findings),
        ),
    ])
}
