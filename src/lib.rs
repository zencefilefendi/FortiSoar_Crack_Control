//! `fsr-deep-audit`: Zero-dependency Linux x86_64 forensic integrity & anti-cracking engine
//! for RHEL/Rocky Linux 8/9 FortiSOAR virtual appliances.

pub mod crypto;
pub mod elf_vma_diff;
pub mod hw_integrity;
pub mod pyc_inspector;
pub mod rpm_forensics;
pub mod schema;

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::elf_vma_diff::run_elf_vma_diff_audit;
use crate::hw_integrity::{current_euid, join_rooted, raw_syscall_read_file, run_hw_integrity_audit};
use crate::pyc_inspector::run_pyc_inspector_audit;
use crate::rpm_forensics::run_rpm_forensics_audit;
use crate::schema::{AuditReport, JsonValue, ScanContext};

/// Controls which of the 4 core forensic detection engines execute during a scan.
#[derive(Debug, Clone, Copy)]
pub struct EngineSelection {
    pub hw_integrity: bool,
    pub elf_vma_diff: bool,
    pub pyc_inspector: bool,
    pub rpm_forensics: bool,
}

impl Default for EngineSelection {
    fn default() -> Self {
        Self {
            hw_integrity: true,
            elf_vma_diff: true,
            pyc_inspector: true,
            rpm_forensics: true,
        }
    }
}

/// Executes all selected forensic engines against `root` and returns the canonical `AuditReport`.
pub fn execute_full_audit(root: &Path, selection: EngineSelection) -> AuditReport {
    let context = collect_scan_context(root);
    let mut findings = Vec::new();

    let hw_summary = if selection.hw_integrity {
        let res = run_hw_integrity_audit(root);
        findings.extend(res.findings);
        res.summary
    } else {
        skipped_engine_summary()
    };

    let elf_summary = if selection.elf_vma_diff {
        let res = run_elf_vma_diff_audit(root);
        findings.extend(res.findings);
        res.summary
    } else {
        skipped_engine_summary()
    };

    let pyc_summary = if selection.pyc_inspector {
        let res = run_pyc_inspector_audit(root);
        findings.extend(res.findings);
        res.summary
    } else {
        skipped_engine_summary()
    };

    let rpm_summary = if selection.rpm_forensics {
        let res = run_rpm_forensics_audit(root);
        findings.extend(res.findings);
        res.summary
    } else {
        skipped_engine_summary()
    };

    AuditReport {
        context,
        hw_summary,
        elf_summary,
        pyc_summary,
        rpm_summary,
        findings,
    }
}

fn skipped_engine_summary() -> JsonValue {
    JsonValue::OrderedObject(vec![("enabled".to_string(), JsonValue::Bool(false))])
}

pub fn collect_scan_context(root: &Path) -> ScanContext {
    let hostname = read_trimmed(&join_rooted(root, "proc/sys/kernel/hostname"))
        .or_else(|| read_trimmed(&join_rooted(root, "etc/hostname")))
        .unwrap_or_else(|| "unknown-appliance".to_string());

    let kernel_release = read_trimmed(&join_rooted(root, "proc/sys/kernel/osrelease"))
        .unwrap_or_else(|| "unknown-kernel".to_string());

    let scan_timestamp_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    ScanContext {
        root_path: root.to_string_lossy().into_owned(),
        hostname,
        kernel_release,
        scan_timestamp_unix,
        scanner_pid: std::process::id(),
        effective_uid: current_euid(),
    }
}

fn read_trimmed(path: &Path) -> Option<String> {
    let bytes = match raw_syscall_read_file(path) {
        Ok(b) => b,
        Err(_) => fs::read(path).ok()?,
    };
    let s = String::from_utf8_lossy(&bytes).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
