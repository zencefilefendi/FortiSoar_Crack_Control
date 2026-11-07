//! Module 4: Air-Gapped Field Deployment & Auditor Self-Integrity Armor (`self_integrity.rs`).
//!
//! Protects `fsr-forensic-verdict` and `fsr-remediation-advisor` when launched from a
//! field USB drive, virtual CD-ROM/ISO, or read-only forensic share onto an untrusted,
//! potentially rootkitted or `LD_PRELOAD`-hooked FortiSOAR / FortiGate appliance:
//!   1. Computes the running binary's own SHA-256 digest (`/proc/self/exe` on Linux,
//!      `current_exe()` fallback elsewhere) via BOTH standard `libc` I/O and raw Linux
//!      `x86_64` kernel syscalls (`__NR_openat`, `__NR_read`, `__NR_close`), catching
//!      userland hooks attempting to spoof the auditor's own image or unlinked binaries.
//!   2. Validates optional pinned release digests (`--expected-self-sha256`,
//!      `FSR_EXPECTED_SELF_SHA256`, or `<exe>.sha256` sidecar file on the USB media)
//!      using constant-time digest comparison.
//!   3. Audits runtime environment variables (`std::env::vars_os` AND raw
//!      `/proc/self/environ`), `/etc/ld.so.preload` (in live host mode), `/proc/self/maps`
//!      (ephemeral `/dev/shm` / `/tmp` / `(deleted)` shared objects), and `/proc/self/status`
//!      (`TracerPid != 0` `ptrace` interception).
//!   4. Checks `/proc/self/mountinfo` to verify whether the auditor is executing from
//!      read-only (`ro`) field media.
//!   5. Never aborts blindly on tamper attempts: immediately emits a high-visibility
//!      `stderr` alert banner and transitions into `SafeExecutionPolicy` (raw-syscall
//!      preference, external subprocess prohibition, untrusted `PATH`/`ENV` quarantine).

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fsr_deep_audit::crypto::{hex_digests_equal, sha256_hex};
use fsr_deep_audit::hw_integrity::raw_syscall_read_file;
use fsr_deep_audit::schema::JsonValue;

/// Dynamic-linker, resolver, and interpreter environment variables that a compromised
/// host shell or root profile may inject to hijack the forensic binary.
pub const HOSTILE_RUNTIME_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG_OUTPUT",
    "LD_ORIGIN_PATH",
    "LD_DYNAMIC_WEAK",
    "DYLD_INSERT_LIBRARIES",
    "GCONV_PATH",
    "HOSTALIASES",
    "RES_OPTIONS",
    "LOCALDOMAIN",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "FAKETIME",
];

/// Individual self-integrity alert raised during auditor startup verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfIntegrityAlert {
    pub code: &'static str,
    pub severity: &'static str,
    pub indicator: String,
    pub detail: String,
}

impl SelfIntegrityAlert {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("code".to_string(), JsonValue::str(self.code)),
            ("severity".to_string(), JsonValue::str(self.severity)),
            ("indicator".to_string(), JsonValue::str(&self.indicator)),
            ("detail".to_string(), JsonValue::str(&self.detail)),
        ])
    }
}

/// Hardened runtime policy activated automatically if the audited system attempts
/// to hook, preload, trace, or tamper with the forensic binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeExecutionPolicy {
    pub safe_mode_active: bool,
    pub prefer_raw_linux_syscalls: bool,
    pub disable_external_subprocesses: bool,
    pub ignore_untrusted_env_paths: bool,
    pub activation_reasons: Vec<String>,
}

impl SafeExecutionPolicy {
    pub fn nominal() -> Self {
        Self {
            safe_mode_active: false,
            prefer_raw_linux_syscalls: cfg!(all(target_os = "linux", target_arch = "x86_64")),
            disable_external_subprocesses: false,
            ignore_untrusted_env_paths: false,
            activation_reasons: Vec::new(),
        }
    }

    pub fn hardened(reasons: Vec<String>) -> Self {
        Self {
            safe_mode_active: true,
            prefer_raw_linux_syscalls: true,
            disable_external_subprocesses: true,
            ignore_untrusted_env_paths: true,
            activation_reasons: reasons,
        }
    }

    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            (
                "safe_mode_active".to_string(),
                JsonValue::Bool(self.safe_mode_active),
            ),
            (
                "prefer_raw_linux_syscalls".to_string(),
                JsonValue::Bool(self.prefer_raw_linux_syscalls),
            ),
            (
                "disable_external_subprocesses".to_string(),
                JsonValue::Bool(self.disable_external_subprocesses),
            ),
            (
                "ignore_untrusted_env_paths".to_string(),
                JsonValue::Bool(self.ignore_untrusted_env_paths),
            ),
            (
                "activation_reasons".to_string(),
                JsonValue::Array(
                    self.activation_reasons
                        .iter()
                        .map(|r| JsonValue::str(r.as_str()))
                        .collect(),
                ),
            ),
        ])
    }
}

/// Complete startup self-integrity attestation for `fsr-forensic-verdict` / `fsr-remediation-advisor`.
#[derive(Debug, Clone)]
pub struct SelfIntegrityReport {
    pub executable_path: String,
    pub self_sha256_libc_hex: String,
    pub self_sha256_raw_syscall_hex: Option<String>,
    pub expected_sha256_hex: Option<String>,
    pub expected_sha256_source: Option<String>,
    pub expected_sha256_verified: Option<bool>,
    pub execution_media_mount_point: Option<String>,
    pub execution_media_readonly: Option<bool>,
    pub tracer_pid: u32,
    pub hostile_env_vars: Vec<(String, String)>,
    pub suspicious_self_mappings: Vec<String>,
    pub compromise_attempt_detected: bool,
    pub safe_mode_policy: SafeExecutionPolicy,
    pub alerts: Vec<SelfIntegrityAlert>,
}

impl SelfIntegrityReport {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            (
                "executable_path".to_string(),
                JsonValue::str(&self.executable_path),
            ),
            (
                "self_sha256_libc_hex".to_string(),
                JsonValue::str(&self.self_sha256_libc_hex),
            ),
            (
                "self_sha256_raw_syscall_hex".to_string(),
                match &self.self_sha256_raw_syscall_hex {
                    Some(h) => JsonValue::str(h),
                    None => JsonValue::Null,
                },
            ),
            (
                "expected_sha256_hex".to_string(),
                match &self.expected_sha256_hex {
                    Some(h) => JsonValue::str(h),
                    None => JsonValue::Null,
                },
            ),
            (
                "expected_sha256_source".to_string(),
                match &self.expected_sha256_source {
                    Some(s) => JsonValue::str(s),
                    None => JsonValue::Null,
                },
            ),
            (
                "expected_sha256_verified".to_string(),
                match self.expected_sha256_verified {
                    Some(b) => JsonValue::Bool(b),
                    None => JsonValue::Null,
                },
            ),
            (
                "execution_media_mount_point".to_string(),
                match &self.execution_media_mount_point {
                    Some(mp) => JsonValue::str(mp),
                    None => JsonValue::Null,
                },
            ),
            (
                "execution_media_readonly".to_string(),
                match self.execution_media_readonly {
                    Some(ro) => JsonValue::Bool(ro),
                    None => JsonValue::Null,
                },
            ),
            (
                "tracer_pid".to_string(),
                JsonValue::Uint(self.tracer_pid as u64),
            ),
            (
                "hostile_env_vars".to_string(),
                JsonValue::Array(
                    self.hostile_env_vars
                        .iter()
                        .map(|(k, v)| {
                            JsonValue::OrderedObject(vec![
                                ("name".to_string(), JsonValue::str(k)),
                                ("value".to_string(), JsonValue::str(v)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "suspicious_self_mappings".to_string(),
                JsonValue::Array(
                    self.suspicious_self_mappings
                        .iter()
                        .map(|m| JsonValue::str(m.as_str()))
                        .collect(),
                ),
            ),
            (
                "compromise_attempt_detected".to_string(),
                JsonValue::Bool(self.compromise_attempt_detected),
            ),
            ("safe_mode_policy".to_string(), self.safe_mode_policy.to_json()),
            (
                "alerts".to_string(),
                JsonValue::Array(self.alerts.iter().map(|a| a.to_json()).collect()),
            ),
        ])
    }

    /// Prints an immediate high-priority warning banner to `stderr` when an untrusted
    /// host attempts to hook or tamper with the auditor binary, without polluting `stdout`.
    pub fn emit_stderr_alert_banner(&self, binary_label: &str) {
        if !self.compromise_attempt_detected {
            return;
        }
        let stderr = io::stderr();
        let mut handle = stderr.lock();
        let _ = writeln!(
            handle,
            "================================================================================"
        );
        let _ = writeln!(
            handle,
            "[{}] SELF-INTEGRITY ALERT: HOST HOOK / SUBVERSION ATTEMPT DETECTED!",
            binary_label
        );
        let _ = writeln!(
            handle,
            "  Executable : {} (SHA-256: {})",
            self.executable_path, self.self_sha256_libc_hex
        );
        for alert in &self.alerts {
            let _ = writeln!(
                handle,
                "  [{}] {}: {} ({})",
                alert.severity, alert.code, alert.detail, alert.indicator
            );
        }
        let _ = writeln!(
            handle,
            "  ACTION     : Continuing in SAFE HARDENED MODE (raw syscalls prioritized,"
        );
        let _ = writeln!(
            handle,
            "               external subprocesses disabled, untrusted ENV/PATH quarantined)."
        );
        let _ = writeln!(
            handle,
            "================================================================================"
        );
    }
}

/// Raw snapshot of auditor runtime signals (allows deterministic unit testing of every
/// hostile counter-forensics scenario on any OS).
#[derive(Debug, Clone, Default)]
pub struct SelfIntegrityInputs {
    pub executable_path: String,
    pub libc_exe_bytes: Option<Vec<u8>>,
    pub raw_syscall_exe_bytes: Option<Vec<u8>>,
    pub expected_sha256: Option<(String, String)>, // (hex, source)
    pub runtime_env: BTreeMap<String, String>,
    pub raw_proc_self_environ: Option<Vec<u8>>,
    pub host_ld_so_preload: Option<String>,
    pub proc_self_maps: Option<String>,
    pub proc_self_status: Option<String>,
    pub proc_self_mountinfo: Option<String>,
}

/// Runs startup self-integrity checks on the live process, emits an immediate `stderr`
/// warning banner if any hook/tamper attempt is detected, and returns the report +
/// active [`SafeExecutionPolicy`].
pub fn run_startup_self_integrity_guard(
    binary_label: &str,
    explicit_expected_sha256: Option<&str>,
    check_host_ld_so_preload: bool,
) -> SelfIntegrityReport {
    let report =
        verify_current_process_self_integrity(explicit_expected_sha256, check_host_ld_so_preload);
    if report.compromise_attempt_detected {
        report.emit_stderr_alert_banner(binary_label);
    }
    report
}

/// Collects live runtime telemetry from `/proc/self/*`, `current_exe()`, and environment
/// variables, then evaluates auditor self-integrity.
pub fn verify_current_process_self_integrity(
    explicit_expected_sha256: Option<&str>,
    check_host_ld_so_preload: bool,
) -> SelfIntegrityReport {
    let proc_self_exe = Path::new("/proc/self/exe");
    let resolved_exe: PathBuf = if proc_self_exe.exists() {
        fs::read_link(proc_self_exe)
            .or_else(|_| env::current_exe())
            .unwrap_or_else(|_| PathBuf::from("/proc/self/exe"))
    } else {
        env::current_exe().unwrap_or_else(|_| PathBuf::from("fsr-forensic-verdict"))
    };
    let executable_path = resolved_exe.to_string_lossy().into_owned();

    let read_target = if proc_self_exe.exists() {
        proc_self_exe
    } else {
        resolved_exe.as_path()
    };

    let libc_exe_bytes = fs::read(read_target)
        .or_else(|_| fs::read(&resolved_exe))
        .ok();
    let raw_syscall_exe_bytes = raw_syscall_read_file(read_target).ok();

    let expected_sha256 = resolve_expected_self_sha256(explicit_expected_sha256, &resolved_exe);

    let mut runtime_env = BTreeMap::new();
    for (k, v) in env::vars_os() {
        runtime_env.insert(
            k.to_string_lossy().into_owned(),
            v.to_string_lossy().into_owned(),
        );
    }

    let raw_proc_self_environ = raw_syscall_read_file(Path::new("/proc/self/environ"))
        .ok()
        .or_else(|| fs::read("/proc/self/environ").ok());

    let host_ld_so_preload = if check_host_ld_so_preload {
        raw_syscall_read_file(Path::new("/etc/ld.so.preload"))
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .or_else(|| fs::read_to_string("/etc/ld.so.preload").ok())
    } else {
        None
    };

    let proc_self_maps = raw_syscall_read_file(Path::new("/proc/self/maps"))
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .or_else(|| fs::read_to_string("/proc/self/maps").ok());

    let proc_self_status = raw_syscall_read_file(Path::new("/proc/self/status"))
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .or_else(|| fs::read_to_string("/proc/self/status").ok());

    let proc_self_mountinfo = raw_syscall_read_file(Path::new("/proc/self/mountinfo"))
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .or_else(|| fs::read_to_string("/proc/self/mountinfo").ok());

    evaluate_self_integrity_inputs(&SelfIntegrityInputs {
        executable_path,
        libc_exe_bytes,
        raw_syscall_exe_bytes,
        expected_sha256,
        runtime_env,
        raw_proc_self_environ,
        host_ld_so_preload,
        proc_self_maps,
        proc_self_status,
        proc_self_mountinfo,
    })
}

/// Deterministic self-integrity evaluator over [`SelfIntegrityInputs`].
pub fn evaluate_self_integrity_inputs(inputs: &SelfIntegrityInputs) -> SelfIntegrityReport {
    let mut alerts = Vec::new();
    let mut safe_reasons = Vec::new();

    // 1. `/proc/self/exe` SHA-256 computation & dual-path (libc vs raw x86_64 syscall) comparison
    let self_sha256_libc_hex = match &inputs.libc_exe_bytes {
        Some(bytes) => sha256_hex(bytes),
        None => {
            alerts.push(SelfIntegrityAlert {
                code: "HIGH_SELF_EXE_UNREADABLE",
                severity: "HIGH",
                indicator: inputs.executable_path.clone(),
                detail: "Unable to read own executable image (`/proc/self/exe`) via standard I/O"
                    .to_string(),
            });
            safe_reasons.push("self_exe_unreadable".to_string());
            String::from("0000000000000000000000000000000000000000000000000000000000000000")
        }
    };

    let self_sha256_raw_syscall_hex = inputs
        .raw_syscall_exe_bytes
        .as_ref()
        .map(|b| sha256_hex(b));

    if let Some(raw_hex) = &self_sha256_raw_syscall_hex {
        if inputs.libc_exe_bytes.is_some() && !hex_digests_equal(&self_sha256_libc_hex, raw_hex) {
            alerts.push(SelfIntegrityAlert {
                code: "CRITICAL_SELF_EXE_LIBC_READ_HOOK",
                severity: "CRITICAL",
                indicator: format!("libc={} vs raw_syscall={}", self_sha256_libc_hex, raw_hex),
                detail: "Userland libc hook intercepted reading `/proc/self/exe` — raw kernel syscall returned a different binary image".to_string(),
            });
            safe_reasons.push("self_exe_libc_vs_syscall_mismatch".to_string());
        }
    }

    if inputs.executable_path.ends_with(" (deleted)") {
        alerts.push(SelfIntegrityAlert {
            code: "CRITICAL_SELF_EXE_UNLINKED_ON_DISK",
            severity: "CRITICAL",
            indicator: inputs.executable_path.clone(),
            detail: "Running auditor binary `/proc/self/exe` was unlinked or replaced on disk during execution".to_string(),
        });
        safe_reasons.push("self_exe_deleted_on_disk".to_string());
    }

    // 2. Verify against expected field-deployment SHA-256 pin if provided
    let authoritative_hex = self_sha256_raw_syscall_hex
        .as_deref()
        .unwrap_or(&self_sha256_libc_hex);
    let mut expected_sha256_hex = None;
    let mut expected_sha256_source = None;
    let mut expected_sha256_verified = None;

    if let Some((exp_raw, src)) = &inputs.expected_sha256 {
        let exp_norm = extract_leading_hex64(exp_raw).unwrap_or_else(|| exp_raw.trim().to_string());
        let matches = hex_digests_equal(authoritative_hex, &exp_norm);
        expected_sha256_hex = Some(exp_norm.to_ascii_lowercase());
        expected_sha256_source = Some(src.clone());
        expected_sha256_verified = Some(matches);

        if !matches {
            alerts.push(SelfIntegrityAlert {
                code: "CRITICAL_SELF_BINARY_SHA256_MISMATCH",
                severity: "CRITICAL",
                indicator: format!("actual={} expected={}", authoritative_hex, exp_norm),
                detail: format!(
                    "Auditor binary SHA-256 does not match trusted field-deployment digest from `{}` — binary tampering or wrapper replacement suspected",
                    src
                ),
            });
            safe_reasons.push("expected_self_sha256_mismatch".to_string());
        }
    }

    // 3. Audit runtime environment variables (`std::env` + raw `/proc/self/environ`)
    let mut merged_env: BTreeMap<String, String> = inputs.runtime_env.clone();
    if let Some(raw_env) = &inputs.raw_proc_self_environ {
        for entry in raw_env.split(|&b| b == 0) {
            if entry.is_empty() {
                continue;
            }
            let text = String::from_utf8_lossy(entry);
            if let Some((k, v)) = text.split_once('=') {
                // Detect userland `environ` scrubbing where kernel `/proc/self/environ` has a hostile var removed from `std::env`!
                if is_hostile_env_key(k) && !inputs.runtime_env.contains_key(k) && !v.is_empty() {
                    alerts.push(SelfIntegrityAlert {
                        code: "CRITICAL_SELF_ENVIRON_SCRUBBED_HOOK",
                        severity: "CRITICAL",
                        indicator: format!("{}={}", k, v),
                        detail: format!(
                            "Kernel `/proc/self/environ` contains `{}` which was scrubbed from userland `environ` — stealth preload implant active",
                            k
                        ),
                    });
                    safe_reasons.push(format!("scrubbed_proc_self_environ:{}", k));
                }
                merged_env
                    .entry(k.to_string())
                    .or_insert_with(|| v.to_string());
            }
        }
    }

    let mut hostile_env_vars = Vec::new();
    for &key in HOSTILE_RUNTIME_ENV_VARS {
        if let Some(val) = merged_env.get(key) {
            let trimmed = val.trim();
            if trimmed.is_empty() {
                continue;
            }
            hostile_env_vars.push((key.to_string(), trimmed.to_string()));
            let (code, sev) = match key {
                "LD_PRELOAD" | "LD_AUDIT" | "DYLD_INSERT_LIBRARIES" => (
                    "CRITICAL_SELF_ENV_PRELOAD_HIJACK",
                    "CRITICAL",
                ),
                "LD_LIBRARY_PATH" | "LD_ORIGIN_PATH" => (
                    "HIGH_SELF_ENV_LIBRARY_PATH_OVERRIDE",
                    "HIGH",
                ),
                _ => ("HIGH_SELF_ENV_RUNTIME_TAMPER", "HIGH"),
            };
            alerts.push(SelfIntegrityAlert {
                code,
                severity: sev,
                indicator: format!("{}={}", key, trimmed),
                detail: format!(
                    "Untrusted runtime environment variable `{}` is set in the auditor's process context — dynamic linker / resolver hook attempt neutralized via safe mode",
                    key
                ),
            });
            safe_reasons.push(format!("hostile_env:{}", key));
        }
    }

    // 4. Live `/etc/ld.so.preload` check on the host executing the auditor
    if let Some(preload_text) = &inputs.host_ld_so_preload {
        for line in preload_text.lines() {
            let entry = line.split('#').next().unwrap_or("").trim();
            if !entry.is_empty() {
                alerts.push(SelfIntegrityAlert {
                    code: "CRITICAL_HOST_LD_SO_PRELOAD_ACTIVE",
                    severity: "CRITICAL",
                    indicator: format!("/etc/ld.so.preload -> {}", entry),
                    detail: format!(
                        "Audited host defines global `/etc/ld.so.preload` (`{}`) attempting to inject shared objects into every dynamically linked process including the auditor",
                        entry
                    ),
                });
                safe_reasons.push("host_etc_ld_so_preload".to_string());
            }
        }
    }

    // 5. Inspect `/proc/self/maps` for injected ephemeral / deleted shared objects inside our own address space
    let mut suspicious_self_mappings = Vec::new();
    if let Some(maps_text) = &inputs.proc_self_maps {
        for line in maps_text.lines() {
            // Format: addr perms offset dev inode pathname
            let mut cols = line.split_whitespace();
            let _addr = cols.next();
            let perms = cols.next().unwrap_or("");
            let _off = cols.next();
            let _dev = cols.next();
            let _ino = cols.next();
            let path_rest: Vec<&str> = cols.collect();
            if path_rest.is_empty() {
                continue;
            }
            let mapped_path = path_rest.join(" ");
            if !mapped_path.starts_with('/') {
                continue;
            }
            let lower = mapped_path.to_ascii_lowercase();
            let is_suspicious = (perms.contains('x') && mapped_path.ends_with(" (deleted)"))
                || lower.starts_with("/dev/shm/")
                || lower.starts_with("/tmp/")
                || lower.starts_with("/var/tmp/")
                || lower.contains("libfaketime")
                || lower.contains("preload")
                || lower.contains("hwid_hook");
            if is_suspicious && !suspicious_self_mappings.contains(&mapped_path) {
                suspicious_self_mappings.push(mapped_path.clone());
                alerts.push(SelfIntegrityAlert {
                    code: "CRITICAL_SELF_MAPS_INJECTED_OBJECT",
                    severity: "CRITICAL",
                    indicator: mapped_path.clone(),
                    detail: format!(
                        "Auditor's own `/proc/self/maps` contains injected or ephemeral shared object `{}` (perms `{}`)",
                        mapped_path, perms
                    ),
                });
                safe_reasons.push(format!("injected_self_vma:{}", mapped_path));
            }
        }
    }

    // 6. Inspect `/proc/self/status` for `TracerPid != 0` (`ptrace` debugger / interceptor)
    let tracer_pid = inputs
        .proc_self_status
        .as_deref()
        .and_then(parse_tracer_pid)
        .unwrap_or(0);
    if tracer_pid != 0 {
        alerts.push(SelfIntegrityAlert {
            code: "CRITICAL_SELF_PTRACE_INTERCEPTION",
            severity: "CRITICAL",
            indicator: format!("TracerPid={}", tracer_pid),
            detail: format!(
                "Host process PID {} is actively `ptrace`-attached to the forensic auditor — syscall return spoofing attempt detected",
                tracer_pid
            ),
        });
        safe_reasons.push(format!("tracer_pid:{}", tracer_pid));
    }

    // 7. Determine field deployment media mount point & read-only (`ro`) mount flag
    let (execution_media_mount_point, execution_media_readonly) = inputs
        .proc_self_mountinfo
        .as_deref()
        .and_then(|mi| resolve_mount_readonly_status(&inputs.executable_path, mi))
        .map(|(mp, ro)| (Some(mp), Some(ro)))
        .unwrap_or((None, None));

    let compromise_attempt_detected = !alerts.is_empty();
    let safe_mode_policy = if compromise_attempt_detected {
        SafeExecutionPolicy::hardened(safe_reasons)
    } else {
        SafeExecutionPolicy::nominal()
    };

    SelfIntegrityReport {
        executable_path: inputs.executable_path.clone(),
        self_sha256_libc_hex,
        self_sha256_raw_syscall_hex,
        expected_sha256_hex,
        expected_sha256_source,
        expected_sha256_verified,
        execution_media_mount_point,
        execution_media_readonly,
        tracer_pid,
        hostile_env_vars,
        suspicious_self_mappings,
        compromise_attempt_detected,
        safe_mode_policy,
        alerts,
    }
}

fn is_hostile_env_key(key: &str) -> bool {
    HOSTILE_RUNTIME_ENV_VARS.contains(&key)
}

fn resolve_expected_self_sha256(
    explicit_cli: Option<&str>,
    resolved_exe: &Path,
) -> Option<(String, String)> {
    if let Some(cli_hex) = explicit_cli {
        let trimmed = cli_hex.trim();
        if !trimmed.is_empty() {
            return Some((trimmed.to_string(), "--expected-self-sha256".to_string()));
        }
    }
    if let Ok(env_hex) = env::var("FSR_EXPECTED_SELF_SHA256") {
        let trimmed = env_hex.trim();
        if !trimmed.is_empty() {
            return Some((
                trimmed.to_string(),
                "env:FSR_EXPECTED_SELF_SHA256".to_string(),
            ));
        }
    }
    // Check adjacent `<exe>.sha256` sidecar file commonly placed on read-only field USB media
    let mut sidecar_os = resolved_exe.as_os_str().to_os_string();
    sidecar_os.push(".sha256");
    let sidecar_path = PathBuf::from(sidecar_os);
    if let Ok(text) = fs::read_to_string(&sidecar_path) {
        if let Some(hex64) = extract_leading_hex64(&text) {
            return Some((hex64, format!("sidecar:{}", sidecar_path.display())));
        }
    }
    None
}

fn extract_leading_hex64(text: &str) -> Option<String> {
    let token = text.split_whitespace().next()?.trim();
    if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(token.to_ascii_lowercase())
    } else {
        None
    }
}

fn parse_tracer_pid(status_text: &str) -> Option<u32> {
    for line in status_text.lines() {
        if let Some(rest) = line.strip_prefix("TracerPid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

fn resolve_mount_readonly_status(exe_path: &str, mountinfo_text: &str) -> Option<(String, bool)> {
    let mut best_mount: Option<(String, bool)> = None;
    for line in mountinfo_text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let mount_point = parts[4];
        let mount_opts = parts[5];
        let matches = if mount_point == "/" {
            exe_path.starts_with('/')
        } else {
            exe_path == mount_point
                || (exe_path.starts_with(mount_point)
                    && exe_path.as_bytes().get(mount_point.len()) == Some(&b'/'))
        };
        if matches {
            let is_ro = mount_opts.split(',').any(|opt| opt == "ro");
            let replace = match &best_mount {
                None => true,
                Some((prev_mp, _)) => mount_point.len() > prev_mp.len(),
            };
            if replace {
                best_mount = Some((mount_point.to_string(), is_ro));
            }
        }
    }
    best_mount
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_readonly_usb_execution_passes_with_nominal_policy() {
        let bin_bytes = b"\x7fELF_mock_clean_auditor_binary_v1";
        let expected = sha256_hex(bin_bytes);
        let inputs = SelfIntegrityInputs {
            executable_path: "/mnt/ir_usb_ro/fsr-forensic-verdict".to_string(),
            libc_exe_bytes: Some(bin_bytes.to_vec()),
            raw_syscall_exe_bytes: Some(bin_bytes.to_vec()),
            expected_sha256: Some((expected, "--expected-self-sha256".to_string())),
            runtime_env: BTreeMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]),
            raw_proc_self_environ: Some(b"PATH=/usr/bin:/bin\0".to_vec()),
            host_ld_so_preload: None,
            proc_self_maps: Some(
                "555555554000-555555600000 r-xp 00000000 08:10 12 /mnt/ir_usb_ro/fsr-forensic-verdict\n"
                    .to_string(),
            ),
            proc_self_status: Some("Name:\tfsr-forensic\nTracerPid:\t0\n".to_string()),
            proc_self_mountinfo: Some(
                "29 1 8:0 / / rw,relatime - xfs /dev/sda1 rw\n\
                 44 29 8:16 / /mnt/ir_usb_ro ro,nosuid,nodev,noexec - iso9660 /dev/sr0 ro\n"
                    .to_string(),
            ),
        };

        let rep = evaluate_self_integrity_inputs(&inputs);
        assert!(!rep.compromise_attempt_detected);
        assert!(!rep.safe_mode_policy.safe_mode_active);
        assert_eq!(rep.expected_sha256_verified, Some(true));
        assert_eq!(
            rep.execution_media_mount_point.as_deref(),
            Some("/mnt/ir_usb_ro")
        );
        assert_eq!(rep.execution_media_readonly, Some(true));
        assert!(rep.alerts.is_empty());
    }

    #[test]
    fn detects_ld_preload_scrubbed_environ_libc_hook_and_activates_safe_mode() {
        let genuine_bytes = b"\x7fELF_genuine_auditor_image";
        let spoofed_bytes = b"\x7fELF_spoofed_by_libc_hook!";
        let expected_hash = sha256_hex(genuine_bytes);

        let mut env_map = BTreeMap::new();
        env_map.insert("LD_LIBRARY_PATH".to_string(), "/tmp/.evil_libs".to_string());

        let inputs = SelfIntegrityInputs {
            executable_path: "/tmp/fsr-forensic-verdict (deleted)".to_string(),
            libc_exe_bytes: Some(spoofed_bytes.to_vec()),
            raw_syscall_exe_bytes: Some(genuine_bytes.to_vec()),
            expected_sha256: Some((
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
                "--expected-self-sha256".to_string(),
            )),
            runtime_env: env_map,
            // Kernel `/proc/self/environ` reveals `LD_PRELOAD` even after userland scrubbed `environ`!
            raw_proc_self_environ: Some(
                b"LD_PRELOAD=/dev/shm/anti_audit.so\0LD_LIBRARY_PATH=/tmp/.evil_libs\0".to_vec(),
            ),
            host_ld_so_preload: Some("/usr/local/lib/libhwid_spoof.so\n".to_string()),
            proc_self_maps: Some(
                "7f0011000000-7f0011004000 r-xp 00000000 00:19 99 /dev/shm/anti_audit.so\n"
                    .to_string(),
            ),
            proc_self_status: Some("Name:\tfsr-forensic\nTracerPid:\t31337\n".to_string()),
            proc_self_mountinfo: None,
        };

        let _ = expected_hash;
        let rep = evaluate_self_integrity_inputs(&inputs);
        assert!(rep.compromise_attempt_detected);
        assert!(rep.safe_mode_policy.safe_mode_active);
        assert!(rep.safe_mode_policy.disable_external_subprocesses);
        assert_eq!(rep.expected_sha256_verified, Some(false));
        assert_eq!(rep.tracer_pid, 31337);

        let codes: Vec<&str> = rep.alerts.iter().map(|a| a.code).collect();
        assert!(codes.contains(&"CRITICAL_SELF_EXE_LIBC_READ_HOOK"));
        assert!(codes.contains(&"CRITICAL_SELF_EXE_UNLINKED_ON_DISK"));
        assert!(codes.contains(&"CRITICAL_SELF_BINARY_SHA256_MISMATCH"));
        assert!(codes.contains(&"CRITICAL_SELF_ENVIRON_SCRUBBED_HOOK"));
        assert!(codes.contains(&"CRITICAL_SELF_ENV_PRELOAD_HIJACK"));
        assert!(codes.contains(&"HIGH_SELF_ENV_LIBRARY_PATH_OVERRIDE"));
        assert!(codes.contains(&"CRITICAL_HOST_LD_SO_PRELOAD_ACTIVE"));
        assert!(codes.contains(&"CRITICAL_SELF_MAPS_INJECTED_OBJECT"));
        assert!(codes.contains(&"CRITICAL_SELF_PTRACE_INTERCEPTION"));
    }
}
