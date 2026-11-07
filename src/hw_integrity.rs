//! Engine 1: Raw x86_64 Syscall Hardware Identity (UUID/MAC) & Preload Hook Detector.
//!
//! Cracked FortiSOAR appliances frequently spoof `/sys/class/dmi/id/product_uuid`
//! and `/sys/class/net/<iface>/address` via `LD_PRELOAD`, `/etc/ld.so.preload`, or
//! patched `libc.so.6` wrappers (`open`, `openat`, `fopen`, `read`) so a single
//! Fortinet license file can be cloned across multiple appliances.
//!
//! This module reads hardware identity and preload artifacts twice:
//!   1. Standard `std::fs::read_to_string` (routed through userland `libc`).
//!   2. Direct Linux `x86_64` kernel `syscall` instruction via `core::arch::asm!`
//!      (`__NR_openat = 257`, `__NR_read = 0`, `__NR_close = 3`), completely
//!      bypassing `libc` PLT/GOT and userland hooks.
//!
//! Any single-byte discrepancy, active `/etc/ld.so.preload` entry, or `LD_PRELOAD` /
//! `LD_AUDIT` hook trace in `/proc/1/environ` triggers `CRITICAL_HW_SPOOF_HOOK`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::crypto::{first_diff_offset, hex_encode, safe_ascii_preview};
use crate::schema::{EngineId, Finding, JsonValue, Severity};

/// Linux x86_64 syscall numbers (`arch/x86/entry/syscalls/syscall_64.tbl`).
pub const SYS_READ: usize = 0;
pub const SYS_CLOSE: usize = 3;
pub const SYS_PREAD64: usize = 17;
pub const SYS_OPENAT: usize = 257;
pub const SYS_GETEUID: usize = 107;

/// Linux `openat(2)` constants on `x86_64`.
pub const AT_FDCWD: i32 = -100;
pub const O_RDONLY: i32 = 0;
pub const O_CLOEXEC: i32 = 0o2000000;

/// Linux errno constants relevant to raw syscall loops.
pub const EINTR: i32 = 4;
pub const ENOENT: i32 = 2;
pub const EACCES: i32 = 13;

/// Maximum bytes read from a single sysfs/procfs descriptor to prevent unbounded allocation.
const MAX_RAW_READ_BYTES: usize = 16 * 1024 * 1024;

/// Structured raw syscall error holding the positive kernel `errno` (or `-1` if unsupported).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSyscallError {
    pub errno: i32,
}

impl RawSyscallError {
    pub fn description(self) -> String {
        match self.errno {
            -1 => "raw_x86_64_syscall_unavailable_on_host_arch".to_string(),
            -2 => "interior_nul_byte_in_path".to_string(),
            -3 => "exceeded_max_forensic_read_limit".to_string(),
            ENOENT => "ENOENT (No such file or directory)".to_string(),
            EACCES => "EACCES (Permission denied)".to_string(),
            1 => "EPERM (Operation not permitted)".to_string(),
            5 => "EIO (Input/output error)".to_string(),
            6 => "ENXIO (No such device or address)".to_string(),
            19 => "ENODEV (No such device)".to_string(),
            22 => "EINVAL (Invalid argument)".to_string(),
            e => format!("errno({})", e),
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_x86_64_raw {
    use super::{
        RawSyscallError, AT_FDCWD, EINTR, MAX_RAW_READ_BYTES, O_CLOEXEC, O_RDONLY, SYS_CLOSE,
        SYS_GETEUID, SYS_OPENAT, SYS_PREAD64, SYS_READ,
    };
    use core::arch::asm;

    #[inline]
    fn decode_ret(ret: isize) -> Result<usize, RawSyscallError> {
        if (-4095..=-1).contains(&ret) {
            Err(RawSyscallError {
                errno: (-ret) as i32,
            })
        } else {
            Ok(ret as usize)
        }
    }

    /// Invokes Linux x86_64 `__NR_openat = 257` directly via `syscall`.
    /// Uses `r10` for the 4th syscall argument (`mode`) per System V AMD64 kernel ABI.
    #[inline]
    pub unsafe fn sys_openat(
        dirfd: i32,
        pathname: *const u8,
        flags: i32,
        mode: u32,
    ) -> Result<i32, RawSyscallError> {
        let ret: isize;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") SYS_OPENAT as isize => ret,
                in("rdi") dirfd as isize,
                in("rsi") pathname as usize,
                in("rdx") flags as isize,
                in("r10") mode as usize,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        decode_ret(ret).map(|fd| fd as i32)
    }

    /// Invokes Linux x86_64 `__NR_read = 0` directly via `syscall`.
    #[inline]
    pub unsafe fn sys_read(
        fd: i32,
        buf: *mut u8,
        count: usize,
    ) -> Result<usize, RawSyscallError> {
        let ret: isize;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") SYS_READ as isize => ret,
                in("rdi") fd as isize,
                in("rsi") buf as usize,
                in("rdx") count,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        decode_ret(ret)
    }

    /// Invokes Linux x86_64 `__NR_pread64 = 17` directly via `syscall`.
    #[inline]
    pub unsafe fn sys_pread64(
        fd: i32,
        buf: *mut u8,
        count: usize,
        offset: u64,
    ) -> Result<usize, RawSyscallError> {
        let ret: isize;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") SYS_PREAD64 as isize => ret,
                in("rdi") fd as isize,
                in("rsi") buf as usize,
                in("rdx") count,
                in("r10") offset as usize,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        decode_ret(ret)
    }

    /// Invokes Linux x86_64 `__NR_close = 3` directly via `syscall`.
    #[inline]
    pub unsafe fn sys_close(fd: i32) -> Result<(), RawSyscallError> {
        let ret: isize;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") SYS_CLOSE as isize => ret,
                in("rdi") fd as isize,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        decode_ret(ret).map(|_| ())
    }

    /// Invokes Linux x86_64 `__NR_geteuid = 107` directly via `syscall`.
    #[inline]
    pub fn sys_geteuid() -> u32 {
        let ret: usize;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") SYS_GETEUID => ret,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack, nomem),
            );
        }
        ret as u32
    }

    /// RAII descriptor guard ensuring `__NR_close` is always executed without `libc::close`.
    pub struct RawFdGuard(pub i32);

    impl Drop for RawFdGuard {
        fn drop(&mut self) {
            if self.0 >= 0 {
                unsafe {
                    let _ = sys_close(self.0);
                }
            }
        }
    }

    pub fn open_readonly_raw(path: &std::path::Path) -> Result<RawFdGuard, RawSyscallError> {
        use std::os::unix::ffi::OsStrExt;
        let raw_bytes = path.as_os_str().as_bytes();
        if raw_bytes.contains(&0) {
            return Err(RawSyscallError { errno: -2 });
        }
        let mut c_path = Vec::with_capacity(raw_bytes.len() + 1);
        c_path.extend_from_slice(raw_bytes);
        c_path.push(0);

        let fd = unsafe { sys_openat(AT_FDCWD, c_path.as_ptr(), O_RDONLY | O_CLOEXEC, 0)? };
        Ok(RawFdGuard(fd))
    }

    pub fn read_entire_file_raw(path: &std::path::Path) -> Result<Vec<u8>, RawSyscallError> {
        let guard = open_readonly_raw(path)?;
        let mut out = Vec::with_capacity(256);
        let mut chunk = [0u8; 4096];

        loop {
            match unsafe { sys_read(guard.0, chunk.as_mut_ptr(), chunk.len()) } {
                Ok(0) => break,
                Ok(n) => {
                    if out.len().saturating_add(n) > MAX_RAW_READ_BYTES {
                        return Err(RawSyscallError { errno: -3 });
                    }
                    out.extend_from_slice(&chunk[..n]);
                }
                Err(RawSyscallError { errno: EINTR }) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    pub fn pread_exact_or_partial_raw(
        path: &std::path::Path,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, RawSyscallError> {
        let guard = open_readonly_raw(path)?;
        let mut out = vec![0u8; len];
        let mut total = 0usize;
        while total < len {
            let cur_off = offset.saturating_add(total as u64);
            match unsafe {
                sys_pread64(
                    guard.0,
                    out[total..].as_mut_ptr(),
                    len - total,
                    cur_off,
                )
            } {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(RawSyscallError { errno: EINTR }) => continue,
                Err(e) => {
                    if total > 0 {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        out.truncate(total);
        Ok(out)
    }
}

/// Reads an entire file directly via Linux x86_64 raw syscalls (`__NR_openat`, `__NR_read`, `__NR_close`).
pub fn raw_syscall_read_file(path: &Path) -> Result<Vec<u8>, RawSyscallError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        linux_x86_64_raw::read_entire_file_raw(path)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (
            path,
            SYS_READ,
            SYS_CLOSE,
            SYS_PREAD64,
            SYS_OPENAT,
            SYS_GETEUID,
            AT_FDCWD,
            O_RDONLY,
            O_CLOEXEC,
            EINTR,
            MAX_RAW_READ_BYTES,
        );
        Err(RawSyscallError { errno: -1 })
    }
}

/// Reads a virtual memory or file range at `offset` directly via `__NR_openat` + `__NR_pread64` + `__NR_close`
/// on Linux x86_64, falling back to `std::os::unix::fs::FileExt::read_at` on non-Linux hosts (e.g. offline tests).
pub fn raw_or_portable_pread(path: &Path, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        linux_x86_64_raw::pread_exact_or_partial_raw(path, offset, len)
            .map_err(|e| io::Error::from_raw_os_error(e.errno.max(1)))
    }
    #[cfg(all(unix, not(all(target_os = "linux", target_arch = "x86_64"))))]
    {
        use std::os::unix::fs::FileExt;
        let file = fs::File::open(path)?;
        let mut buf = vec![0u8; len];
        let mut total = 0usize;
        while total < len {
            match file.read_at(&mut buf[total..], offset.saturating_add(total as u64)) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    if total > 0 {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        buf.truncate(total);
        Ok(buf)
    }
    #[cfg(not(unix))]
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = fs::File::open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        let n = file.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

/// Returns the effective UID using raw x86_64 syscall on Linux x86_64.
pub fn current_euid() -> u32 {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        linux_x86_64_raw::sys_geteuid()
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        0
    }
}

/// Outcome of reading a path through userland `std::fs::read_to_string` (libc).
#[derive(Debug, Clone)]
pub enum LibcReadOutcome {
    Ok(String),
    NonUtf8Bytes(Vec<u8>),
    NotFound,
    PermissionDenied,
    OtherError(String),
}

/// Outcome of reading a path through direct kernel `syscall` (`asm!`).
#[derive(Debug, Clone)]
pub enum RawReadOutcome {
    Ok(Vec<u8>),
    NotFound,
    PermissionDenied,
    UnsupportedHost,
    OtherError(RawSyscallError),
}

/// Provider trait enabling live raw-syscall auditing on Linux x86_64 and deterministic unit testing.
pub trait HwReadProvider {
    fn read_via_libc_string(&self, path: &Path) -> LibcReadOutcome;
    fn read_via_raw_syscall(&self, path: &Path) -> RawReadOutcome;
    fn list_net_interfaces(&self, root: &Path) -> Vec<String>;
}

/// Production provider executing `std::fs::read_to_string` vs `core::arch::asm!` syscalls.
pub struct LiveSystemHwProvider;

impl HwReadProvider for LiveSystemHwProvider {
    fn read_via_libc_string(&self, path: &Path) -> LibcReadOutcome {
        match fs::read_to_string(path) {
            Ok(s) => LibcReadOutcome::Ok(s),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => match fs::read(path) {
                Ok(raw) => LibcReadOutcome::NonUtf8Bytes(raw),
                Err(inner) => LibcReadOutcome::OtherError(inner.to_string()),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => LibcReadOutcome::NotFound,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                LibcReadOutcome::PermissionDenied
            }
            Err(e) => LibcReadOutcome::OtherError(e.to_string()),
        }
    }

    fn read_via_raw_syscall(&self, path: &Path) -> RawReadOutcome {
        match raw_syscall_read_file(path) {
            Ok(bytes) => RawReadOutcome::Ok(bytes),
            Err(RawSyscallError { errno: -1 }) => RawReadOutcome::UnsupportedHost,
            Err(RawSyscallError { errno: ENOENT }) => RawReadOutcome::NotFound,
            Err(RawSyscallError { errno: EACCES }) => RawReadOutcome::PermissionDenied,
            Err(e) => RawReadOutcome::OtherError(e),
        }
    }

    fn list_net_interfaces(&self, root: &Path) -> Vec<String> {
        let mut ifaces = BTreeSet::new();

        // Source 1: standard directory listing of /sys/class/net
        let sys_net = join_rooted(root, "sys/class/net");
        if let Ok(entries) = fs::read_dir(&sys_net) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if !name.is_empty() && !name.starts_with('.') {
                        ifaces.insert(name.to_string());
                    }
                }
            }
        }

        // Source 2: cross-check /proc/net/dev via raw syscall in case `readdir` on /sys/class/net is hooked
        let proc_net_dev = join_rooted(root, "proc/net/dev");
        let dev_bytes = match raw_syscall_read_file(&proc_net_dev) {
            Ok(b) => Some(b),
            Err(_) => fs::read(&proc_net_dev).ok(),
        };
        if let Some(bytes) = dev_bytes {
            let text = String::from_utf8_lossy(&bytes);
            for line in text.lines().skip(2) {
                if let Some((iface_raw, _rest)) = line.split_once(':') {
                    let iface = iface_raw.trim();
                    if !iface.is_empty() {
                        ifaces.insert(iface.to_string());
                    }
                }
            }
        }

        ifaces.into_iter().collect()
    }
}

/// Output of Engine 1 (`hw_integrity`).
pub struct HwIntegrityResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 1 against `root` (normally `"/"` on live FortiSOAR appliances).
pub fn run_hw_integrity_audit(root: &Path) -> HwIntegrityResult {
    run_hw_integrity_with_provider(root, &LiveSystemHwProvider)
}

/// Executes hardware UUID/MAC dual-path verification and preload/environ hook checks.
pub fn run_hw_integrity_with_provider<P: HwReadProvider>(
    root: &Path,
    provider: &P,
) -> HwIntegrityResult {
    let mut findings = Vec::new();
    let mut checked_targets = Vec::new();
    let mut verified_identities: BTreeMap<String, JsonValue> = BTreeMap::new();
    let mut raw_syscall_active = true;

    // 1. Build deterministic list of DMI + NIC hardware identity files
    let mut target_paths: Vec<(String, PathBuf)> = Vec::new();
    let dmi_rel_paths = [
        "sys/class/dmi/id/product_uuid",
        "sys/class/dmi/id/product_serial",
        "sys/class/dmi/id/board_serial",
    ];
    for rel in &dmi_rel_paths {
        target_paths.push((format!("/{}", rel), join_rooted(root, rel)));
    }

    let interfaces = provider.list_net_interfaces(root);
    for iface in &interfaces {
        let rel = format!("sys/class/net/{}/address", iface);
        target_paths.push((format!("/{}", rel), join_rooted(root, &rel)));
    }

    // 2. Compare `std::fs::read_to_string` (libc) vs raw x86_64 syscall (`__NR_openat`/`__NR_read`/`__NR_close`)
    for (logical_path, full_path) in &target_paths {
        let libc_res = provider.read_via_libc_string(full_path);
        let raw_res = provider.read_via_raw_syscall(full_path);

        if matches!(raw_res, RawReadOutcome::UnsupportedHost) {
            raw_syscall_active = false;
        }

        checked_targets.push(JsonValue::str(logical_path));

        compare_libc_vs_raw(
            logical_path,
            &libc_res,
            &raw_res,
            &mut verified_identities,
            &mut findings,
        );
    }

    // 3. Inspect /etc/ld.so.preload (both dual-path stealth check and content inspection)
    let ld_preload_path = join_rooted(root, "etc/ld.so.preload");
    let ld_libc = provider.read_via_libc_string(&ld_preload_path);
    let ld_raw = provider.read_via_raw_syscall(&ld_preload_path);
    checked_targets.push(JsonValue::str("/etc/ld.so.preload"));
    inspect_ld_so_preload(&ld_libc, &ld_raw, &mut findings);

    // 4. Inspect /proc/1/environ and /proc/self/environ for LD_PRELOAD / LD_AUDIT / hook traces
    let environ_targets = [
        ("/proc/1/environ", join_rooted(root, "proc/1/environ")),
        ("/proc/self/environ", join_rooted(root, "proc/self/environ")),
    ];
    for (logical_env, full_env) in &environ_targets {
        let env_libc = provider.read_via_libc_string(full_env);
        let env_raw = provider.read_via_raw_syscall(full_env);
        checked_targets.push(JsonValue::str(*logical_env));
        inspect_proc_environ(logical_env, &env_libc, &env_raw, &mut findings);
    }

    let summary = JsonValue::OrderedObject(vec![
        (
            "raw_syscall_enforced".to_string(),
            JsonValue::Bool(raw_syscall_active),
        ),
        (
            "syscalls_used".to_string(),
            JsonValue::Array(vec![
                JsonValue::str("__NR_openat(257)"),
                JsonValue::str("__NR_read(0)"),
                JsonValue::str("__NR_close(3)"),
            ]),
        ),
        (
            "network_interfaces_discovered".to_string(),
            JsonValue::Array(interfaces.into_iter().map(JsonValue::Str).collect()),
        ),
        (
            "checked_targets_count".to_string(),
            JsonValue::Uint(checked_targets.len() as u64),
        ),
        (
            "checked_targets".to_string(),
            JsonValue::Array(checked_targets),
        ),
        (
            "verified_hardware_identities".to_string(),
            JsonValue::MapObject(verified_identities),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    HwIntegrityResult { summary, findings }
}

fn compare_libc_vs_raw(
    logical_path: &str,
    libc_res: &LibcReadOutcome,
    raw_res: &RawReadOutcome,
    verified_identities: &mut BTreeMap<String, JsonValue>,
    findings: &mut Vec<Finding>,
) {
    let libc_bytes_opt: Option<Vec<u8>> = match libc_res {
        LibcReadOutcome::Ok(s) => Some(s.as_bytes().to_vec()),
        LibcReadOutcome::NonUtf8Bytes(b) => Some(b.clone()),
        _ => None,
    };

    match (libc_bytes_opt, raw_res) {
        (Some(libc_bytes), RawReadOutcome::Ok(raw_bytes)) => {
            if let Some(diff_idx) = first_diff_offset(&libc_bytes, raw_bytes) {
                let finding = Finding::new(
                    EngineId::HwIntegrity,
                    "CRITICAL_HW_SPOOF_HOOK",
                    Severity::Critical,
                    logical_path,
                    format!(
                        "Userland libc vs raw x86_64 kernel syscall byte mismatch on {} at byte offset {} (active UUID/MAC spoofing hook)",
                        logical_path, diff_idx
                    ),
                )
                .with_evidence("first_diff_byte_offset", JsonValue::Uint(diff_idx as u64))
                .with_evidence("libc_byte_len", JsonValue::Uint(libc_bytes.len() as u64))
                .with_evidence("raw_syscall_byte_len", JsonValue::Uint(raw_bytes.len() as u64))
                .with_evidence(
                    "libc_value_preview",
                    JsonValue::str(safe_ascii_preview(&libc_bytes, 256)),
                )
                .with_evidence(
                    "raw_syscall_value_preview",
                    JsonValue::str(safe_ascii_preview(raw_bytes, 256)),
                )
                .with_evidence("libc_hex", JsonValue::str(hex_encode(&libc_bytes)))
                .with_evidence("raw_syscall_hex", JsonValue::str(hex_encode(raw_bytes)));
                findings.push(finding);
            } else {
                let trimmed = String::from_utf8_lossy(raw_bytes).trim().to_string();
                verified_identities.insert(logical_path.to_string(), JsonValue::str(trimmed));
            }
        }
        (Some(libc_bytes), RawReadOutcome::NotFound) => {
            // File does not exist in kernel sysfs, yet userland `libc` returned synthetic data!
            let finding = Finding::new(
                EngineId::HwIntegrity,
                "CRITICAL_HW_SPOOF_HOOK",
                Severity::Critical,
                logical_path,
                format!(
                    "Userland libc returned synthetic hardware identity for {}, while raw kernel openat(257) returned ENOENT",
                    logical_path
                ),
            )
            .with_evidence(
                "libc_value_preview",
                JsonValue::str(safe_ascii_preview(&libc_bytes, 256)),
            )
            .with_evidence("libc_hex", JsonValue::str(hex_encode(&libc_bytes)))
            .with_evidence("raw_syscall_status", JsonValue::str("ENOENT"));
            findings.push(finding);
        }
        (None, RawReadOutcome::Ok(raw_bytes))
            if matches!(libc_res, LibcReadOutcome::NotFound) =>
        {
            // Kernel sees the file, but userland `libc` claims ENOENT!
            let finding = Finding::new(
                EngineId::HwIntegrity,
                "CRITICAL_HW_SPOOF_HOOK",
                Severity::Critical,
                logical_path,
                format!(
                    "Userland libc concealed {} (ENOENT), while raw kernel openat(257) read {} bytes",
                    logical_path,
                    raw_bytes.len()
                ),
            )
            .with_evidence("libc_status", JsonValue::str("ENOENT"))
            .with_evidence(
                "raw_syscall_value_preview",
                JsonValue::str(safe_ascii_preview(raw_bytes, 256)),
            )
            .with_evidence("raw_syscall_hex", JsonValue::str(hex_encode(raw_bytes)));
            findings.push(finding);
        }
        (Some(libc_bytes), RawReadOutcome::PermissionDenied) => {
            // Kernel denied openat(257) with EACCES (e.g., 0400 product_uuid), yet userland libc returned synthetic data!
            let finding = Finding::new(
                EngineId::HwIntegrity,
                "CRITICAL_HW_SPOOF_HOOK",
                Severity::Critical,
                logical_path,
                format!(
                    "Userland libc returned synthetic data for {}, whereas raw kernel openat(257) returned EACCES",
                    logical_path
                ),
            )
            .with_evidence(
                "libc_value_preview",
                JsonValue::str(safe_ascii_preview(&libc_bytes, 256)),
            )
            .with_evidence("libc_hex", JsonValue::str(hex_encode(&libc_bytes)))
            .with_evidence("raw_syscall_status", JsonValue::str("EACCES"));
            findings.push(finding);
        }
        (Some(libc_bytes), RawReadOutcome::OtherError(err)) => {
            let finding = Finding::new(
                EngineId::HwIntegrity,
                "CRITICAL_HW_SPOOF_HOOK",
                Severity::Critical,
                logical_path,
                format!(
                    "Userland libc returned synthetic data for {}, whereas raw kernel syscall failed with {}",
                    logical_path,
                    err.description()
                ),
            )
            .with_evidence(
                "libc_value_preview",
                JsonValue::str(safe_ascii_preview(&libc_bytes, 256)),
            )
            .with_evidence("raw_syscall_error", JsonValue::str(err.description()));
            findings.push(finding);
        }
        (Some(libc_bytes), RawReadOutcome::UnsupportedHost) => {
            let trimmed = String::from_utf8_lossy(&libc_bytes).trim().to_string();
            verified_identities.insert(logical_path.to_string(), JsonValue::str(trimmed));
        }
        _ => {}
    }
}

fn inspect_ld_so_preload(
    libc_res: &LibcReadOutcome,
    raw_res: &RawReadOutcome,
    findings: &mut Vec<Finding>,
) {
    let libc_bytes = match libc_res {
        LibcReadOutcome::Ok(s) => Some(s.as_bytes().to_vec()),
        LibcReadOutcome::NonUtf8Bytes(b) => Some(b.clone()),
        _ => None,
    };

    // Check if userland rootkit hides /etc/ld.so.preload from libc while kernel sees it
    if let RawReadOutcome::Ok(raw_bytes) = raw_res {
        match &libc_bytes {
            None => {
                findings.push(
                    Finding::new(
                        EngineId::HwIntegrity,
                        "CRITICAL_HW_SPOOF_HOOK",
                        Severity::Critical,
                        "/etc/ld.so.preload",
                        "Stealth userland hook hides /etc/ld.so.preload from libc while raw kernel openat(257) exposed its contents",
                    )
                    .with_evidence(
                        "raw_syscall_value_preview",
                        JsonValue::str(safe_ascii_preview(raw_bytes, 512)),
                    )
                    .with_evidence("raw_syscall_hex", JsonValue::str(hex_encode(raw_bytes))),
                );
            }
            Some(lb) if lb != raw_bytes => {
                let diff_off = first_diff_offset(lb, raw_bytes).unwrap_or(0);
                findings.push(
                    Finding::new(
                        EngineId::HwIntegrity,
                        "CRITICAL_HW_SPOOF_HOOK",
                        Severity::Critical,
                        "/etc/ld.so.preload",
                        "Content mismatch between libc and raw kernel syscall when reading /etc/ld.so.preload",
                    )
                    .with_evidence("first_diff_byte_offset", JsonValue::Uint(diff_off as u64))
                    .with_evidence(
                        "libc_value_preview",
                        JsonValue::str(safe_ascii_preview(lb, 512)),
                    )
                    .with_evidence(
                        "raw_syscall_value_preview",
                        JsonValue::str(safe_ascii_preview(raw_bytes, 512)),
                    ),
                );
            }
            _ => {}
        }
    }

    // Prefer raw kernel bytes when available, otherwise inspect libc bytes
    let authoritative_bytes = match raw_res {
        RawReadOutcome::Ok(b) => Some(b.as_slice()),
        _ => libc_bytes.as_deref(),
    };

    if let Some(bytes) = authoritative_bytes {
        let content = String::from_utf8_lossy(bytes);
        let mut preload_entries = Vec::new();
        for line in content.lines() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            for token in trimmed.split_whitespace() {
                if !token.is_empty() {
                    preload_entries.push(token.to_string());
                }
            }
        }

        if !preload_entries.is_empty() {
            findings.push(
                Finding::new(
                    EngineId::HwIntegrity,
                    "CRITICAL_HW_SPOOF_HOOK",
                    Severity::Critical,
                    "/etc/ld.so.preload",
                    format!(
                        "Global dynamic linker hook active via /etc/ld.so.preload ({} shared library entries)",
                        preload_entries.len()
                    ),
                )
                .with_evidence(
                    "preloaded_libraries",
                    JsonValue::Array(preload_entries.into_iter().map(JsonValue::Str).collect()),
                )
                .with_evidence("raw_hex", JsonValue::str(hex_encode(bytes))),
            );
        }
    }
}

fn inspect_proc_environ(
    logical_path: &str,
    libc_res: &LibcReadOutcome,
    raw_res: &RawReadOutcome,
    findings: &mut Vec<Finding>,
) {
    let libc_bytes = match libc_res {
        LibcReadOutcome::Ok(s) => Some(s.as_bytes().to_vec()),
        LibcReadOutcome::NonUtf8Bytes(b) => Some(b.clone()),
        _ => None,
    };

    if let (Some(lb), RawReadOutcome::Ok(rb)) = (&libc_bytes, raw_res) {
        if let Some(diff_idx) = first_diff_offset(lb, rb) {
            findings.push(
                Finding::new(
                    EngineId::HwIntegrity,
                    "CRITICAL_HW_SPOOF_HOOK",
                    Severity::Critical,
                    logical_path,
                    format!(
                        "Userland hook sanitized or altered {} (libc vs raw syscall mismatch at byte {})",
                        logical_path, diff_idx
                    ),
                )
                .with_evidence("first_diff_byte_offset", JsonValue::Uint(diff_idx as u64))
                .with_evidence("libc_byte_len", JsonValue::Uint(lb.len() as u64))
                .with_evidence("raw_syscall_byte_len", JsonValue::Uint(rb.len() as u64)),
            );
        }
    }

    let authoritative_bytes = match raw_res {
        RawReadOutcome::Ok(b) => Some(b.as_slice()),
        _ => libc_bytes.as_deref(),
    };

    let Some(bytes) = authoritative_bytes else {
        return;
    };

    let mut suspicious_vars = Vec::new();
    for entry in bytes.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        let kv = String::from_utf8_lossy(entry);
        let Some((key, val)) = kv.split_once('=') else {
            continue;
        };

        let is_direct_hook_var = matches!(key, "LD_PRELOAD" | "LD_AUDIT" | "LD_ORIGIN_PATH");
        let val_lower = val.to_ascii_lowercase();
        let is_suspicious_lib_path = key == "LD_LIBRARY_PATH"
            && (val.contains("/tmp")
                || val.contains("/dev/shm")
                || val.contains("/var/tmp")
                || val_lower.contains("spoof")
                || val_lower.contains("hook")
                || val_lower.contains("crack")
                || val_lower.contains("uuid")
                || val_lower.contains("fakelib"));

        if (is_direct_hook_var && !val.trim().is_empty()) || is_suspicious_lib_path {
            suspicious_vars.push(format!("{}={}", key, val));
        }
    }

    if !suspicious_vars.is_empty() {
        findings.push(
            Finding::new(
                EngineId::HwIntegrity,
                "CRITICAL_HW_SPOOF_HOOK",
                Severity::Critical,
                logical_path,
                format!(
                    "Dynamic linker hook environment variable(s) detected in {}",
                    logical_path
                ),
            )
            .with_evidence(
                "hook_environment_entries",
                JsonValue::Array(suspicious_vars.into_iter().map(JsonValue::Str).collect()),
            ),
        );
    }
}

/// Joins a relative path safely onto `root` without allowing leading `/` in `rel` to discard `root`.
pub fn join_rooted(root: &Path, rel: &str) -> PathBuf {
    let clean = rel.trim_start_matches('/');
    if clean.is_empty() {
        root.to_path_buf()
    } else {
        root.join(clean)
    }
}
