//! Engine 4: Systemd Generator, PAM (`pam_unix.so` ELF64 Prologue) & SSH Persistence Hunter.
//!
//! Performs read-only OS-level persistence and authentication-bypass forensics:
//!   1. Systemd Generators & Cron (`/etc/systemd/system-generators/`, `/usr/lib/systemd/system-generators/`,
//!      `/run/systemd/generator/`, `/etc/systemd/system/*.service`, `/etc/crontab`, `/etc/cron.*/*`,
//!      `/var/spool/cron/*`, `/etc/rc.d/rc.local`) -> `CRITICAL_SYSTEMD_OR_CRON_IMPLANT`.
//!   2. PAM Stack & ELF64 Binary Patching (`/etc/pam.d/*` `pam_exec.so` / `pam_permit.so` abuse +
//!      byte-level `.dynsym`/`.symtab` inspection of `/usr/lib64/security/pam_unix.so`
//!      `pam_sm_authenticate` for `xor eax, eax; ret` / `mov eax, 0; ret` `PAM_SUCCESS=0` patches)
//!      -> `CRITICAL_PAM_AUTH_BYPASS_IMPLANT`.
//!   3. SSH & Ghost UID=0 Accounts (`/etc/passwd` non-`root` `UID == 0` -> `CRITICAL_GHOST_UID0_ACCOUNT`,
//!      `sshd_config` `AuthorizedKeysCommand` / `PermitEmptyPasswords`, and rogue `authorized_keys`
//!      on `root` or service accounts).

use std::fs;
use std::path::{Path, PathBuf};

use fsr_deep_audit::crypto::{hex_encode, sha256_hex};
use fsr_deep_audit::elf_vma_diff::{parse_elf64_bytes, Elf64Info, Elf64Section};
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};
use fsr_net_crypto_audit::asn1_x509::base64_decode;

use crate::connector_skimmer_audit::{display_under_root, join_rooted};

const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const PT_LOAD: u32 = 1;

const TARGET_PAM_SYMBOLS: &[&str] = &["pam_sm_authenticate", "pam_sm_acct_mgmt"];

/// Resolved symbol inside `pam_unix.so`.
#[derive(Debug, Clone)]
pub struct ResolvedPamSymbol {
    pub symbol_name: String,
    pub table: &'static str,
    pub elf_vaddr: u64,
    pub file_offset: u64,
    pub symbol_size: u64,
    pub prologue_bytes: Vec<u8>,
}

/// Output of Engine 4 (`os_persistence_audit`).
pub struct OsPersistenceAuditResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 4 across systemd/cron, PAM configs + `pam_unix.so`, and SSH / `/etc/passwd`.
pub fn run_os_persistence_audit(root: &Path) -> OsPersistenceAuditResult {
    let mut findings = Vec::new();

    let systemd_cron_scanned = scan_systemd_and_cron_persistence(root, &mut findings);
    let (pam_configs_scanned, pam_elf_symbols_checked) =
        scan_pam_configs_and_elf_binaries(root, &mut findings);
    let (passwd_entries_checked, ssh_artifacts_checked) =
        scan_passwd_and_ssh_persistence(root, &mut findings);

    let summary = JsonValue::OrderedObject(vec![
        (
            "systemd_and_cron_files_scanned".to_string(),
            JsonValue::Uint(systemd_cron_scanned),
        ),
        (
            "pam_configs_scanned".to_string(),
            JsonValue::Uint(pam_configs_scanned),
        ),
        (
            "pam_elf_symbols_inspected".to_string(),
            JsonValue::Uint(pam_elf_symbols_checked),
        ),
        (
            "passwd_accounts_inspected".to_string(),
            JsonValue::Uint(passwd_entries_checked),
        ),
        (
            "ssh_configs_and_keyfiles_scanned".to_string(),
            JsonValue::Uint(ssh_artifacts_checked),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    OsPersistenceAuditResult { summary, findings }
}

// ============================================================================
// 4.1 Systemd Generators, Service Units, Crontabs & rc.local
// ============================================================================

fn scan_systemd_and_cron_persistence(root: &Path, findings: &mut Vec<Finding>) -> u64 {
    let mut scanned = 0u64;

    // 1. `/etc/systemd/system-generators` (should be empty on clean RHEL/Rocky 8/9!)
    let etc_gen_dir = join_rooted(root, "etc/systemd/system-generators");
    if let Ok(entries) = fs::read_dir(&etc_gen_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                scanned += 1;
                let label = display_under_root(root, &p);
                let sha = fs::read(&p)
                    .ok()
                    .map(|b| sha256_hex(&b))
                    .unwrap_or_default();
                findings.push(
                    Finding::new(
                        EngineId::OsPersistenceAudit,
                        "CRITICAL_SYSTEMD_OR_CRON_IMPLANT",
                        Severity::Critical,
                        &label,
                        format!(
                            "Unauthorized early-boot systemd generator `{}` found in /etc/systemd/system-generators/",
                            label
                        ),
                    )
                    .with_evidence("generator_path", JsonValue::str(&label))
                    .with_evidence("sha256", JsonValue::str(&sha)),
                );
            }
        }
    }

    // 2. Inspect `/usr/lib/systemd/system-generators/`, `/run/systemd/generator/`, `/etc/systemd/system/`
    let mut unit_and_gen_files = Vec::new();
    for rel in [
        "usr/lib/systemd/system-generators",
        "run/systemd/generator",
        "run/systemd/generator.early",
        "run/systemd/generator.late",
        "etc/systemd/system",
    ] {
        collect_regular_files_bounded(&join_rooted(root, rel), 3, &mut unit_and_gen_files);
    }
    unit_and_gen_files.sort();
    unit_and_gen_files.dedup();

    for path in unit_and_gen_files {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        let label = display_under_root(root, &path);
        for (idx, raw_line) in text.lines().enumerate() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some(reason) = detect_implant_exec_line(line) {
                findings.push(
                    Finding::new(
                        EngineId::OsPersistenceAudit,
                        "CRITICAL_SYSTEMD_OR_CRON_IMPLANT",
                        Severity::Critical,
                        format!("{}:{}", label, idx + 1),
                        format!(
                            "Systemd unit/generator `{}` executes covert or network-backdoor payload ({}) at line {}",
                            label,
                            reason,
                            idx + 1
                        ),
                    )
                    .with_evidence("file", JsonValue::str(&label))
                    .with_evidence("line", JsonValue::Uint((idx + 1) as u64))
                    .with_evidence("reason", JsonValue::str(reason))
                    .with_evidence("directive", JsonValue::str(line)),
                );
            }
        }
    }

    // 3. Inspect Crontabs & `rc.local`
    let mut cron_files = Vec::new();
    for single in ["etc/crontab", "etc/rc.d/rc.local", "etc/rc.local"] {
        let p = join_rooted(root, single);
        if p.is_file() {
            cron_files.push(p);
        }
    }
    for dir_rel in [
        "etc/cron.d",
        "etc/cron.hourly",
        "etc/cron.daily",
        "etc/cron.weekly",
        "etc/cron.monthly",
        "var/spool/cron",
    ] {
        collect_regular_files_bounded(&join_rooted(root, dir_rel), 2, &mut cron_files);
    }
    cron_files.sort();
    cron_files.dedup();

    for cf in cron_files {
        let Ok(text) = fs::read_to_string(&cf) else {
            continue;
        };
        scanned += 1;
        let label = display_under_root(root, &cf);
        for (idx, raw_line) in text.lines().enumerate() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some(reason) = detect_implant_exec_line(line) {
                findings.push(
                    Finding::new(
                        EngineId::OsPersistenceAudit,
                        "CRITICAL_SYSTEMD_OR_CRON_IMPLANT",
                        Severity::Critical,
                        format!("{}:{}", label, idx + 1),
                        format!(
                            "Cron / rc.local persistence implant in {}:{} ({})",
                            label,
                            idx + 1,
                            reason
                        ),
                    )
                    .with_evidence("file", JsonValue::str(&label))
                    .with_evidence("line", JsonValue::Uint((idx + 1) as u64))
                    .with_evidence("reason", JsonValue::str(reason))
                    .with_evidence("command", JsonValue::str(line)),
                );
            }
        }
    }

    scanned
}

fn detect_implant_exec_line(line: &str) -> Option<&'static str> {
    let lower = line.to_ascii_lowercase();
    for (needle, reason) in [
        ("/dev/shm/", "executes binary/script from /dev/shm"),
        ("/tmp/", "executes binary/script from /tmp"),
        ("/var/tmp/", "executes binary/script from /var/tmp"),
        ("/.", "executes binary/script from hidden dot-directory"),
        ("/dev/tcp/", "opens bash /dev/tcp reverse shell socket"),
        ("nc -e", "netcat -e shell bind/reverse backdoor"),
        ("ncat ", "ncat network socket relay"),
        ("socat ", "socat network socket relay"),
        ("mkfifo ", "named-pipe reverse shell"),
        ("base64 -d", "base64-decoded inline shell execution"),
        ("base64 --decode", "base64-decoded inline shell execution"),
    ] {
        if lower.contains(needle) {
            return Some(reason);
        }
    }
    if (lower.contains("curl ") || lower.contains("wget "))
        && (lower.contains("| sh") || lower.contains("| bash") || lower.contains("|sh") || lower.contains("|bash"))
    {
        return Some("remote curl/wget pipe-to-shell dropper");
    }
    if lower.contains("python") && lower.contains("socket") && lower.contains("subprocess") {
        return Some("inline Python socket reverse shell");
    }
    None
}

// ============================================================================
// 4.2 PAM Configuration & ELF64 `pam_unix.so` Prologue Patch Inspection
// ============================================================================

fn scan_pam_configs_and_elf_binaries(root: &Path, findings: &mut Vec<Finding>) -> (u64, u64) {
    let mut pam_confs = 0u64;
    let pam_dir = join_rooted(root, "etc/pam.d");
    if let Ok(entries) = fs::read_dir(&pam_dir) {
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            if !p.is_file() {
                continue;
            }
            let Ok(text) = fs::read_to_string(&p) else {
                continue;
            };
            pam_confs += 1;
            let label = display_under_root(root, &p);
            let service_name = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            audit_pam_service_file(&label, &service_name, &text, findings);
        }
    }

    // Inspect ELF64 `/usr/lib64/security/pam_unix.so` & `/lib64/security/pam_unix.so`
    let mut checked_inodes_sha = Vec::new();
    let mut symbols_inspected = 0u64;
    for rel in [
        "usr/lib64/security/pam_unix.so",
        "lib64/security/pam_unix.so",
    ] {
        let pam_so_path = join_rooted(root, rel);
        let Ok(bytes) = fs::read(&pam_so_path) else {
            continue;
        };
        let sha = sha256_hex(&bytes);
        if checked_inodes_sha.contains(&sha) {
            continue;
        }
        checked_inodes_sha.push(sha.clone());

        let label = display_under_root(root, &pam_so_path);
        if let Ok(elf) = parse_elf64_bytes(&bytes) {
            let resolved = resolve_pam_elf64_symbols(&bytes, &elf);
            symbols_inspected += resolved.len() as u64;
            for sym in resolved {
                if let Some(patch_desc) =
                    detect_pam_success_prologue_patch(&sym.prologue_bytes, sym.symbol_size)
                {
                    findings.push(
                        Finding::new(
                            EngineId::OsPersistenceAudit,
                            "CRITICAL_PAM_AUTH_BYPASS_IMPLANT",
                            Severity::Critical,
                            format!("{}!{}+0x{:x}", label, sym.symbol_name, sym.file_offset),
                            format!(
                                "Binary-patched PAM module `{}`: `{}` at file offset 0x{:08x} hardcoded with `{}` to return PAM_SUCCESS (0) for any password",
                                label, sym.symbol_name, sym.file_offset, patch_desc
                            ),
                        )
                        .with_evidence("library_path", JsonValue::str(&label))
                        .with_evidence("library_sha256", JsonValue::str(&sha))
                        .with_evidence("symbol_name", JsonValue::str(&sym.symbol_name))
                        .with_evidence("table", JsonValue::str(sym.table))
                        .with_evidence("elf_vaddr", JsonValue::str(format!("0x{:08x}", sym.elf_vaddr)))
                        .with_evidence("file_offset", JsonValue::str(format!("0x{:08x}", sym.file_offset)))
                        .with_evidence("prologue_hex", JsonValue::str(hex_encode(&sym.prologue_bytes)))
                        .with_evidence("patch_signature", JsonValue::str(patch_desc)),
                    );
                }
            }
        }
    }

    (pam_confs, symbols_inspected)
}

pub fn audit_pam_service_file(
    file_label: &str,
    service_name: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let is_sensitive_auth_stack = matches!(
        service_name,
        "sshd" | "system-auth" | "system-auth-ac" | "password-auth" | "password-auth-ac" | "su" | "su-l" | "sudo" | "sudo-i" | "login" | "remote"
    );

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let clean = raw_line.split('#').next().unwrap_or("").trim();
        if clean.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = clean.split_whitespace().collect();
        if tokens.len() < 3 {
            continue;
        }
        let pam_type = tokens[0].trim_start_matches('-').to_ascii_lowercase();
        let control = if tokens[1].starts_with('[') {
            // Handle `[default=1 success=ok]` bracketed PAM control syntax
            let mut end_tok = 1usize;
            while end_tok < tokens.len() && !tokens[end_tok].ends_with(']') {
                end_tok += 1;
            }
            if end_tok + 1 >= tokens.len() {
                continue;
            }
            tokens[1..=end_tok].join(" ")
        } else {
            tokens[1].to_ascii_lowercase()
        };

        let mod_idx = if tokens[1].starts_with('[') {
            tokens
                .iter()
                .position(|t| t.ends_with(']'))
                .map(|p| p + 1)
                .unwrap_or(2)
        } else {
            2
        };
        let Some(&module_tok) = tokens.get(mod_idx) else {
            continue;
        };
        let args_str = tokens[mod_idx + 1..].join(" ");

        // 1. `pam_permit.so` on `auth` interface (grants passwordless login!)
        if module_tok.ends_with("pam_permit.so")
            && pam_type == "auth"
            && (is_sensitive_auth_stack || control == "sufficient" || control == "required")
        {
            findings.push(
                Finding::new(
                    EngineId::OsPersistenceAudit,
                    "CRITICAL_PAM_AUTH_BYPASS_IMPLANT",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!(
                        "PAM authentication stack `{}` uses `pam_permit.so` (`{} {}`) — unconditionally permits authentication without valid password",
                        file_label, pam_type, control
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("line", JsonValue::Uint(line_no as u64))
                .with_evidence("pam_line", JsonValue::str(clean)),
            );
        }

        // 2. `pam_exec.so` hook (used by credential-harvesting / backdoor PAM implants, esp. `expose_authtok`)
        if module_tok.ends_with("pam_exec.so") {
            findings.push(
                Finding::new(
                    EngineId::OsPersistenceAudit,
                    "CRITICAL_PAM_AUTH_BYPASS_IMPLANT",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!(
                        "PAM `pam_exec.so` command hook in `{}:{}` (`{}`) — intercepts authentication or harvests plaintext passwords",
                        file_label, line_no, args_str
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("line", JsonValue::Uint(line_no as u64))
                .with_evidence("expose_authtok", JsonValue::Bool(args_str.contains("expose_authtok")))
                .with_evidence("pam_line", JsonValue::str(clean)),
            );
        }

        // 3. Rogue external path PAM module (`/tmp/.../pam_*.so`, `/dev/shm/...`)
        if module_tok.contains("/tmp/")
            || module_tok.contains("/var/tmp/")
            || module_tok.contains("/dev/shm/")
            || module_tok.contains("/.")
        {
            findings.push(
                Finding::new(
                    EngineId::OsPersistenceAudit,
                    "CRITICAL_PAM_AUTH_BYPASS_IMPLANT",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!(
                        "Rogue PAM shared object `{}` loaded from untrusted directory in {}:{}",
                        module_tok, file_label, line_no
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("line", JsonValue::Uint(line_no as u64))
                .with_evidence("module_path", JsonValue::str(module_tok)),
            );
        }
    }
}

/// Resolves `pam_sm_authenticate` and `pam_sm_acct_mgmt` file offsets inside `pam_unix.so`.
pub fn resolve_pam_elf64_symbols(data: &[u8], elf: &Elf64Info) -> Vec<ResolvedPamSymbol> {
    let mut out = Vec::new();
    for sec in &elf.sections {
        if sec.sh_type != SHT_DYNSYM && sec.sh_type != SHT_SYMTAB {
            continue;
        }
        let Some(sym_bytes) = slice_elf_sec(data, sec) else {
            continue;
        };
        let Some(str_sec) = elf.sections.get(sec.sh_link as usize) else {
            continue;
        };
        let Some(str_bytes) = slice_elf_sec(data, str_sec) else {
            continue;
        };
        let table = if sec.sh_type == SHT_DYNSYM {
            ".dynsym"
        } else {
            ".symtab"
        };
        let ent_sz = if sec.sh_entsize >= 24 {
            sec.sh_entsize as usize
        } else {
            24
        };
        let mut pos = 0usize;
        while pos + 24 <= sym_bytes.len() {
            let e = &sym_bytes[pos..pos + 24];
            pos += ent_sz;
            let st_name = u32::from_le_bytes([e[0], e[1], e[2], e[3]]) as usize;
            let st_shndx = u16::from_le_bytes([e[6], e[7]]);
            let st_value = u64::from_le_bytes(e[8..16].try_into().unwrap());
            let st_size = u64::from_le_bytes(e[16..24].try_into().unwrap());
            if st_shndx == 0 || st_value == 0 {
                continue;
            }
            let raw_name = read_elf_cstr(str_bytes, st_name);
            let base_name = raw_name.split('@').next().unwrap_or(&raw_name);
            if !TARGET_PAM_SYMBOLS.contains(&base_name) {
                continue;
            }
            let Some(file_off) = pam_vaddr_to_offset(elf, st_value, st_shndx) else {
                continue;
            };
            let off_u = file_off as usize;
            if off_u >= data.len() {
                continue;
            }
            let take = 20.min(data.len() - off_u);
            out.push(ResolvedPamSymbol {
                symbol_name: base_name.to_string(),
                table,
                elf_vaddr: st_value,
                file_offset: file_off,
                symbol_size: st_size,
                prologue_bytes: data[off_u..off_u + take].to_vec(),
            });
        }
    }
    out
}

/// Detects x86_64 prologue patches forcing `PAM_SUCCESS` (`0`) in `pam_sm_authenticate`.
pub fn detect_pam_success_prologue_patch(prologue: &[u8], symbol_size: u64) -> Option<&'static str> {
    if prologue.is_empty() {
        return None;
    }
    let mut s = prologue;
    // Skip optional RHEL 8/9 Intel CET `endbr64` (`f3 0f 1e fa`)
    if s.starts_with(&[0xf3, 0x0f, 0x1e, 0xfa]) {
        s = &s[4..];
    }
    // Skip leading `nop`s (`0x90`)
    while s.first() == Some(&0x90) {
        s = &s[1..];
    }
    if s.is_empty() {
        return None;
    }

    if s.starts_with(&[0x31, 0xc0, 0xc3]) || s.starts_with(&[0x33, 0xc0, 0xc3]) {
        return Some("xor eax, eax; ret (31 c0 c3 -> PAM_SUCCESS=0)");
    }
    if s.starts_with(&[0x48, 0x31, 0xc0, 0xc3]) {
        return Some("xor rax, rax; ret (48 31 c0 c3 -> PAM_SUCCESS=0)");
    }
    if s.starts_with(&[0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3]) {
        return Some("mov eax, 0; ret (b8 00 00 00 00 c3 -> PAM_SUCCESS=0)");
    }
    if s.starts_with(&[0x29, 0xc0, 0xc3]) {
        return Some("sub eax, eax; ret (29 c0 c3 -> PAM_SUCCESS=0)");
    }
    if s[0] == 0xc3 {
        return Some("ret (c3 immediate return)");
    }
    if s[0] == 0xe9 || s[0] == 0xeb {
        return Some("unconditional jmp hook at function entry");
    }
    if symbol_size > 0 && symbol_size <= 10 && s.contains(&0xc3) {
        return Some("truncated stub returning immediately");
    }
    None
}

// ============================================================================
// 4.3 `/etc/passwd` Ghost UID=0 Accounts & SSH Backdoors
// ============================================================================

fn scan_passwd_and_ssh_persistence(root: &Path, findings: &mut Vec<Finding>) -> (u64, u64) {
    let mut passwd_count = 0u64;
    let mut ssh_count = 0u64;
    let mut user_homes: Vec<(String, u32, String, String)> = Vec::new();

    // 1. `/etc/passwd` ghost UID == 0 inspection
    let passwd_path = join_rooted(root, "etc/passwd");
    if let Ok(passwd_text) = fs::read_to_string(&passwd_path) {
        for (idx, raw_line) in passwd_text.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 7 {
                continue;
            }
            passwd_count += 1;
            let username = fields[0];
            let uid: u32 = fields[2].parse().unwrap_or(65534);
            let home_dir = fields[5];
            let shell = fields[6];

            if uid == 0 && username != "root" {
                findings.push(
                    Finding::new(
                        EngineId::OsPersistenceAudit,
                        "CRITICAL_GHOST_UID0_ACCOUNT",
                        Severity::Critical,
                        format!("/etc/passwd:{}", username),
                        format!(
                            "Ghost root-equivalent account `{}` with UID 0 (home=`{}`, shell=`{}`) in /etc/passwd:{}",
                            username,
                            home_dir,
                            shell,
                            idx + 1
                        ),
                    )
                    .with_evidence("username", JsonValue::str(username))
                    .with_evidence("uid", JsonValue::Uint(0))
                    .with_evidence("home", JsonValue::str(home_dir))
                    .with_evidence("shell", JsonValue::str(shell)),
                );
            }

            user_homes.push((
                username.to_string(),
                uid,
                home_dir.to_string(),
                shell.to_string(),
            ));
        }
    }

    // 2. `/etc/ssh/sshd_config` & `/etc/ssh/sshd_config.d/*.conf`
    let mut sshd_confs = Vec::new();
    let main_sshd = join_rooted(root, "etc/ssh/sshd_config");
    if main_sshd.is_file() {
        sshd_confs.push(main_sshd);
    }
    collect_regular_files_bounded(&join_rooted(root, "etc/ssh/sshd_config.d"), 2, &mut sshd_confs);

    for sc in sshd_confs {
        let Ok(text) = fs::read_to_string(&sc) else {
            continue;
        };
        ssh_count += 1;
        let label = display_under_root(root, &sc);
        audit_sshd_config(&label, &text, findings);
    }

    // 3. Scan `authorized_keys` across discovered `/etc/passwd` homes + `/root` + `/home/*`
    let mut candidate_ak_files: Vec<(String, bool, PathBuf)> = Vec::new();
    for (uname, _uid, home, shell) in &user_homes {
        let is_nologin_service = shell.contains("nologin") || shell.contains("/bin/false");
        for ak_name in ["authorized_keys", "authorized_keys2"] {
            let rel = format!("{}/.ssh/{}", home.trim_start_matches('/'), ak_name);
            candidate_ak_files.push((uname.clone(), is_nologin_service, join_rooted(root, &rel)));
        }
    }
    // Also enumerate `/root/.ssh` and `/home/*/.ssh` directly in case `/etc/passwd` wasn't present in partial dump
    for ak_name in ["authorized_keys", "authorized_keys2"] {
        candidate_ak_files.push((
            "root".to_string(),
            false,
            join_rooted(root, &format!("root/.ssh/{}", ak_name)),
        ));
    }
    if let Ok(homes) = fs::read_dir(join_rooted(root, "home")) {
        for entry in homes.flatten() {
            let uname = entry.file_name().to_string_lossy().into_owned();
            for ak_name in ["authorized_keys", "authorized_keys2"] {
                candidate_ak_files.push((
                    uname.clone(),
                    false,
                    entry.path().join(".ssh").join(ak_name),
                ));
            }
        }
    }

    let mut visited_ak = Vec::new();
    for (uname, is_nologin_service, ak_path) in candidate_ak_files {
        if visited_ak.contains(&ak_path) || !ak_path.is_file() {
            continue;
        }
        visited_ak.push(ak_path.clone());
        let Ok(content) = fs::read_to_string(&ak_path) else {
            continue;
        };
        ssh_count += 1;
        let label = display_under_root(root, &ak_path);

        for (idx, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let key_fp = compute_authorized_key_sha256(line);
            let comment = extract_authorized_key_comment(line);

            // SSH keys on `nologin` daemon accounts (`postgres`, `nginx`, `apache`) or `root` / `authorized_keys2`
            let is_ak2 = label.ends_with("authorized_keys2");
            let sev = if is_nologin_service || uname == "root" || is_ak2 {
                Severity::High
            } else {
                Severity::Medium
            };
            findings.push(
                Finding::new(
                    EngineId::OsPersistenceAudit,
                    "HIGH_SSH_AUTHORIZED_KEY_PERSISTENCE",
                    sev,
                    format!("{}:{}", label, idx + 1),
                    format!(
                        "Pre-installed SSH public key in `{}` for account `{}` (nologin_service={}, comment=`{}`, sha256={})",
                        label, uname, is_nologin_service, comment, key_fp
                    ),
                )
                .with_evidence("file", JsonValue::str(&label))
                .with_evidence("line", JsonValue::Uint((idx + 1) as u64))
                .with_evidence("account", JsonValue::str(&uname))
                .with_evidence("nologin_service_account", JsonValue::Bool(is_nologin_service))
                .with_evidence("key_blob_sha256", JsonValue::str(&key_fp))
                .with_evidence("key_comment", JsonValue::str(&comment)),
            );
        }
    }

    (passwd_count, ssh_count)
}

fn audit_sshd_config(file_label: &str, content: &str, findings: &mut Vec<Finding>) {
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let clean = raw_line.split('#').next().unwrap_or("").trim();
        if clean.is_empty() {
            continue;
        }
        let mut parts = clean.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let val = clean[key.len()..].trim();
        let key_low = key.to_ascii_lowercase();

        if key_low == "authorizedkeyscommand"
            && !val.eq_ignore_ascii_case("none")
            && val != "/usr/bin/sss_ssh_authorizedkeys"
        {
            findings.push(
                Finding::new(
                    EngineId::OsPersistenceAudit,
                    "CRITICAL_SSH_AUTHORIZED_KEYS_COMMAND_BACKDOOR",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!(
                        "SSHD `AuthorizedKeysCommand {}` executes external key-provider binary/script ({}:{})",
                        val, file_label, line_no
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("line", JsonValue::Uint(line_no as u64))
                .with_evidence("command", JsonValue::str(val)),
            );
        } else if key_low == "permitemptypasswords" && val.eq_ignore_ascii_case("yes") {
            findings.push(
                Finding::new(
                    EngineId::OsPersistenceAudit,
                    "CRITICAL_SSH_AUTHORIZED_KEYS_COMMAND_BACKDOOR",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!("SSHD `PermitEmptyPasswords yes` enabled in {}:{}", file_label, line_no),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("line", JsonValue::Uint(line_no as u64)),
            );
        } else if key_low == "authorizedkeysfile"
            && (val.contains("/tmp/") || val.contains("/dev/shm/") || val.contains("/etc/"))
        {
            findings.push(
                Finding::new(
                    EngineId::OsPersistenceAudit,
                    "CRITICAL_SSH_AUTHORIZED_KEYS_COMMAND_BACKDOOR",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!(
                        "SSHD `AuthorizedKeysFile {}` redirected to global/hidden backdoor key path ({}:{})",
                        val, file_label, line_no
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("line", JsonValue::Uint(line_no as u64))
                .with_evidence("authorized_keys_file", JsonValue::str(val)),
            );
        }
    }
}

fn compute_authorized_key_sha256(line: &str) -> String {
    for tok in line.split_whitespace() {
        if tok.len() >= 48
            && tok
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        {
            if let Ok(raw) = base64_decode(tok) {
                return sha256_hex(&raw);
            }
        }
    }
    sha256_hex(line.as_bytes())
}

fn extract_authorized_key_comment(line: &str) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if let Some(key_pos) = parts.iter().position(|t| {
        t.starts_with("ssh-") || t.starts_with("ecdsa-") || t.starts_with("sk-")
    }) {
        if key_pos + 2 < parts.len() {
            return parts[key_pos + 2..].join(" ");
        }
    }
    String::new()
}

fn pam_vaddr_to_offset(elf: &Elf64Info, vaddr: u64, shndx: u16) -> Option<u64> {
    for seg in &elf.phdrs {
        if seg.p_type == PT_LOAD && vaddr >= seg.p_vaddr && vaddr < seg.p_vaddr + seg.p_filesz {
            return Some(seg.p_offset + (vaddr - seg.p_vaddr));
        }
    }
    let sec = elf.sections.get(shndx as usize)?;
    if vaddr >= sec.sh_addr && vaddr < sec.sh_addr + sec.sh_size {
        Some(sec.sh_offset + (vaddr - sec.sh_addr))
    } else {
        None
    }
}

fn slice_elf_sec<'a>(data: &'a [u8], sec: &Elf64Section) -> Option<&'a [u8]> {
    let start = sec.sh_offset as usize;
    let end = start.checked_add(sec.sh_size as usize)?;
    data.get(start..end)
}

fn read_elf_cstr(strtab: &[u8], offset: usize) -> String {
    if offset >= strtab.len() {
        return String::new();
    }
    let slice = &strtab[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

fn collect_regular_files_bounded(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth == 0 || !dir.is_dir() {
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
        let p = entry.path();
        if ft.is_dir() {
            collect_regular_files_bounded(&p, depth - 1, out);
        } else if ft.is_file() {
            out.push(p);
        }
    }
}
