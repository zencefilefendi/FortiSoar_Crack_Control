//! Engine 3: `libssl` / `libcrypto` Dynamic Verification Bypass (Prologue Patch) Analyzer.
//!
//! Resolves exact file offsets of `SSL_get_verify_result`, `X509_verify_cert`,
//! `EVP_VerifyFinal`, and `EVP_DigestVerifyFinal` from `.dynsym`/`.symtab` and `.rela.plt`
//! tables inside `/usr/lib64/libssl.so*` and `/usr/lib64/libcrypto.so*`, inspecting
//! x86_64 function prologues (including after RHEL 8/9 Intel CET `endbr64` `f3 0f 1e fa`)
//! for hardcoded `mov eax, 0; ret` (`b8 00 00 00 00 c3`), `mov eax, 1; ret`
//! (`b8 01 00 00 00 c3`), `xor eax, eax; ret`, and inline detour patches.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use fsr_deep_audit::crypto::{hex_encode, sha256_hex};
use fsr_deep_audit::elf_vma_diff::{parse_elf64_bytes, Elf64Info, Elf64Section};
use fsr_deep_audit::hw_integrity::{join_rooted, raw_syscall_read_file};
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};

/// High-value OpenSSL verification functions targeted by binary crackers.
pub const TARGET_OPENSSL_VERIFY_SYMBOLS: &[&str] = &[
    "SSL_get_verify_result",
    "X509_verify_cert",
    "EVP_VerifyFinal",
    "EVP_DigestVerifyFinal",
    "X509_verify",
    "RSA_verify",
];

const PT_LOAD: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_DYNSYM: u32 = 11;
const R_X86_64_JUMP_SLOT: u32 = 7;

/// Resolved symbol prologue location inside an on-disk ELF64 shared library.
#[derive(Debug, Clone)]
pub struct ResolvedSslSymbol {
    pub symbol_name: String,
    pub source_table: &'static str,
    pub elf_vaddr: u64,
    pub file_offset: u64,
    pub symbol_size: u64,
    pub prologue_bytes: Vec<u8>,
}

/// Output of Engine 3 (`ssl_bypass_check`).
pub struct SslBypassCheckResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 3 against `libssl.so*` and `libcrypto.so*` shared libraries under `root`.
pub fn run_ssl_bypass_audit(root: &Path) -> SslBypassCheckResult {
    let mut findings = Vec::new();
    let candidate_files = discover_ssl_crypto_libraries(root);

    let mut audited_libs = Vec::new();
    let mut total_symbols_inspected = 0u64;

    for (logical_path, full_path) in candidate_files {
        let Some(bytes) = read_bytes(&full_path) else {
            continue;
        };
        let Ok(elf) = parse_elf64_bytes(&bytes) else {
            continue;
        };

        let file_sha256 = sha256_hex(&bytes);
        let resolved = resolve_target_symbols(&bytes, &elf);
        total_symbols_inspected += resolved.len() as u64;

        let mut sym_summaries = Vec::new();
        for sym in &resolved {
            sym_summaries.push(JsonValue::OrderedObject(vec![
                ("symbol".to_string(), JsonValue::str(&sym.symbol_name)),
                ("table".to_string(), JsonValue::str(sym.source_table)),
                (
                    "elf_vaddr".to_string(),
                    JsonValue::str(format!("0x{:08x}", sym.elf_vaddr)),
                ),
                (
                    "file_offset".to_string(),
                    JsonValue::str(format!("0x{:08x}", sym.file_offset)),
                ),
                (
                    "prologue_hex".to_string(),
                    JsonValue::str(hex_encode(&sym.prologue_bytes)),
                ),
            ]));

            let is_plt_stub = sym.source_table == ".rela.plt->plt";
            if let Some((patch_sig, forced_ret)) =
                detect_hardcoded_verify_bypass(&sym.prologue_bytes, sym.symbol_size, is_plt_stub)
            {
                findings.push(
                    Finding::new(
                        EngineId::SslBypassCheck,
                        "CRITICAL_SSL_VERIFY_PROLOGUE_BYPASS",
                        Severity::Critical,
                        format!("{}!{}+0x{:x}", logical_path, sym.symbol_name, sym.file_offset),
                        format!(
                            "Hardcoded certificate/signature verification bypass `{}` ({}) in {} symbol `{}` at file offset 0x{:08x}",
                            patch_sig, forced_ret, logical_path, sym.symbol_name, sym.file_offset
                        ),
                    )
                    .with_evidence("library_path", JsonValue::str(&logical_path))
                    .with_evidence("library_sha256", JsonValue::str(&file_sha256))
                    .with_evidence("symbol_name", JsonValue::str(&sym.symbol_name))
                    .with_evidence("resolution_source", JsonValue::str(sym.source_table))
                    .with_evidence(
                        "elf_vaddr",
                        JsonValue::str(format!("0x{:08x}", sym.elf_vaddr)),
                    )
                    .with_evidence(
                        "file_offset",
                        JsonValue::str(format!("0x{:08x}", sym.file_offset)),
                    )
                    .with_evidence(
                        "prologue_hex",
                        JsonValue::str(hex_encode(&sym.prologue_bytes)),
                    )
                    .with_evidence("patch_signature", JsonValue::str(patch_sig))
                    .with_evidence("forced_return_semantics", JsonValue::str(forced_ret)),
                );
            }
        }

        audited_libs.push(JsonValue::OrderedObject(vec![
            ("path".to_string(), JsonValue::str(&logical_path)),
            ("sha256".to_string(), JsonValue::str(file_sha256)),
            (
                "symbols_resolved".to_string(),
                JsonValue::Array(sym_summaries),
            ),
        ]));
    }

    let summary = JsonValue::OrderedObject(vec![
        (
            "libraries_audited_count".to_string(),
            JsonValue::Uint(audited_libs.len() as u64),
        ),
        (
            "verification_symbols_inspected".to_string(),
            JsonValue::Uint(total_symbols_inspected),
        ),
        ("libraries".to_string(), JsonValue::Array(audited_libs)),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    SslBypassCheckResult { summary, findings }
}

/// Resolves target OpenSSL symbols from `.dynsym`, `.symtab`, and `.rela.plt` -> `.plt`/`.plt.sec`.
pub fn resolve_target_symbols(data: &[u8], elf: &Elf64Info) -> Vec<ResolvedSslSymbol> {
    let mut out = Vec::new();

    // 1. Exported / local definitions in `.dynsym` and `.symtab`
    for sec in &elf.sections {
        if sec.sh_type != SHT_DYNSYM && sec.sh_type != SHT_SYMTAB {
            continue;
        }
        let Some(sym_bytes) = slice_sec(data, sec) else {
            continue;
        };
        let Some(str_sec) = elf.sections.get(sec.sh_link as usize) else {
            continue;
        };
        let Some(str_bytes) = slice_sec(data, str_sec) else {
            continue;
        };
        let table_label = if sec.sh_type == SHT_DYNSYM {
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
            let raw_name = read_cstr(str_bytes, st_name);
            let base_name = raw_name.split('@').next().unwrap_or(&raw_name);
            if !TARGET_OPENSSL_VERIFY_SYMBOLS.contains(&base_name) {
                continue;
            }

            let Some(file_off) = vaddr_to_file_offset(elf, st_value, st_shndx) else {
                continue;
            };
            let off_usize = file_off as usize;
            if off_usize >= data.len() {
                continue;
            }
            let take = 20.min(data.len() - off_usize);
            out.push(ResolvedSslSymbol {
                symbol_name: base_name.to_string(),
                source_table: table_label,
                elf_vaddr: st_value,
                file_offset: file_off,
                symbol_size: st_size,
                prologue_bytes: data[off_usize..off_usize + take].to_vec(),
            });
        }
    }

    // 2. `.rela.plt` jump-slot stubs inside `.plt.sec` or `.plt` (catches PLT stub patching in libssl.so)
    let plt_sec = elf.sections.iter().find(|s| s.name == ".plt.sec");
    let plt_legacy = elf.sections.iter().find(|s| s.name == ".plt");

    if let Some(rela_plt) = elf
        .sections
        .iter()
        .find(|s| s.sh_type == SHT_RELA && s.name == ".rela.plt")
    {
        if let (Some(rela_bytes), Some(dynsym)) = (
            slice_sec(data, rela_plt),
            elf.sections.get(rela_plt.sh_link as usize),
        ) {
            if let (Some(sym_bytes), Some(dynstr)) = (
                slice_sec(data, dynsym),
                elf.sections
                    .get(dynsym.sh_link as usize)
                    .and_then(|s| slice_sec(data, s)),
            ) {
                let ent_sz = if rela_plt.sh_entsize >= 24 {
                    rela_plt.sh_entsize as usize
                } else {
                    24
                };
                let mut slot_idx = 0usize;
                let mut pos = 0usize;
                while pos + 24 <= rela_bytes.len() {
                    let r_info =
                        u64::from_le_bytes(rela_bytes[pos + 8..pos + 16].try_into().unwrap());
                    pos += ent_sz;
                    let cur_slot = slot_idx;
                    slot_idx += 1;

                    if (r_info & 0xffff_ffff) as u32 != R_X86_64_JUMP_SLOT {
                        continue;
                    }
                    let sym_idx = (r_info >> 32) as usize;
                    let sym_off = sym_idx.saturating_mul(24);
                    if sym_off + 24 > sym_bytes.len() {
                        continue;
                    }
                    let st_name =
                        u32::from_le_bytes(sym_bytes[sym_off..sym_off + 4].try_into().unwrap())
                            as usize;
                    let raw_name = read_cstr(dynstr, st_name);
                    let base_name = raw_name.split('@').next().unwrap_or(&raw_name);
                    if !TARGET_OPENSSL_VERIFY_SYMBOLS.contains(&base_name) {
                        continue;
                    }

                    let stub_loc: Option<(u64, u64)> = if let Some(ps) = plt_sec {
                        let off = ps.sh_offset.saturating_add((cur_slot as u64) * 16);
                        let va = ps.sh_addr.saturating_add((cur_slot as u64) * 16);
                        if off + 16 <= ps.sh_offset + ps.sh_size {
                            Some((va, off))
                        } else {
                            None
                        }
                    } else if let Some(pl) = plt_legacy {
                        let off = pl.sh_offset.saturating_add(((cur_slot + 1) as u64) * 16);
                        let va = pl.sh_addr.saturating_add(((cur_slot + 1) as u64) * 16);
                        if off + 16 <= pl.sh_offset + pl.sh_size {
                            Some((va, off))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    if let Some((stub_va, stub_off)) = stub_loc {
                        let o = stub_off as usize;
                        if o + 16 <= data.len() {
                            out.push(ResolvedSslSymbol {
                                symbol_name: base_name.to_string(),
                                source_table: ".rela.plt->plt",
                                elf_vaddr: stub_va,
                                file_offset: stub_off,
                                symbol_size: 16,
                                prologue_bytes: data[o..o + 16].to_vec(),
                            });
                        }
                    }
                }
            }
        }
    }

    out
}

/// Inspects an x86_64 prologue (skipping optional Intel CET `endbr64` `f3 0f 1e fa` and NOPs)
/// for hardcoded `return 0` (`X509_V_OK`) or `return 1` (`verified`) patches.
pub fn detect_hardcoded_verify_bypass(
    prologue: &[u8],
    sym_size: u64,
    is_plt_stub: bool,
) -> Option<(&'static str, &'static str)> {
    let mut s = prologue;

    // Skip Intel CET `endbr64` (`f3 0f 1e fa`) present at the start of RHEL 8/9 functions
    if s.len() >= 4 && s[0..4] == [0xf3, 0x0f, 0x1e, 0xfa] {
        s = &s[4..];
    }
    // Skip leading alignment / patch-padding NOPs (`90` or `66 90`)
    while !s.is_empty() {
        if s[0] == 0x90 {
            s = &s[1..];
        } else if s.len() >= 2 && s[0..2] == [0x66, 0x90] {
            s = &s[2..];
        } else {
            break;
        }
    }

    // 1. `mov eax, 0; ret` (`b8 00 00 00 00 c3`)
    if s.len() >= 6 && s[0..6] == [0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3] {
        return Some(("mov eax, 0; ret (b8 00 00 00 00 c3)", "FORCE_RETURN_0 (X509_V_OK)"));
    }
    // 2. `mov eax, 1; ret` (`b8 01 00 00 00 c3`)
    if s.len() >= 6 && s[0..6] == [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3] {
        return Some(("mov eax, 1; ret (b8 01 00 00 00 c3)", "FORCE_RETURN_1 (VERIFY_SUCCESS)"));
    }
    // 3. `mov rax, 0; ret` (`48 c7 c0 00 00 00 00 c3`)
    if s.len() >= 8 && s[0..8] == [0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, 0xc3] {
        return Some(("mov rax, 0; ret (48 c7 c0 00..00 c3)", "FORCE_RETURN_0 (X509_V_OK)"));
    }
    // 4. `mov rax, 1; ret` (`48 c7 c0 01 00 00 00 c3`)
    if s.len() >= 8 && s[0..8] == [0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0xc3] {
        return Some(("mov rax, 1; ret (48 c7 c0 01..00 c3)", "FORCE_RETURN_1 (VERIFY_SUCCESS)"));
    }
    // 5. `xor eax, eax; ret` / `sub eax, eax; ret` / `xor rax, rax; ret`
    if (s.len() >= 3 && (s[0..3] == [0x31, 0xc0, 0xc3] || s[0..3] == [0x29, 0xc0, 0xc3]))
        || (s.len() >= 4 && s[0..4] == [0x48, 0x31, 0xc0, 0xc3])
    {
        return Some(("xor eax, eax; ret (31 c0 c3)", "FORCE_RETURN_0 (X509_V_OK)"));
    }
    // 6. `xor eax, eax; inc eax; ret` or `xor eax, eax; add eax, 1; ret`
    if (s.len() >= 5 && s[0..5] == [0x31, 0xc0, 0xff, 0xc0, 0xc3])
        || (s.len() >= 6 && s[0..6] == [0x31, 0xc0, 0x83, 0xc0, 0x01, 0xc3])
    {
        return Some(("xor eax, eax; inc eax; ret", "FORCE_RETURN_1 (VERIFY_SUCCESS)"));
    }
    // 7. `push 0; pop rax; ret` (`6a 00 58 c3`) / `push 1; pop rax; ret` (`6a 01 58 c3`)
    if s.len() >= 4 && s[0..4] == [0x6a, 0x00, 0x58, 0xc3] {
        return Some(("push 0; pop rax; ret (6a 00 58 c3)", "FORCE_RETURN_0 (X509_V_OK)"));
    }
    if s.len() >= 4 && s[0..4] == [0x6a, 0x01, 0x58, 0xc3] {
        return Some(("push 1; pop rax; ret (6a 01 58 c3)", "FORCE_RETURN_1 (VERIFY_SUCCESS)"));
    }
    // 8. Absolute 64-bit trampoline `mov rax, imm64; jmp rax` (`48 b8 ... ff e0`)
    if s.len() >= 12 && s[0] == 0x48 && s[1] == 0xb8 && s[10] == 0xff && s[11] == 0xe0 {
        return Some(("mov rax, imm64; jmp rax", "INLINE_DETOUR_TRAMPOLINE"));
    }
    // 9. Immediate `jmp rel32` (`e9 ...`) overwriting a non-trivial function body (exclude PLT stubs)
    if !is_plt_stub && sym_size > 24 && s.len() >= 5 && s[0] == 0xe9 {
        return Some(("jmp rel32 (e9 xx xx xx xx)", "PROLOGUE_JMP_DETOUR_HOOK"));
    }

    None
}

fn vaddr_to_file_offset(elf: &Elf64Info, vaddr: u64, shndx: u16) -> Option<u64> {
    for ph in &elf.phdrs {
        if ph.p_type == PT_LOAD
            && vaddr >= ph.p_vaddr
            && vaddr < ph.p_vaddr.saturating_add(ph.p_filesz)
        {
            return Some(ph.p_offset.saturating_add(vaddr - ph.p_vaddr));
        }
    }
    let sec = elf.sections.get(shndx as usize)?;
    if vaddr >= sec.sh_addr && vaddr < sec.sh_addr.saturating_add(sec.sh_size) {
        Some(sec.sh_offset.saturating_add(vaddr - sec.sh_addr))
    } else {
        None
    }
}

fn discover_ssl_crypto_libraries(root: &Path) -> Vec<(String, PathBuf)> {
    let mut seen_real = BTreeSet::new();
    let mut results = Vec::new();

    let mut search_dirs = vec![
        join_rooted(root, "usr/lib64"),
        join_rooted(root, "lib64"),
    ];

    let opt_dir = join_rooted(root, "opt");
    if let Ok(entries) = fs::read_dir(&opt_dir) {
        for e in entries.flatten() {
            if let Some(n) = e.file_name().to_str() {
                if n == "cyops" || n.starts_with("cyops-") {
                    search_dirs.push(e.path().join("lib"));
                    search_dirs.push(e.path().join("lib64"));
                }
            }
        }
    }

    for dir in search_dirs {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();

        for p in paths {
            let Some(fname) = p.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if !fname.starts_with("libssl.so") && !fname.starts_with("libcrypto.so") {
                continue;
            }
            let resolved = fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
            if !resolved.is_file() || !seen_real.insert(resolved.clone()) {
                continue;
            }
            let rel = p.strip_prefix(root).unwrap_or(&p);
            let logical = format!("/{}", rel.to_string_lossy().trim_start_matches('/'));
            results.push((logical, resolved));
        }
    }

    results.sort_by(|a, b| a.0.cmp(&b.0));
    results
}

fn slice_sec<'a>(data: &'a [u8], sec: &Elf64Section) -> Option<&'a [u8]> {
    let start = sec.sh_offset as usize;
    let end = start.checked_add(sec.sh_size as usize)?;
    data.get(start..end)
}

fn read_cstr(strtab: &[u8], off: usize) -> String {
    let Some(s) = strtab.get(off..) else {
        return String::new();
    };
    let nul = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..nul]).into_owned()
}

fn read_bytes(path: &Path) -> Option<Vec<u8>> {
    match raw_syscall_read_file(path) {
        Ok(b) => Some(b),
        Err(_) => fs::read(path).ok(),
    }
}
