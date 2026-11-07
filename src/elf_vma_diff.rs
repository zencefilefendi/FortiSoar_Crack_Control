//! Engine 2: ELF64 Disk-Memory (VMA) Byte Diff & GOT/PLT Injection Analyzer.
//!
//! Scans `/proc` for `uwsgi`, `python3`, `celery`, and `nginx` processes, inspects
//! `/proc/<pid>/maps` for anonymous/deleted/tmp-backed shared objects, parses on-disk
//! ELF64 headers/sections/relocations from raw offsets, diffs `.text`/`.plt` against
//! `/proc/<pid>/mem`, and verifies `.got`/`.got.plt` function pointers against mapped VMAs.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::hex_encode;
use crate::hw_integrity::{join_rooted, raw_or_portable_pread, raw_syscall_read_file};
use crate::schema::{EngineId, Finding, JsonValue, Severity};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EM_X86_64: u16 = 62;

const PT_LOAD: u32 = 1;
const SHT_DYNAMIC: u32 = 6;
const SHT_RELA: u32 = 4;
const SHT_DYNSYM: u32 = 11;

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_SONAME: i64 = 14;
const DT_RPATH: i64 = 15;
const DT_TEXTREL: i64 = 22;
const DT_RUNPATH: i64 = 29;
const DT_FLAGS: i64 = 30;
const DF_TEXTREL: u64 = 0x4;

const R_X86_64_GLOB_DATA: u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;

/// Parsed ELF64 Program Header (`Elf64_Phdr`).
#[derive(Debug, Clone)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// Parsed ELF64 Section Header (`Elf64_Shdr`).
#[derive(Debug, Clone)]
pub struct Elf64Section {
    pub name: String,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_entsize: u64,
}

/// Parsed GOT/PLT relocation slot (`Elf64_Rela`).
#[derive(Debug, Clone)]
pub struct GotRelocEntry {
    pub r_offset: u64,
    pub reloc_type: u32,
    pub symbol_name: String,
}

/// Complete binary metadata extracted from an x86_64 ELF64 file.
#[derive(Debug, Clone)]
pub struct Elf64Info {
    pub e_type: u16,
    pub e_machine: u16,
    pub e_entry: u64,
    pub phdrs: Vec<Elf64Phdr>,
    pub sections: Vec<Elf64Section>,
    pub dt_needed: Vec<String>,
    pub dt_rpath: Option<String>,
    pub dt_runpath: Option<String>,
    pub dt_soname: Option<String>,
    pub has_textrel: bool,
    pub got_relocs: Vec<GotRelocEntry>,
}

/// Parses an ELF64 binary directly from byte offsets without external crates.
pub fn parse_elf64_bytes(data: &[u8]) -> Result<Elf64Info, String> {
    if data.len() < 64 {
        return Err("file smaller than 64-byte Elf64_Ehdr".to_string());
    }
    if data[0..4] != ELF_MAGIC {
        return Err("invalid ELF magic".to_string());
    }
    if data[4] != ELFCLASS64 {
        return Err(format!("unsupported ELF class {} (expected ELFCLASS64=2)", data[4]));
    }
    if data[5] != ELFDATA2LSB {
        return Err("unsupported endianness (expected ELFDATA2LSB=1)".to_string());
    }

    let e_type = read_u16_le(data, 16)?;
    let e_machine = read_u16_le(data, 18)?;
    let e_entry = read_u64_le(data, 24)?;
    let e_phoff = read_u64_le(data, 32)? as usize;
    let e_shoff = read_u64_le(data, 40)? as usize;
    let e_phentsize = read_u16_le(data, 54)? as usize;
    let e_phnum = read_u16_le(data, 56)? as usize;
    let e_shentsize = read_u16_le(data, 58)? as usize;
    let e_shnum = read_u16_le(data, 60)? as usize;
    let e_shstrndx = read_u16_le(data, 62)? as usize;

    let mut phdrs = Vec::new();
    if e_phoff > 0 && e_phnum > 0 && e_phentsize >= 56 {
        for i in 0..e_phnum {
            let off = e_phoff.saturating_add(i.saturating_mul(e_phentsize));
            if off.saturating_add(56) > data.len() {
                break;
            }
            phdrs.push(Elf64Phdr {
                p_type: read_u32_le(data, off)?,
                p_flags: read_u32_le(data, off + 4)?,
                p_offset: read_u64_le(data, off + 8)?,
                p_vaddr: read_u64_le(data, off + 16)?,
                p_filesz: read_u64_le(data, off + 32)?,
                p_memsz: read_u64_le(data, off + 40)?,
                p_align: read_u64_le(data, off + 48)?,
            });
        }
    }

    // Locate `.shstrtab` first to resolve section names
    let shstrtab_range: Option<(usize, usize)> =
        if e_shoff > 0 && e_shstrndx < e_shnum && e_shentsize >= 64 {
            let shstr_hdr = e_shoff.saturating_add(e_shstrndx.saturating_mul(e_shentsize));
            if shstr_hdr.saturating_add(64) <= data.len() {
                let off = read_u64_le(data, shstr_hdr + 24)? as usize;
                let sz = read_u64_le(data, shstr_hdr + 32)? as usize;
                if off.saturating_add(sz) <= data.len() {
                    Some((off, sz))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

    let mut sections = Vec::new();
    if e_shoff > 0 && e_shnum > 0 && e_shentsize >= 64 {
        for i in 0..e_shnum {
            let off = e_shoff.saturating_add(i.saturating_mul(e_shentsize));
            if off.saturating_add(64) > data.len() {
                break;
            }
            let sh_name_idx = read_u32_le(data, off)? as usize;
            let sh_type = read_u32_le(data, off + 4)?;
            let sh_flags = read_u64_le(data, off + 8)?;
            let sh_addr = read_u64_le(data, off + 16)?;
            let sh_offset = read_u64_le(data, off + 24)?;
            let sh_size = read_u64_le(data, off + 32)?;
            let sh_link = read_u32_le(data, off + 40)?;
            let sh_entsize = read_u64_le(data, off + 56)?;

            let name = if let Some((str_off, str_sz)) = shstrtab_range {
                read_cstr_from_table(&data[str_off..str_off + str_sz], sh_name_idx)
            } else {
                String::new()
            };

            sections.push(Elf64Section {
                name,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                sh_link,
                sh_entsize,
            });
        }
    }

    // Parse `.dynamic` + `.dynstr` for DT_NEEDED / DT_RPATH / DT_RUNPATH / DT_TEXTREL
    let mut dt_needed = Vec::new();
    let mut dt_rpath = None;
    let mut dt_runpath = None;
    let mut dt_soname = None;
    let mut has_textrel = false;

    let dynstr_slice: Option<&[u8]> = sections
        .iter()
        .find(|s| s.name == ".dynstr")
        .and_then(|s| slice_section(data, s));

    if let Some(dyn_sec) = sections.iter().find(|s| s.sh_type == SHT_DYNAMIC || s.name == ".dynamic")
    {
        if let Some(dyn_bytes) = slice_section(data, dyn_sec) {
            let strtab = sections
                .get(dyn_sec.sh_link as usize)
                .and_then(|s| slice_section(data, s))
                .or(dynstr_slice);

            let mut pos = 0usize;
            while pos + 16 <= dyn_bytes.len() {
                let d_tag = i64::from_le_bytes(dyn_bytes[pos..pos + 8].try_into().unwrap());
                let d_val = u64::from_le_bytes(dyn_bytes[pos + 8..pos + 16].try_into().unwrap());
                pos += 16;

                if d_tag == DT_NULL {
                    break;
                }
                match d_tag {
                    DT_NEEDED => {
                        if let Some(st) = strtab {
                            let s = read_cstr_from_table(st, d_val as usize);
                            if !s.is_empty() {
                                dt_needed.push(s);
                            }
                        }
                    }
                    DT_RPATH => {
                        if let Some(st) = strtab {
                            let s = read_cstr_from_table(st, d_val as usize);
                            if !s.is_empty() {
                                dt_rpath = Some(s);
                            }
                        }
                    }
                    DT_RUNPATH => {
                        if let Some(st) = strtab {
                            let s = read_cstr_from_table(st, d_val as usize);
                            if !s.is_empty() {
                                dt_runpath = Some(s);
                            }
                        }
                    }
                    DT_SONAME => {
                        if let Some(st) = strtab {
                            let s = read_cstr_from_table(st, d_val as usize);
                            if !s.is_empty() {
                                dt_soname = Some(s);
                            }
                        }
                    }
                    DT_TEXTREL => has_textrel = true,
                    DT_FLAGS if (d_val & DF_TEXTREL) != 0 => has_textrel = true,
                    _ => {}
                }
            }
        }
    }

    // Parse `.dynsym` + `.rela.plt` / `.rela.dyn` for GOT/PLT pointer verification
    let mut got_relocs = Vec::new();
    let dynsym_sec = sections
        .iter()
        .find(|s| s.sh_type == SHT_DYNSYM || s.name == ".dynsym");

    if let (Some(sym_sec), Some(strtab)) = (dynsym_sec, dynstr_slice) {
        if let Some(sym_bytes) = slice_section(data, sym_sec) {
            for rela_sec in sections
                .iter()
                .filter(|s| s.sh_type == SHT_RELA && (s.name == ".rela.plt" || s.name == ".rela.dyn"))
            {
                let Some(rela_bytes) = slice_section(data, rela_sec) else {
                    continue;
                };
                let ent_sz = if rela_sec.sh_entsize >= 24 {
                    rela_sec.sh_entsize as usize
                } else {
                    24
                };
                let mut pos = 0usize;
                while pos + 24 <= rela_bytes.len() {
                    let r_offset =
                        u64::from_le_bytes(rela_bytes[pos..pos + 8].try_into().unwrap());
                    let r_info =
                        u64::from_le_bytes(rela_bytes[pos + 8..pos + 16].try_into().unwrap());
                    let reloc_type = (r_info & 0xffff_ffff) as u32;
                    let sym_idx = (r_info >> 32) as usize;
                    pos += ent_sz;

                    if reloc_type != R_X86_64_JUMP_SLOT && reloc_type != R_X86_64_GLOB_DATA {
                        continue;
                    }

                    let sym_off = sym_idx.saturating_mul(24);
                    let symbol_name = if sym_off + 24 <= sym_bytes.len() {
                        let st_name =
                            u32::from_le_bytes(sym_bytes[sym_off..sym_off + 4].try_into().unwrap())
                                as usize;
                        read_cstr_from_table(strtab, st_name)
                    } else {
                        String::new()
                    };

                    if !symbol_name.is_empty() {
                        got_relocs.push(GotRelocEntry {
                            r_offset,
                            reloc_type,
                            symbol_name,
                        });
                    }
                }
            }
        }
    }

    Ok(Elf64Info {
        e_type,
        e_machine,
        e_entry,
        phdrs,
        sections,
        dt_needed,
        dt_rpath,
        dt_runpath,
        dt_soname,
        has_textrel,
        got_relocs,
    })
}

fn slice_section<'a>(data: &'a [u8], sec: &Elf64Section) -> Option<&'a [u8]> {
    let off = sec.sh_offset as usize;
    let sz = sec.sh_size as usize;
    let end = off.checked_add(sz)?;
    if end <= data.len() {
        Some(&data[off..end])
    } else {
        None
    }
}

fn read_cstr_from_table(table: &[u8], offset: usize) -> String {
    if offset >= table.len() {
        return String::new();
    }
    let slice = &table[offset..];
    let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..len]).into_owned()
}

/// Parsed line from `/proc/<pid>/maps`.
#[derive(Debug, Clone)]
pub struct ProcMapEntry {
    pub start_addr: u64,
    pub end_addr: u64,
    pub perms: String,
    pub file_offset: u64,
    pub dev: String,
    pub inode: u64,
    pub raw_pathname: String,
    pub clean_pathname: String,
    pub is_deleted: bool,
}

impl ProcMapEntry {
    #[inline]
    pub fn len(&self) -> u64 {
        self.end_addr.saturating_sub(self.start_addr)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn is_exec(&self) -> bool {
        self.perms.as_bytes().get(2) == Some(&b'x')
    }

    #[inline]
    pub fn is_write(&self) -> bool {
        self.perms.as_bytes().get(1) == Some(&b'w')
    }
}

/// Parses the full contents of `/proc/<pid>/maps`.
pub fn parse_proc_maps(maps_text: &str) -> Vec<ProcMapEntry> {
    let mut entries = Vec::new();
    for line in maps_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.splitn(6, char::is_whitespace);
        let Some(range_str) = parts.next() else { continue };
        let rest_parts: Vec<&str> = trimmed[range_str.len()..]
            .trim_start()
            .splitn(5, char::is_whitespace)
            .collect();
        if rest_parts.len() < 4 {
            continue;
        }

        let Some((start_hex, end_hex)) = range_str.split_once('-') else {
            continue;
        };
        let (Ok(start_addr), Ok(end_addr)) = (
            u64::from_str_radix(start_hex, 16),
            u64::from_str_radix(end_hex, 16),
        ) else {
            continue;
        };
        let perms = rest_parts[0].to_string();
        let Ok(file_offset) = u64::from_str_radix(rest_parts[1], 16) else {
            continue;
        };
        let dev = rest_parts[2].to_string();
        let inode = rest_parts[3].parse::<u64>().unwrap_or(0);
        let raw_pathname = if rest_parts.len() == 5 {
            rest_parts[4].trim().to_string()
        } else {
            String::new()
        };

        let (clean_pathname, is_deleted) =
            if let Some(stripped) = raw_pathname.strip_suffix(" (deleted)") {
                (stripped.to_string(), true)
            } else {
                (raw_pathname.clone(), false)
            };

        entries.push(ProcMapEntry {
            start_addr,
            end_addr,
            perms,
            file_offset,
            dev,
            inode,
            raw_pathname,
            clean_pathname,
            is_deleted,
        });
    }
    entries
}

/// Contiguous modified code range inside `.text` or `.plt`.
#[derive(Debug, Clone)]
pub struct BytePatchHunk {
    pub live_vaddr: u64,
    pub elf_file_offset: u64,
    pub disk_bytes: Vec<u8>,
    pub mem_bytes: Vec<u8>,
    pub hook_classification: &'static str,
}

/// Output of Engine 2 (`elf_vma_diff`).
pub struct ElfVmaDiffResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 2 against `/proc` and on-disk ELF64 targets under `root`.
pub fn run_elf_vma_diff_audit(root: &Path) -> ElfVmaDiffResult {
    let mut findings = Vec::new();
    let proc_dir = join_rooted(root, "proc");
    let self_pid = if root == Path::new("/") {
        std::process::id()
    } else {
        0
    };

    let mut matched_processes = Vec::new();
    let mut total_vmas_inspected = 0u64;
    let mut total_elf_sections_diffed = 0u64;
    let mut total_got_slots_checked = 0u64;

    // Cache parsed on-disk ELF64 binaries to avoid re-reading `libpython`/`libcrypto` across workers
    let mut elf_cache: BTreeMap<PathBuf, Option<(Vec<u8>, Elf64Info, u64)>> = BTreeMap::new();

    let mut pids: Vec<u32> = Vec::new();
    if let Ok(entries) = fs::read_dir(&proc_dir) {
        for entry in entries.flatten() {
            if let Some(s) = entry.file_name().to_str() {
                if let Ok(pid) = s.parse::<u32>() {
                    if pid != self_pid {
                        pids.push(pid);
                    }
                }
            }
        }
    }
    pids.sort_unstable();

    for pid in pids {
        let pid_dir = proc_dir.join(pid.to_string());
        let comm = read_proc_bytes(&pid_dir.join("comm"))
            .map(|b| String::from_utf8_lossy(&b).trim().to_string())
            .unwrap_or_default();
        let cmdline_raw = read_proc_bytes(&pid_dir.join("cmdline")).unwrap_or_default();
        let cmdline = cmdline_raw
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<Vec<_>>()
            .join(" ");

        let Some(role) = classify_target_process(&comm, &cmdline) else {
            continue;
        };

        let Some(maps_bytes) = read_proc_bytes(&pid_dir.join("maps")) else {
            continue;
        };
        let maps_text = String::from_utf8_lossy(&maps_bytes);
        let vmas = parse_proc_maps(&maps_text);
        total_vmas_inspected += vmas.len() as u64;

        matched_processes.push(JsonValue::OrderedObject(vec![
            ("pid".to_string(), JsonValue::Uint(pid as u64)),
            ("role".to_string(), JsonValue::str(role)),
            ("comm".to_string(), JsonValue::str(&comm)),
            ("vma_count".to_string(), JsonValue::Uint(vmas.len() as u64)),
        ]));

        // Step A: Detect deleted, /tmp, /dev/shm, /var/tmp, memfd, or anonymous executable mappings
        inspect_suspicious_vmas(pid, role, &comm, &vmas, &mut findings);

        // Step A2: Detect in-memory `sys.modules` Cython `.so` Ghosting (`cyops-auth` / `csdassrv.py` import bypass)
        inspect_cython_so_sys_modules_ghosting(root, pid, &comm, &cmdline, &vmas, &mut findings);

        // Step B: Compare on-disk ELF64 `.text` / `.plt` vs `/proc/<pid>/mem` & audit GOT/PLT slots
        let mem_path = pid_dir.join("mem");
        if !mem_path.exists() {
            continue;
        }

        let mut got_checked_files = std::collections::BTreeSet::new();

        for vma in &vmas {
            if !vma.is_exec() || vma.is_deleted || vma.clean_pathname.is_empty() {
                continue;
            }
            if vma.clean_pathname.starts_with('[') {
                continue;
            }
            if !is_target_elf_path(&vma.clean_pathname) {
                continue;
            }

            let disk_path = join_rooted(root, &vma.clean_pathname);
            let cached = elf_cache.entry(disk_path.clone()).or_insert_with(|| {
                let bytes = read_proc_bytes(&disk_path)?;
                let info = parse_elf64_bytes(&bytes).ok()?;
                if info.e_machine != EM_X86_64 {
                    return None;
                }
                let ino = file_inode(&disk_path).unwrap_or(0);
                Some((bytes, info, ino))
            });

            let Some((disk_bytes, elf_info, disk_ino)) = cached.as_ref() else {
                continue;
            };

            // Verify inode consistency when running against live filesystem with non-zero VMA inode
            if root == Path::new("/") && vma.inode != 0 && *disk_ino != 0 && vma.inode != *disk_ino {
                findings.push(
                    Finding::new(
                        EngineId::ElfVmaDiff,
                        "HIGH_ELF_INODE_MISMATCH_ON_DISK",
                        Severity::High,
                        format!("pid:{} ({}) -> {}", pid, comm, vma.clean_pathname),
                        format!(
                            "Process {} ({}) executes inode {} of {}, but on-disk file was replaced by inode {}",
                            pid, comm, vma.inode, vma.clean_pathname, disk_ino
                        ),
                    )
                    .with_evidence("pid", JsonValue::Uint(pid as u64))
                    .with_evidence("mapped_inode", JsonValue::Uint(vma.inode))
                    .with_evidence("disk_inode", JsonValue::Uint(*disk_ino)),
                );
                continue;
            }

            if elf_info.has_textrel {
                continue;
            }

            // Diff executable code sections (`.text`, `.plt`, `.plt.sec`) covered by this `r-xp` VMA
            let vma_file_start = vma.file_offset;
            let vma_file_end = vma.file_offset.saturating_add(vma.len());

            for sec in &elf_info.sections {
                if !matches!(sec.name.as_str(), ".text" | ".plt" | ".plt.sec") || sec.sh_size == 0 {
                    continue;
                }
                let sec_start = sec.sh_offset;
                let sec_end = sec.sh_offset.saturating_add(sec.sh_size);

                let cmp_start = sec_start.max(vma_file_start);
                let cmp_end = sec_end.min(vma_file_end);
                if cmp_start >= cmp_end {
                    continue;
                }
                let cmp_len = (cmp_end - cmp_start) as usize;
                if (cmp_end as usize) > disk_bytes.len() {
                    continue;
                }

                let live_vaddr = vma.start_addr.saturating_add(cmp_start - vma_file_start);
                let Ok(mem_slice) = raw_or_portable_pread(&mem_path, live_vaddr, cmp_len) else {
                    continue;
                };
                if mem_slice.len() != cmp_len {
                    continue;
                }

                total_elf_sections_diffed += 1;
                let disk_slice = &disk_bytes[cmp_start as usize..cmp_end as usize];

                if disk_slice != mem_slice.as_slice() {
                    let hunks = extract_patch_hunks(disk_slice, &mem_slice, live_vaddr, cmp_start);
                    for hunk in hunks {
                        let severity = if hunk.hook_classification == "X86_64_INT3_TRAP_OR_UPROBE" {
                            Severity::High
                        } else {
                            Severity::Critical
                        };
                        findings.push(
                            Finding::new(
                                EngineId::ElfVmaDiff,
                                "CRITICAL_ELF_TEXT_INLINE_PATCH",
                                severity,
                                format!(
                                    "pid:{} ({}) {}+0x{:x}",
                                    pid, comm, vma.clean_pathname, hunk.elf_file_offset
                                ),
                                format!(
                                    "In-memory {} code modification in {} ({}, pid {}) section {} at VMA 0x{:016x} ({} bytes altered)",
                                    hunk.hook_classification,
                                    vma.clean_pathname,
                                    comm,
                                    pid,
                                    sec.name,
                                    hunk.live_vaddr,
                                    hunk.mem_bytes.len()
                                ),
                            )
                            .with_evidence("pid", JsonValue::Uint(pid as u64))
                            .with_evidence("process_comm", JsonValue::str(&comm))
                            .with_evidence("process_role", JsonValue::str(role))
                            .with_evidence("elf_path", JsonValue::str(&vma.clean_pathname))
                            .with_evidence("section", JsonValue::str(&sec.name))
                            .with_evidence(
                                "vma_address",
                                JsonValue::str(format!("0x{:016x}", hunk.live_vaddr)),
                            )
                            .with_evidence(
                                "elf_file_offset",
                                JsonValue::str(format!("0x{:08x}", hunk.elf_file_offset)),
                            )
                            .with_evidence(
                                "patch_byte_len",
                                JsonValue::Uint(hunk.mem_bytes.len() as u64),
                            )
                            .with_evidence(
                                "disk_bytes_hex",
                                JsonValue::str(hex_encode(&hunk.disk_bytes)),
                            )
                            .with_evidence(
                                "mem_bytes_hex",
                                JsonValue::str(hex_encode(&hunk.mem_bytes)),
                            )
                            .with_evidence(
                                "hook_classification",
                                JsonValue::str(hunk.hook_classification),
                            ),
                        );
                    }
                }
            }

            // Audit GOT/PLT resolved function pointers once per mapped ELF binary in this PID
            if !elf_info.got_relocs.is_empty()
                && got_checked_files.insert(vma.clean_pathname.clone())
            {
                if let Some(load_bias) = compute_elf_load_bias(elf_info, vma) {
                    total_got_slots_checked += audit_got_plt_pointers(
                        pid,
                        &comm,
                        &vma.clean_pathname,
                        elf_info,
                        load_bias,
                        &mem_path,
                        &vmas,
                        &mut findings,
                    );
                }
            }
        }
    }

    let summary = JsonValue::OrderedObject(vec![
        (
            "target_daemons".to_string(),
            JsonValue::Array(vec![
                JsonValue::str("uwsgi"),
                JsonValue::str("python3"),
                JsonValue::str("celery"),
                JsonValue::str("nginx"),
            ]),
        ),
        (
            "matched_processes_count".to_string(),
            JsonValue::Uint(matched_processes.len() as u64),
        ),
        (
            "matched_processes".to_string(),
            JsonValue::Array(matched_processes),
        ),
        (
            "total_vmas_inspected".to_string(),
            JsonValue::Uint(total_vmas_inspected),
        ),
        (
            "elf_code_sections_diffed".to_string(),
            JsonValue::Uint(total_elf_sections_diffed),
        ),
        (
            "got_plt_slots_audited".to_string(),
            JsonValue::Uint(total_got_slots_checked),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    ElfVmaDiffResult { summary, findings }
}

fn classify_target_process(comm: &str, cmdline: &str) -> Option<&'static str> {
    let comm_l = comm.to_ascii_lowercase();
    let cmd_l = cmdline.to_ascii_lowercase();

    if comm_l.contains("uwsgi") || cmd_l.contains("uwsgi") {
        Some("uwsgi")
    } else if comm_l.contains("celery") || cmd_l.contains("celery") {
        Some("celery")
    } else if comm_l.contains("nginx") || cmd_l.contains("nginx") {
        Some("nginx")
    } else if comm_l.starts_with("python")
        || comm_l == "platform-python"
        || cmd_l.contains("python3")
        || cmd_l.contains("/opt/cyops")
    {
        Some("python3")
    } else {
        None
    }
}

fn is_target_elf_path(clean_path: &str) -> bool {
    clean_path.starts_with("/opt/cyops")
        || clean_path.starts_with("/usr/lib64/libpython")
        || clean_path.starts_with("/lib64/libpython")
        || clean_path.starts_with("/usr/lib64/libcrypto")
        || clean_path.starts_with("/lib64/libcrypto")
        || clean_path.starts_with("/usr/lib64/libssl")
        || clean_path.starts_with("/usr/lib64/libc.")
        || clean_path.starts_with("/usr/lib64/libc-")
        || clean_path.starts_with("/lib64/libc.")
        || clean_path.starts_with("/lib64/libc-")
        || clean_path.starts_with("/usr/sbin/nginx")
        || clean_path.starts_with("/usr/bin/python")
        || clean_path.contains("uwsgi")
}

fn inspect_cython_so_sys_modules_ghosting(
    root: &Path,
    pid: u32,
    comm: &str,
    cmdline: &str,
    vmas: &[ProcMapEntry],
    findings: &mut Vec<Finding>,
) {
    let is_das_proc = cmdline.contains("csdassrv.py")
        || cmdline.contains("cyops-auth")
        || vmas
            .iter()
            .any(|v| v.clean_pathname.contains("/cyops-auth/handlers/"));
    if !is_das_proc {
        return;
    }

    let has_loaded_das_handlers = vmas.iter().any(|v| {
        v.clean_pathname.ends_with("/handlers/authenticationhandler.so")
            || v.clean_pathname.ends_with("/handlers/licensehandler.so")
            || v.clean_pathname.ends_with("/handlers/tokenhandler.so")
    });
    if !has_loaded_das_handlers {
        return;
    }

    for expected_so in [
        "opt/cyops-auth/handlerworkers/license.so",
        "opt/cyops-auth/handlerworkers/fdnclient.so",
    ] {
        let on_disk = join_rooted(root, expected_so).is_file();
        let suffix = format!("/{}", expected_so);
        let mapped_in_vma = vmas.iter().any(|v| v.clean_pathname.ends_with(&suffix));
        if on_disk && !mapped_in_vma {
            findings.push(
                Finding::new(
                    EngineId::ElfVmaDiff,
                    "CRITICAL_LIVE_CYTHON_SO_SYS_MODULES_GHOSTING",
                    Severity::Critical,
                    format!("pid:{} ({}) -> /{}", pid, comm, expected_so),
                    format!(
                        "Running FortiSOAR DAS process {} (pid {}) mapped `cyops-auth/handlers/*.so` but NEVER dlopen'd `/{}` into `/proc/{}/maps` — proves in-memory `sys.modules` shadowing via Python startup or `csdassrv.py` import hook",
                        comm, pid, expected_so, pid
                    ),
                )
                .with_evidence("pid", JsonValue::Uint(pid as u64))
                .with_evidence("cmdline", JsonValue::str(cmdline))
                .with_evidence("ghosted_cython_so", JsonValue::str(format!("/{}", expected_so))),
            );
        }
    }
}

fn inspect_suspicious_vmas(
    pid: u32,
    role: &str,
    comm: &str,
    vmas: &[ProcMapEntry],
    findings: &mut Vec<Finding>,
) {
    let mut reported_paths = std::collections::BTreeSet::new();

    for vma in vmas {
        let path = &vma.clean_pathname;
        let is_so_like = path.contains(".so") || vma.is_exec();

        // 1. Ephemeral / world-writable shared library injection (/tmp, /dev/shm, /var/tmp, memfd)
        let is_ephemeral = path.starts_with("/tmp/")
            || path.starts_with("/dev/shm/")
            || path.starts_with("/var/tmp/")
            || path.starts_with("/run/user/")
            || path.starts_with("/memfd:")
            || path.starts_with("memfd:");

        if is_so_like && is_ephemeral && reported_paths.insert(format!("ephem:{}", vma.raw_pathname))
        {
            findings.push(
                Finding::new(
                    EngineId::ElfVmaDiff,
                    "CRITICAL_EPHEMERAL_SHARED_OBJECT_INJECTION",
                    Severity::Critical,
                    format!("pid:{} ({}) -> {}", pid, comm, vma.raw_pathname),
                    format!(
                        "Unsigned/ephemeral shared object or executable VMA mapped into {} (pid {}) from {}",
                        comm, pid, vma.raw_pathname
                    ),
                )
                .with_evidence("pid", JsonValue::Uint(pid as u64))
                .with_evidence("process_role", JsonValue::str(role))
                .with_evidence("process_comm", JsonValue::str(comm))
                .with_evidence("vma_range", JsonValue::str(format!("0x{:016x}-0x{:016x}", vma.start_addr, vma.end_addr)))
                .with_evidence("permissions", JsonValue::str(&vma.perms))
                .with_evidence("backing_path", JsonValue::str(&vma.raw_pathname)),
            );
        }

        // 2. Deleted shared library or deleted executable VMA (`r-xp ... (deleted)`)
        // Exclude benign non-executable `/dev/zero (deleted)` shared memory slabs used by nginx/uwsgi.
        let benign_shm = !vma.is_exec()
            && (path == "/dev/zero" || path.starts_with("/SYSV") || path.starts_with("/dev/shm/PostgreSQL"));
        if vma.is_deleted
            && is_so_like
            && !benign_shm
            && reported_paths.insert(format!("del:{}", vma.raw_pathname))
        {
            findings.push(
                Finding::new(
                    EngineId::ElfVmaDiff,
                    "CRITICAL_DELETED_EXECUTABLE_MAPPING",
                    Severity::Critical,
                    format!("pid:{} ({}) -> {}", pid, comm, vma.raw_pathname),
                    format!(
                        "Unlinked/deleted executable or .so mapping active in {} (pid {}): {}",
                        comm, pid, vma.raw_pathname
                    ),
                )
                .with_evidence("pid", JsonValue::Uint(pid as u64))
                .with_evidence("process_role", JsonValue::str(role))
                .with_evidence("process_comm", JsonValue::str(comm))
                .with_evidence("vma_range", JsonValue::str(format!("0x{:016x}-0x{:016x}", vma.start_addr, vma.end_addr)))
                .with_evidence("permissions", JsonValue::str(&vma.perms))
                .with_evidence("backing_path", JsonValue::str(&vma.raw_pathname)),
            );
        }

        // 3. Anonymous RWX memory region (shellcode / inline hook trampoline allocation)
        if path.is_empty() && vma.is_exec() && vma.is_write() {
            findings.push(
                Finding::new(
                    EngineId::ElfVmaDiff,
                    "HIGH_ANONYMOUS_RWX_MEMORY_REGION",
                    Severity::High,
                    format!("pid:{} ({}) @ 0x{:016x}", pid, comm, vma.start_addr),
                    format!(
                        "Anonymous RWX executable memory page allocated in {} (pid {}) at 0x{:016x}-0x{:016x}",
                        comm, pid, vma.start_addr, vma.end_addr
                    ),
                )
                .with_evidence("pid", JsonValue::Uint(pid as u64))
                .with_evidence("process_role", JsonValue::str(role))
                .with_evidence("vma_size_bytes", JsonValue::Uint(vma.len()))
                .with_evidence("permissions", JsonValue::str(&vma.perms)),
            );
        }
    }
}

fn extract_patch_hunks(
    disk: &[u8],
    mem: &[u8],
    base_vaddr: u64,
    base_file_offset: u64,
) -> Vec<BytePatchHunk> {
    let mut hunks = Vec::new();
    let len = disk.len().min(mem.len());
    let mut i = 0usize;

    while i < len {
        if disk[i] == mem[i] {
            i += 1;
            continue;
        }
        let start = i;
        let mut last_diff = i;
        i += 1;
        while i < len {
            if disk[i] != mem[i] {
                last_diff = i;
                i += 1;
            } else if i - last_diff <= 4 && (i - start) < 64 {
                // Coalesce up to 4 identical intermediate bytes within a single instruction sequence
                i += 1;
            } else {
                break;
            }
        }
        let end = (last_diff + 1).min(len);
        let max_dump = (end - start).min(64);
        let d_slice = disk[start..start + max_dump].to_vec();
        let m_slice = mem[start..start + max_dump].to_vec();
        let hook_classification = classify_x86_64_patch(&m_slice);

        hunks.push(BytePatchHunk {
            live_vaddr: base_vaddr.saturating_add(start as u64),
            elf_file_offset: base_file_offset.saturating_add(start as u64),
            disk_bytes: d_slice,
            mem_bytes: m_slice,
            hook_classification,
        });
    }

    hunks
}

fn classify_x86_64_patch(mem_bytes: &[u8]) -> &'static str {
    if mem_bytes == [0xcc] {
        return "X86_64_INT3_TRAP_OR_UPROBE";
    }
    if mem_bytes.first() == Some(&0xe9) && mem_bytes.len() >= 5 {
        return "X86_64_JMP_REL32_INLINE_HOOK";
    }
    if mem_bytes.len() >= 6 && mem_bytes[0] == 0xff && mem_bytes[1] == 0x25 {
        return "X86_64_JMP_RIP_INDIRECT_HOOK";
    }
    if mem_bytes.len() >= 12
        && mem_bytes[0] == 0x48
        && mem_bytes[1] == 0xb8
        && mem_bytes[10] == 0xff
        && (mem_bytes[11] == 0xe0 || mem_bytes[11] == 0xd0)
    {
        return "X86_64_MOV_RAX_JMP_TRAMPOLINE";
    }
    if (mem_bytes.len() >= 6 && mem_bytes[0..6] == [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3])
        || (mem_bytes.len() >= 4 && mem_bytes[0..4] == [0x6a, 0x01, 0x58, 0xc3])
        || (mem_bytes.len() >= 8
            && mem_bytes[0..8] == [0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0xc3])
    {
        return "X86_64_FORCE_RETURN_ONE_LICENSE_BYPASS";
    }
    if mem_bytes.len() >= 3 && mem_bytes[0..3] == [0x31, 0xc0, 0xc3] {
        return "X86_64_FORCE_RETURN_ZERO_PATCH";
    }
    if mem_bytes.len() >= 2 && mem_bytes.iter().all(|&b| b == 0x90) {
        return "X86_64_NOP_BRANCH_NEUTRALIZATION";
    }
    "X86_64_INLINE_CODE_PATCH"
}

fn compute_elf_load_bias(elf: &Elf64Info, vma: &ProcMapEntry) -> Option<u64> {
    for ph in &elf.phdrs {
        if ph.p_type != PT_LOAD || ph.p_filesz == 0 {
            continue;
        }
        let page_aligned_off = ph.p_offset & !0xfff;
        let page_aligned_vaddr = ph.p_vaddr & !0xfff;
        if vma.file_offset >= page_aligned_off
            && vma.file_offset < ph.p_offset.saturating_add(ph.p_filesz)
        {
            let delta = vma.file_offset - page_aligned_off;
            let expected_vaddr = page_aligned_vaddr.saturating_add(delta);
            return Some(vma.start_addr.wrapping_sub(expected_vaddr));
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn audit_got_plt_pointers(
    pid: u32,
    comm: &str,
    elf_path: &str,
    elf: &Elf64Info,
    load_bias: u64,
    mem_path: &Path,
    vmas: &[ProcMapEntry],
    findings: &mut Vec<Finding>,
) -> u64 {
    let mut checked = 0u64;
    for reloc in &elf.got_relocs {
        let got_vaddr = load_bias.wrapping_add(reloc.r_offset);
        let Ok(ptr_bytes) = raw_or_portable_pread(mem_path, got_vaddr, 8) else {
            continue;
        };
        if ptr_bytes.len() != 8 {
            continue;
        }
        checked += 1;
        let target_ptr = u64::from_le_bytes(ptr_bytes[..8].try_into().unwrap());
        if target_ptr == 0 {
            continue;
        }

        let target_vma = vmas
            .iter()
            .find(|m| target_ptr >= m.start_addr && target_ptr < m.end_addr);

        match target_vma {
            None => {
                findings.push(
                    Finding::new(
                        EngineId::ElfVmaDiff,
                        "CRITICAL_GOT_PLT_POINTER_HIJACK",
                        Severity::Critical,
                        format!("pid:{} ({}) {}!{}", pid, comm, elf_path, reloc.symbol_name),
                        format!(
                            "GOT/PLT entry for `{}` in {} (pid {}) points to unmapped address 0x{:016x}",
                            reloc.symbol_name, elf_path, pid, target_ptr
                        ),
                    )
                    .with_evidence("pid", JsonValue::Uint(pid as u64))
                    .with_evidence("symbol", JsonValue::str(&reloc.symbol_name))
                    .with_evidence("got_slot_vaddr", JsonValue::str(format!("0x{:016x}", got_vaddr)))
                    .with_evidence("target_vaddr", JsonValue::str(format!("0x{:016x}", target_ptr))),
                );
            }
            Some(m) => {
                let bad_target = !m.is_exec()
                    || m.is_deleted
                    || (m.clean_pathname.is_empty() && m.raw_pathname != "[vdso]" && m.raw_pathname != "[vsyscall]")
                    || m.clean_pathname.starts_with("/tmp/")
                    || m.clean_pathname.starts_with("/dev/shm/")
                    || m.clean_pathname.starts_with("/var/tmp/")
                    || m.clean_pathname.contains("memfd:");

                if bad_target {
                    let target_desc = if m.raw_pathname.is_empty() {
                        "<anonymous-vma>"
                    } else {
                        &m.raw_pathname
                    };
                    findings.push(
                        Finding::new(
                            EngineId::ElfVmaDiff,
                            "CRITICAL_GOT_PLT_POINTER_HIJACK",
                            Severity::Critical,
                            format!("pid:{} ({}) {}!{}", pid, comm, elf_path, reloc.symbol_name),
                            format!(
                                "GOT/PLT hijack on symbol `{}` in {} (pid {}): slot 0x{:016x} -> 0x{:016x} ({})",
                                reloc.symbol_name, elf_path, pid, got_vaddr, target_ptr, target_desc
                            ),
                        )
                        .with_evidence("pid", JsonValue::Uint(pid as u64))
                        .with_evidence("symbol", JsonValue::str(&reloc.symbol_name))
                        .with_evidence("elf_path", JsonValue::str(elf_path))
                        .with_evidence("got_slot_vaddr", JsonValue::str(format!("0x{:016x}", got_vaddr)))
                        .with_evidence("target_vaddr", JsonValue::str(format!("0x{:016x}", target_ptr)))
                        .with_evidence("target_vma_path", JsonValue::str(target_desc))
                        .with_evidence("target_vma_perms", JsonValue::str(&m.perms)),
                    );
                }
            }
        }
    }
    checked
}

fn read_proc_bytes(path: &Path) -> Option<Vec<u8>> {
    match raw_syscall_read_file(path) {
        Ok(b) => Some(b),
        Err(_) => fs::read(path).ok(),
    }
}

fn file_inode(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).ok().map(|m| m.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[inline]
fn read_u16_le(data: &[u8], off: usize) -> Result<u16, String> {
    let s = data
        .get(off..off + 2)
        .ok_or_else(|| "EOF reading u16".to_string())?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
fn read_u32_le(data: &[u8], off: usize) -> Result<u32, String> {
    let s = data
        .get(off..off + 4)
        .ok_or_else(|| "EOF reading u32".to_string())?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
fn read_u64_le(data: &[u8], off: usize) -> Result<u64, String> {
    let s = data
        .get(off..off + 8)
        .ok_or_else(|| "EOF reading u64".to_string())?;
    Ok(u64::from_le_bytes(s.try_into().unwrap()))
}
