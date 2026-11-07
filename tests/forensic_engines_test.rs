use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use fsr_deep_audit::crypto::{hex_encode, sha256_hex};
use fsr_deep_audit::elf_vma_diff::run_elf_vma_diff_audit;
use fsr_deep_audit::hw_integrity::{
    run_hw_integrity_with_provider, HwReadProvider, LibcReadOutcome, RawReadOutcome,
};
use fsr_deep_audit::pyc_inspector::run_pyc_inspector_audit;
use fsr_deep_audit::rpm_forensics::{
    run_rpm_forensics_audit, RPMTAG_ARCH, RPMTAG_BASENAMES, RPMTAG_DIRINDEXES, RPMTAG_DIRNAMES,
    RPMTAG_FILEDIGESTALGO, RPMTAG_FILEDIGESTS, RPMTAG_FILEFLAGS, RPMTAG_NAME, RPMTAG_RELEASE,
    RPMTAG_RSAHEADER, RPMTAG_SIGPGP, RPMTAG_VENDOR, RPMTAG_VERSION,
};
use fsr_deep_audit::{execute_full_audit, EngineSelection};

// ============================================================================
// Engine 1 Test: Raw Syscall vs Libc UUID/MAC Spoof & Preload Hook Detection
// ============================================================================

struct SimulatedHookedAppliance {
    libc_files: BTreeMap<String, LibcReadOutcome>,
    raw_files: BTreeMap<String, RawReadOutcome>,
}

impl HwReadProvider for SimulatedHookedAppliance {
    fn read_via_libc_string(&self, path: &Path) -> LibcReadOutcome {
        let key = path.to_string_lossy().into_owned();
        self.libc_files
            .get(&key)
            .cloned()
            .unwrap_or(LibcReadOutcome::NotFound)
    }

    fn read_via_raw_syscall(&self, path: &Path) -> RawReadOutcome {
        let key = path.to_string_lossy().into_owned();
        self.raw_files
            .get(&key)
            .cloned()
            .unwrap_or(RawReadOutcome::NotFound)
    }

    fn list_net_interfaces(&self, _root: &Path) -> Vec<String> {
        vec!["eth0".to_string(), "ens192".to_string()]
    }
}

#[test]
fn test_engine1_detects_single_byte_uuid_mac_spoof_and_hidden_preload() {
    let root = Path::new("/mock_fsr");
    let mut libc_files = BTreeMap::new();
    let mut raw_files = BTreeMap::new();

    // 1. Single-byte UUID spoof (last hex digit '5' in libc vs '6' in raw kernel syscall)
    libc_files.insert(
        "/mock_fsr/sys/class/dmi/id/product_uuid".to_string(),
        LibcReadOutcome::Ok("4218a9c0-1111-2222-3333-abcdef012345\n".to_string()),
    );
    raw_files.insert(
        "/mock_fsr/sys/class/dmi/id/product_uuid".to_string(),
        RawReadOutcome::Ok(b"4218a9c0-1111-2222-3333-abcdef012346\n".to_vec()),
    );

    // 2. Clean NIC eth0 (identical bytes -> must NOT trigger false positive)
    libc_files.insert(
        "/mock_fsr/sys/class/net/eth0/address".to_string(),
        LibcReadOutcome::Ok("00:50:56:aa:bb:cc\n".to_string()),
    );
    raw_files.insert(
        "/mock_fsr/sys/class/net/eth0/address".to_string(),
        RawReadOutcome::Ok(b"00:50:56:aa:bb:cc\n".to_vec()),
    );

    // 3. Spoofed NIC ens192
    libc_files.insert(
        "/mock_fsr/sys/class/net/ens192/address".to_string(),
        LibcReadOutcome::Ok("00:0c:29:de:ad:01\n".to_string()),
    );
    raw_files.insert(
        "/mock_fsr/sys/class/net/ens192/address".to_string(),
        RawReadOutcome::Ok(b"00:0c:29:88:99:aa\n".to_vec()),
    );

    // 4. Rootkit hiding /etc/ld.so.preload from libc while kernel sees it
    libc_files.insert(
        "/mock_fsr/etc/ld.so.preload".to_string(),
        LibcReadOutcome::NotFound,
    );
    raw_files.insert(
        "/mock_fsr/etc/ld.so.preload".to_string(),
        RawReadOutcome::Ok(b"/usr/lib64/.libfsr_hwid_hook.so\n".to_vec()),
    );

    // 5. LD_PRELOAD inside /proc/1/environ
    let env_bytes = b"PATH=/usr/sbin:/usr/bin\0LD_PRELOAD=/dev/shm/libuuid_override.so\0";
    libc_files.insert(
        "/mock_fsr/proc/1/environ".to_string(),
        LibcReadOutcome::Ok(String::from_utf8(env_bytes.to_vec()).unwrap()),
    );
    raw_files.insert(
        "/mock_fsr/proc/1/environ".to_string(),
        RawReadOutcome::Ok(env_bytes.to_vec()),
    );

    let provider = SimulatedHookedAppliance {
        libc_files,
        raw_files,
    };
    let result = run_hw_integrity_with_provider(root, &provider);

    assert!(
        result
            .findings
            .iter()
            .all(|f| f.code == "CRITICAL_HW_SPOOF_HOOK"),
        "all hw_integrity findings must carry CRITICAL_HW_SPOOF_HOOK"
    );

    // Verify UUID mismatch caught at exact byte offset 35
    let uuid_finding = result
        .findings
        .iter()
        .find(|f| f.target == "/sys/class/dmi/id/product_uuid")
        .expect("expected product_uuid spoof finding");
    assert_eq!(
        uuid_finding.evidence.get("first_diff_byte_offset"),
        Some(&fsr_deep_audit::schema::JsonValue::Uint(35))
    );

    // Clean eth0 must NOT appear in findings
    assert!(
        !result
            .findings
            .iter()
            .any(|f| f.target == "/sys/class/net/eth0/address"),
        "clean eth0 interface must not produce a finding"
    );

    // Spoofed ens192, /etc/ld.so.preload, and /proc/1/environ must all be flagged
    assert!(result
        .findings
        .iter()
        .any(|f| f.target == "/sys/class/net/ens192/address"));
    assert!(result
        .findings
        .iter()
        .any(|f| f.target == "/etc/ld.so.preload"));
    assert!(result
        .findings
        .iter()
        .any(|f| f.target == "/proc/1/environ"));
}

// ============================================================================
// Engine 2 Test: ELF64 .text Disk-vs-Mem Patch & GOT/PLT Hijack Detection
// ============================================================================

/// Builds a minimal, spec-compliant x86_64 ELF64 shared library (`ET_DYN`) containing:
/// - `Elf64_Ehdr` (64B)
/// - 2 `PT_LOAD` `Elf64_Phdr` entries (`r-xp` code at 0x0..0x1000, `rw-p` GOT at 0x2000..0x3000)
/// - `.text`, `.dynstr`, `.dynsym`, `.rela.plt`, `.dynamic`, `.got.plt`, `.shstrtab`
fn build_synthetic_elf64_so(text_code: &[u8], rpath: Option<&str>) -> Vec<u8> {
    let mut buf = vec![0u8; 0x3000];

    // `.text` placed at file offset 0x0400 (vaddr 0x0400)
    let text_off = 0x0400usize;
    buf[text_off..text_off + text_code.len()].copy_from_slice(text_code);

    // `.dynstr` at 0x0600
    let dynstr_off = 0x0600usize;
    let mut dynstr = vec![0u8]; // index 0 = ""
    let sym_name_off = dynstr.len();
    dynstr.extend_from_slice(b"EVP_DigestVerifyFinal\0");
    let needed_off = dynstr.len();
    dynstr.extend_from_slice(b"libcrypto.so.3\0");
    let rpath_off = dynstr.len();
    if let Some(rp) = rpath {
        dynstr.extend_from_slice(rp.as_bytes());
        dynstr.push(0);
    }
    buf[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(&dynstr);

    // `.dynsym` at 0x0700: 2 entries (NULL + EVP_DigestVerifyFinal)
    let dynsym_off = 0x0700usize;
    // sym[1] at dynsym_off + 24
    buf[dynsym_off + 24..dynsym_off + 28].copy_from_slice(&(sym_name_off as u32).to_le_bytes());
    buf[dynsym_off + 28] = 0x12; // STB_GLOBAL | STT_FUNC

    // `.rela.plt` at 0x0800: 1 entry targeting GOT slot at vaddr 0x2018
    let rela_off = 0x0800usize;
    let got_slot_r_offset: u64 = 0x2018;
    let r_info: u64 = (1u64 << 32) | 7u64; // sym_idx=1, R_X86_64_JUMP_SLOT=7
    buf[rela_off..rela_off + 8].copy_from_slice(&got_slot_r_offset.to_le_bytes());
    buf[rela_off + 8..rela_off + 16].copy_from_slice(&r_info.to_le_bytes());

    // `.dynamic` at 0x2100
    let dynamic_off = 0x2100usize;
    let mut dyn_pos = dynamic_off;
    // DT_NEEDED (1)
    buf[dyn_pos..dyn_pos + 8].copy_from_slice(&1i64.to_le_bytes());
    buf[dyn_pos + 8..dyn_pos + 16].copy_from_slice(&(needed_off as u64).to_le_bytes());
    dyn_pos += 16;
    if rpath.is_some() {
        // DT_RPATH (15)
        buf[dyn_pos..dyn_pos + 8].copy_from_slice(&15i64.to_le_bytes());
        buf[dyn_pos + 8..dyn_pos + 16].copy_from_slice(&(rpath_off as u64).to_le_bytes());
        dyn_pos += 16;
    }
    // DT_NULL (0)
    let dynamic_sz = (dyn_pos + 16) - dynamic_off;

    // `.shstrtab` at 0x2300
    let shstr_off = 0x2300usize;
    let shstr = b"\0.text\0.dynstr\0.dynsym\0.rela.plt\0.dynamic\0.shstrtab\0";
    buf[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

    // Program Headers (`Elf64_Phdr`, 2 * 56 bytes) at 0x0040
    let phoff = 0x0040usize;
    write_phdr(&mut buf[phoff..phoff + 56], 1, 5, 0x0, 0x0, 0x1000, 0x1000);
    write_phdr(
        &mut buf[phoff + 56..phoff + 112],
        1,
        6,
        0x2000,
        0x2000,
        0x0800,
        0x0800,
    );

    // Section Headers (`Elf64_Shdr`, 7 * 64 bytes) at 0x2400
    let shoff = 0x2400usize;
    // [0] NULL
    // [1] .text (name=1, SHT_PROGBITS=1, SHF_ALLOC|SHF_EXECINSTR=6)
    write_shdr(
        &mut buf[shoff + 64..shoff + 128],
        1,
        1,
        6,
        text_off as u64,
        text_off as u64,
        text_code.len() as u64,
        0,
        0,
    );
    // [2] .dynstr (name=7, SHT_STRTAB=3)
    write_shdr(
        &mut buf[shoff + 128..shoff + 192],
        7,
        3,
        2,
        dynstr_off as u64,
        dynstr_off as u64,
        dynstr.len() as u64,
        0,
        0,
    );
    // [3] .dynsym (name=15, SHT_DYNSYM=11, link=2, entsize=24)
    write_shdr(
        &mut buf[shoff + 192..shoff + 256],
        15,
        11,
        2,
        dynsym_off as u64,
        dynsym_off as u64,
        48,
        2,
        24,
    );
    // [4] .rela.plt (name=23, SHT_RELA=4, link=3, entsize=24)
    write_shdr(
        &mut buf[shoff + 256..shoff + 320],
        23,
        4,
        2,
        rela_off as u64,
        rela_off as u64,
        24,
        3,
        24,
    );
    // [5] .dynamic (name=33, SHT_DYNAMIC=6, link=2, entsize=16)
    write_shdr(
        &mut buf[shoff + 320..shoff + 384],
        33,
        6,
        3,
        dynamic_off as u64,
        dynamic_off as u64,
        dynamic_sz as u64,
        2,
        16,
    );
    // [6] .shstrtab (name=42, SHT_STRTAB=3)
    write_shdr(
        &mut buf[shoff + 384..shoff + 448],
        42,
        3,
        0,
        shstr_off as u64,
        shstr_off as u64,
        shstr.len() as u64,
        0,
        0,
    );

    // ELF64 Header (`Elf64_Ehdr`, 64B) at 0x0000
    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    buf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[24..32].copy_from_slice(&(text_off as u64).to_le_bytes());
    buf[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
    buf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    buf[52..54].copy_from_slice(&64u16.to_le_bytes());
    buf[54..56].copy_from_slice(&56u16.to_le_bytes());
    buf[56..58].copy_from_slice(&2u16.to_le_bytes());
    buf[58..60].copy_from_slice(&64u16.to_le_bytes());
    buf[60..62].copy_from_slice(&7u16.to_le_bytes());
    buf[62..64].copy_from_slice(&6u16.to_le_bytes()); // e_shstrndx = 6

    buf
}

fn write_phdr(
    dst: &mut [u8],
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
) {
    dst[0..4].copy_from_slice(&p_type.to_le_bytes());
    dst[4..8].copy_from_slice(&p_flags.to_le_bytes());
    dst[8..16].copy_from_slice(&p_offset.to_le_bytes());
    dst[16..24].copy_from_slice(&p_vaddr.to_le_bytes());
    dst[24..32].copy_from_slice(&p_vaddr.to_le_bytes());
    dst[32..40].copy_from_slice(&p_filesz.to_le_bytes());
    dst[40..48].copy_from_slice(&p_memsz.to_le_bytes());
    dst[48..56].copy_from_slice(&0x1000u64.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn write_shdr(
    dst: &mut [u8],
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
) {
    dst[0..4].copy_from_slice(&sh_name.to_le_bytes());
    dst[4..8].copy_from_slice(&sh_type.to_le_bytes());
    dst[8..16].copy_from_slice(&sh_flags.to_le_bytes());
    dst[16..24].copy_from_slice(&sh_addr.to_le_bytes());
    dst[24..32].copy_from_slice(&sh_offset.to_le_bytes());
    dst[32..40].copy_from_slice(&sh_size.to_le_bytes());
    dst[40..44].copy_from_slice(&sh_link.to_le_bytes());
    dst[48..56].copy_from_slice(&8u64.to_le_bytes());
    dst[56..64].copy_from_slice(&sh_entsize.to_le_bytes());
}

// ============================================================================
// Engine 3 Test Helpers: PEP 552 .pyc + CPython Marshal CodeObject Builder
// ============================================================================

fn build_pep552_pyc_311(timestamp: u32, func_name: &str, stub_return_true: bool) -> Vec<u8> {
    let mut out = Vec::new();
    // 16-byte PEP 552 header: Python 3.11 magic = 3495 (0x0da7), \r\n, bitfield=0, ts, size
    out.extend_from_slice(&3495u16.to_le_bytes());
    out.extend_from_slice(&[0x0d, 0x0a]);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(&512u32.to_le_bytes());

    // Inner function CodeObject (Python 3.11 layout)
    // Bytecode: RESUME 0 (97 00), then either LOAD_CONST 1 (True); RETURN_VALUE (64 01 53 00)
    // or normal non-stub bytecode LOAD_FAST 0 (7c 00); RETURN_VALUE (53 00)
    let fn_code: &[u8] = if stub_return_true {
        &[151, 0, 100, 1, 83, 0]
    } else {
        &[151, 0, 124, 0, 83, 0]
    };

    let mut child = Vec::new();
    child.push(b'c'); // TYPE_CODE
    child.extend_from_slice(&2i32.to_le_bytes()); // co_argcount = 2 (serial, signature)
    child.extend_from_slice(&0i32.to_le_bytes()); // co_posonlyargcount
    child.extend_from_slice(&0i32.to_le_bytes()); // co_kwonlyargcount
    child.extend_from_slice(&2i32.to_le_bytes()); // co_stacksize
    child.extend_from_slice(&67i32.to_le_bytes()); // co_flags
    write_marshal_bytes(&mut child, fn_code);
    // co_consts = (None, True, "fortiguard_signature")
    child.push(b')');
    child.push(3);
    child.push(b'N');
    child.push(b'T');
    write_marshal_short_ascii(&mut child, "fortiguard_signature");
    // co_names = ("validate",)
    child.push(b')');
    child.push(1);
    write_marshal_short_ascii(&mut child, "validate");
    // co_localsplusnames = ("serial", "hw_id")
    child.push(b')');
    child.push(2);
    write_marshal_short_ascii(&mut child, "serial");
    write_marshal_short_ascii(&mut child, "hw_id");
    // co_localspluskinds
    write_marshal_bytes(&mut child, &[0x20, 0x20]);
    // co_filename, co_name, co_qualname
    write_marshal_short_ascii(&mut child, "/opt/cyops-licensing/validator.py");
    write_marshal_short_ascii(&mut child, func_name);
    write_marshal_short_ascii(&mut child, func_name);
    child.extend_from_slice(&42i32.to_le_bytes()); // co_firstlineno
    write_marshal_bytes(&mut child, &[]); // co_linetable
    write_marshal_bytes(&mut child, &[]); // co_exceptiontable

    // Root `<module>` CodeObject wrapping `child` in `co_consts`
    out.push(b'c');
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&1i32.to_le_bytes());
    out.extend_from_slice(&64i32.to_le_bytes());
    write_marshal_bytes(&mut out, &[151, 0, 100, 1, 83, 0]); // module returns None at idx 1
    out.push(b')');
    out.push(2);
    out.extend_from_slice(&child);
    out.push(b'N');
    out.push(b')');
    out.push(0); // co_names
    out.push(b')');
    out.push(0); // co_localsplusnames
    write_marshal_bytes(&mut out, &[]);
    write_marshal_short_ascii(&mut out, "/opt/cyops-licensing/validator.py");
    write_marshal_short_ascii(&mut out, "<module>");
    write_marshal_short_ascii(&mut out, "<module>");
    out.extend_from_slice(&1i32.to_le_bytes());
    write_marshal_bytes(&mut out, &[]);
    write_marshal_bytes(&mut out, &[]);

    out
}

fn write_marshal_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.push(b's');
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}

fn write_marshal_short_ascii(buf: &mut Vec<u8>, s: &str) {
    buf.push(b'z');
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

#[test]
fn test_engine3_python39_marshal_and_pep552_siphash_parsing() {
    use fsr_deep_audit::pyc_inspector::{
        detect_return_true_stub, parse_marshaled_code_object, parse_pep552_header,
        Pep552ValidationPayload,
    };

    // Build a Python 3.9 (magic 3425 = 0x0d61) unchecked-hash PEP 552 header (bitfield = 0x1)
    let mut pyc39 = Vec::new();
    pyc39.extend_from_slice(&3425u16.to_le_bytes());
    pyc39.extend_from_slice(&[0x0d, 0x0a]);
    pyc39.extend_from_slice(&1u32.to_le_bytes()); // bit 0 = 1 (SipHash), bit 1 = 0 (unchecked)
    pyc39.extend_from_slice(&0xdead_beef_cafe_babeu64.to_le_bytes());

    // Python 3.8–3.10 TYPE_CODE layout (6 leading i32 fields)
    pyc39.push(b'c');
    pyc39.extend_from_slice(&1i32.to_le_bytes()); // co_argcount
    pyc39.extend_from_slice(&0i32.to_le_bytes()); // co_posonlyargcount
    pyc39.extend_from_slice(&0i32.to_le_bytes()); // co_kwonlyargcount
    pyc39.extend_from_slice(&1i32.to_le_bytes()); // co_nlocals
    pyc39.extend_from_slice(&1i32.to_le_bytes()); // co_stacksize
    pyc39.extend_from_slice(&67i32.to_le_bytes()); // co_flags
    // Python 3.8–3.10 entry stub: LOAD_CONST 1 (True) [100, 1], RETURN_VALUE [83, 0]
    write_marshal_bytes(&mut pyc39, &[100, 1, 83, 0]);
    pyc39.push(b')');
    pyc39.push(2);
    pyc39.push(b'N'); // const 0: None (docstring slot)
    pyc39.push(b'T'); // const 1: True
    pyc39.push(b')');
    pyc39.push(0); // co_names
    pyc39.push(b')');
    pyc39.push(1);
    write_marshal_short_ascii(&mut pyc39, "license_blob"); // co_varnames
    pyc39.push(b')');
    pyc39.push(0); // co_freevars
    pyc39.push(b')');
    pyc39.push(0); // co_cellvars
    write_marshal_short_ascii(&mut pyc39, "check_expiry.py");
    write_marshal_short_ascii(&mut pyc39, "validate_expiry");
    pyc39.extend_from_slice(&19i32.to_le_bytes()); // co_firstlineno
    write_marshal_bytes(&mut pyc39, &[]); // co_lnotab

    let hdr = parse_pep552_header(&pyc39).expect("valid PEP 552 header");
    assert_eq!(hdr.python_version, "3.9");
    assert!(hdr.crlf_valid);
    match hdr.payload {
        Pep552ValidationPayload::SipHash {
            check_source,
            siphash64,
        } => {
            assert!(!check_source);
            assert_eq!(siphash64, 0xdead_beef_cafe_babe);
        }
        _ => panic!("expected SipHash PEP 552 payload"),
    }

    let code =
        parse_marshaled_code_object(&pyc39[hdr.header_len..], hdr.code_layout).expect("valid 3.9 marshal");
    assert_eq!(code.co_name, "validate_expiry");
    let (idx, bytes, disasm) = detect_return_true_stub(&code).expect("must detect 3.9 True stub");
    assert_eq!(idx, 1);
    assert_eq!(bytes, vec![100, 1, 83, 0]);
    assert_eq!(disasm, vec!["LOAD_CONST 1 (True)", "RETURN_VALUE"]);
}

// ============================================================================
// Engine 4 Test Helpers: Real RPM v4 Header + OpenPGP Packet + SQLite3 rpmdb
// ============================================================================

fn build_openpgp_v4_rsa_sig_packet(key_id: [u8; 8]) -> Vec<u8> {
    // Hashed subpacket: [len=9, type=16 (Issuer Key ID), 8-byte key_id]
    let mut body = vec![
        4,    // v4 signature
        0x00, // binary document signature
        1,    // RSA Encrypt-or-Sign
        8,    // SHA-256
    ];
    body.extend_from_slice(&10u16.to_be_bytes()); // hashed subpacket area length = 10
    body.push(9); // subpacket length (1 type byte + 8 key id bytes)
    body.push(16); // Subpacket 16: Issuer Key ID
    body.extend_from_slice(&key_id);
    body.extend_from_slice(&0u16.to_be_bytes()); // unhashed subpackets length = 0
    body.extend_from_slice(&[0xab, 0xcd]); // left 16 bits of signed hash
    body.extend_from_slice(&[0x08, 0x00]); // 2048-bit MPI stub
    body.extend_from_slice(&[0x55; 32]);

    // Old-format Tag 2 packet header with 1-byte length: 0x80 | (2 << 2) | 0 = 0x88
    let mut pkt = Vec::with_capacity(2 + body.len());
    pkt.push(0x88);
    pkt.push(body.len() as u8);
    pkt.extend_from_slice(&body);
    pkt
}

#[allow(clippy::too_many_arguments)]
fn build_rpm_header_blob(
    name: &str,
    version: &str,
    release: &str,
    signed_key: Option<[u8; 8]>,
    dir_name: &str,
    files: &[(&str, &str, u32)], // (basename, sha256, flags)
    extra_padding_bytes: usize,
) -> Vec<u8> {
    let mut entries: Vec<(i32, u32, usize, usize)> = Vec::new();
    let mut store: Vec<u8> = Vec::new();

    let push_cstr = |tag: i32, val: &str, entries: &mut Vec<_>, store: &mut Vec<u8>| {
        let off = store.len();
        store.extend_from_slice(val.as_bytes());
        store.push(0);
        entries.push((tag, 6, off, 1));
    };

    push_cstr(RPMTAG_NAME, name, &mut entries, &mut store);
    push_cstr(RPMTAG_VERSION, version, &mut entries, &mut store);
    push_cstr(RPMTAG_RELEASE, release, &mut entries, &mut store);
    push_cstr(RPMTAG_ARCH, "x86_64", &mut entries, &mut store);
    push_cstr(RPMTAG_VENDOR, "Fortinet, Inc.", &mut entries, &mut store);

    if let Some(key_id) = signed_key {
        let sig = build_openpgp_v4_rsa_sig_packet(key_id);
        let rsa_off = store.len();
        store.extend_from_slice(&sig);
        entries.push((RPMTAG_RSAHEADER, 7, rsa_off, sig.len()));

        let pgp_off = store.len();
        store.extend_from_slice(&sig);
        entries.push((RPMTAG_SIGPGP, 7, pgp_off, sig.len()));
    }

    // Align 4-byte integers in store
    while (store.len() & 3) != 0 {
        store.push(0);
    }
    let algo_off = store.len();
    store.extend_from_slice(&8u32.to_be_bytes()); // SHA-256
    entries.push((RPMTAG_FILEDIGESTALGO, 4, algo_off, 1));

    if !files.is_empty() {
        while (store.len() & 3) != 0 {
            store.push(0);
        }
        let dir_idx_off = store.len();
        for _ in files {
            store.extend_from_slice(&0u32.to_be_bytes());
        }
        entries.push((RPMTAG_DIRINDEXES, 4, dir_idx_off, files.len()));

        let flags_off = store.len();
        for (_, _, fl) in files {
            store.extend_from_slice(&fl.to_be_bytes());
        }
        entries.push((RPMTAG_FILEFLAGS, 4, flags_off, files.len()));

        let dirnames_off = store.len();
        store.extend_from_slice(dir_name.as_bytes());
        store.push(0);
        entries.push((RPMTAG_DIRNAMES, 8, dirnames_off, 1));

        let basenames_off = store.len();
        for (base, _, _) in files {
            store.extend_from_slice(base.as_bytes());
            store.push(0);
        }
        entries.push((RPMTAG_BASENAMES, 8, basenames_off, files.len()));

        let digests_off = store.len();
        for (_, dig, _) in files {
            store.extend_from_slice(dig.as_bytes());
            store.push(0);
        }
        entries.push((RPMTAG_FILEDIGESTS, 8, digests_off, files.len()));
    }

    // Optional large binary tag to force SQLite3 multi-page overflow chain (> 4096B pages)
    if extra_padding_bytes > 0 {
        let pad_off = store.len();
        store.resize(store.len() + extra_padding_bytes, 0x41);
        entries.push((9999, 7, pad_off, extra_padding_bytes));
    }

    // Assemble exported rpmdb blob (no 8-byte file magic, matching librpm headerExport)
    let mut blob = Vec::with_capacity(8 + entries.len() * 16 + store.len());
    blob.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    blob.extend_from_slice(&(store.len() as u32).to_be_bytes());
    for (tag, dtype, off, cnt) in entries {
        blob.extend_from_slice(&tag.to_be_bytes());
        blob.extend_from_slice(&dtype.to_be_bytes());
        blob.extend_from_slice(&(off as i32).to_be_bytes());
        blob.extend_from_slice(&(cnt as u32).to_be_bytes());
    }
    blob.extend_from_slice(&store);
    blob
}

#[test]
fn test_end_to_end_elf_pyc_and_sqlite_rpm_forensics() {
    let tmp_root: PathBuf = std::env::temp_dir().join(format!(
        "fsr_deep_audit_e2e_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&tmp_root);
    fs::create_dir_all(&tmp_root).unwrap();

    // ------------------------------------------------------------------------
    // 1. Setup Engine 2 Fixture: ELF64 `.text` inline bypass + GOT hijack + deleted .so
    // ------------------------------------------------------------------------
    let orig_text = [
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0xe8, 0x11, 0x22, 0x33, 0x44, 0x85, 0xc0,
        0x74,
    ];
    let so_bytes = build_synthetic_elf64_so(&orig_text, None);
    let so_rel = "opt/cyops-licensing/lib/liblicverify.so";
    let so_disk = tmp_root.join(so_rel);
    fs::create_dir_all(so_disk.parent().unwrap()).unwrap();
    fs::write(&so_disk, &so_bytes).unwrap();

    // Create simulated process `/proc/4242` (`uwsgi`)
    let pid_dir = tmp_root.join("proc/4242");
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(pid_dir.join("comm"), b"uwsgi\n").unwrap();
    fs::write(
        pid_dir.join("cmdline"),
        b"/opt/cyops/bin/uwsgi\0--ini\0/etc/cyops/uwsgi.ini\0",
    )
    .unwrap();

    // Map `liblicverify.so` at low synthetic VMA 0x10000 so `/proc/4242/mem` stays compact
    let maps = "\
00010000-00011000 r-xp 00000000 fd:00 0 /opt/cyops-licensing/lib/liblicverify.so
00012000-00013000 rw-p 00002000 fd:00 0 /opt/cyops-licensing/lib/liblicverify.so
00020000-00021000 r-xp 00000000 00:01 99 /dev/shm/libcrack_hook.so (deleted)
";
    fs::write(pid_dir.join("maps"), maps).unwrap();

    // Build `/proc/4242/mem` image (0x21000 bytes)
    let mut mem_img = vec![0u8; 0x21000];
    mem_img[0x10000..0x11000].copy_from_slice(&so_bytes[0x0..0x1000]);
    mem_img[0x12000..0x12800].copy_from_slice(&so_bytes[0x2000..0x2800]);

    // Patch `.text` in memory at VMA 0x10400 (file offset 0x0400) with `mov eax, 1; ret`!
    mem_img[0x10400..0x10406].copy_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);

    // Hijack GOT slot at load_bias(0x10000) + r_offset(0x2018) = 0x12018 -> 0x20040 (inside `/dev/shm/libcrack_hook.so (deleted)`)!
    mem_img[0x12018..0x12020].copy_from_slice(&0x0002_0040u64.to_le_bytes());
    fs::write(pid_dir.join("mem"), &mem_img).unwrap();

    // ------------------------------------------------------------------------
    // 2. Setup Engine 3 Fixture: Cohort of 6 clean PEP 552 .pyc + 1 recompiled stubbed .pyc
    // ------------------------------------------------------------------------
    let pyc_dir = tmp_root.join("opt/cyops-licensing/cyops_licensing/__pycache__");
    fs::create_dir_all(&pyc_dir).unwrap();

    let baseline_ts = 1_700_000_000u32;
    for i in 0..6 {
        let clean_pyc =
            build_pep552_pyc_311(baseline_ts + (i * 5), &format!("helper_{}", i), false);
        fs::write(
            pyc_dir.join(format!("mod_{}.cpython-311.pyc", i)),
            clean_pyc,
        )
        .unwrap();
    }
    // Single recompiled + stubbed `license_validator.cpython-311.pyc` (compiled 45 days later!)
    let cracked_pyc = build_pep552_pyc_311(
        baseline_ts + 45 * 86_400,
        "validate_fortiguard_license",
        true,
    );
    fs::write(
        pyc_dir.join("license_validator.cpython-311.pyc"),
        &cracked_pyc,
    )
    .unwrap();

    // ------------------------------------------------------------------------
    // 3. Setup Engine 4 Fixture: `/usr/bin/rpm` + Real SQLite3 `rpmdb.sqlite`
    // ------------------------------------------------------------------------
    let rpm_bin_dir = tmp_root.join("usr/bin");
    fs::create_dir_all(&rpm_bin_dir).unwrap();
    let trojan_rpm_elf = build_synthetic_elf64_so(&orig_text, Some("/tmp/evil_rpath"));
    fs::write(rpm_bin_dir.join("rpm"), &trojan_rpm_elf).unwrap();

    // Create installed files for `cyops-core` (clean) and `cyops-licensing` (tampered)
    let core_dir = tmp_root.join("opt/cyops-core");
    fs::create_dir_all(&core_dir).unwrap();
    let clean_engine_py = b"def run_workflow():\n    return 'ok'\n";
    fs::write(core_dir.join("engine.py"), clean_engine_py).unwrap();
    let clean_engine_sha = sha256_hex(clean_engine_py);

    let lic_dir = tmp_root.join("opt/cyops-licensing/cyops_licensing");
    fs::create_dir_all(&lic_dir).unwrap();
    let orig_validator_py = b"def validate_license(lic):\n    return verify_rsa(lic)\n";
    let orig_validator_sha = sha256_hex(orig_validator_py);
    // Write TAMPERED file onto disk!
    fs::write(
        lic_dir.join("validator.py"),
        b"def validate_license(lic):\n    return True  # CRACKED\n",
    )
    .unwrap();

    // Also create a modified `%config` file (`RPMFILE_CONFIG = 1`) to verify zero false positives on config edits
    let orig_conf = b"log_level = INFO\n";
    let orig_conf_sha = sha256_hex(orig_conf);
    fs::write(lic_dir.join("licensing.conf"), b"log_level = DEBUG\n").unwrap();

    let fortinet_key: [u8; 8] = [0x46, 0x4f, 0x52, 0x54, 0x49, 0x4e, 0x45, 0x54];
    // Include 18,000 bytes of padding so SQLite3 stores each blob across ~5 overflow pages!
    let blob_core = build_rpm_header_blob(
        "cyops-core",
        "7.6.0",
        "1.el9",
        Some(fortinet_key),
        "/opt/cyops-core/",
        &[("engine.py", &clean_engine_sha, 0)],
        18_000,
    );
    let blob_licensing = build_rpm_header_blob(
        "cyops-licensing",
        "7.6.0",
        "1.el9",
        Some(fortinet_key),
        "/opt/cyops-licensing/cyops_licensing/",
        &[
            ("validator.py", &orig_validator_sha, 0),
            ("licensing.conf", &orig_conf_sha, 1), // RPMFILE_CONFIG = 1
        ],
        18_000,
    );
    let blob_unsigned_repack = build_rpm_header_blob(
        "cyops-ui-repacked",
        "7.6.0",
        "99.cracked",
        None, // Missing both RPMTAG_RSAHEADER (268) and RPMTAG_SIGPGP (259)!
        "/opt/cyops-core/",
        &[("engine.py", &clean_engine_sha, 0)],
        512,
    );

    let rpmdb_dir = tmp_root.join("var/lib/rpm");
    fs::create_dir_all(&rpmdb_dir).unwrap();
    let sqlite_path = rpmdb_dir.join("rpmdb.sqlite");

    let sql_script = format!(
        "PRAGMA page_size = 4096;\n\
         CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);\n\
         INSERT INTO Packages (blob) VALUES (X'{}');\n\
         INSERT INTO Packages (blob) VALUES (X'{}');\n\
         INSERT INTO Packages (blob) VALUES (X'{}');\n",
        hex_encode(&blob_core),
        hex_encode(&blob_licensing),
        hex_encode(&blob_unsigned_repack),
    );
    let sql_file = rpmdb_dir.join("seed.sql");
    fs::write(&sql_file, sql_script).unwrap();

    let status = Command::new("sqlite3")
        .arg(&sqlite_path)
        .arg(format!(".read {}", sql_file.display()))
        .status()
        .expect("sqlite3 binary required for integration test");
    assert!(status.success(), "sqlite3 failed to create rpmdb.sqlite");
    let _ = fs::remove_file(&sql_file);

    // ------------------------------------------------------------------------
    // 4. Execute Engines & Assert Exact Detections
    // ------------------------------------------------------------------------
    let elf_res = run_elf_vma_diff_audit(&tmp_root);
    let elf_codes: Vec<&str> = elf_res.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(
        elf_codes.contains(&"CRITICAL_EPHEMERAL_SHARED_OBJECT_INJECTION"),
        "missing ephemeral /dev/shm .so detection: {:?}",
        elf_codes
    );
    assert!(
        elf_codes.contains(&"CRITICAL_DELETED_EXECUTABLE_MAPPING"),
        "missing (deleted) executable VMA detection: {:?}",
        elf_codes
    );
    assert!(
        elf_codes.contains(&"CRITICAL_ELF_TEXT_INLINE_PATCH"),
        "missing .text inline patch detection: {:?}",
        elf_codes
    );
    assert!(
        elf_codes.contains(&"CRITICAL_GOT_PLT_POINTER_HIJACK"),
        "missing GOT/PLT pointer hijack detection: {:?}",
        elf_codes
    );

    let pyc_res = run_pyc_inspector_audit(&tmp_root);
    let pyc_codes: Vec<&str> = pyc_res.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(
        pyc_codes.contains(&"CRITICAL_PYC_BYTECODE_RETURN_TRUE_STUB"),
        "missing Python 3.11 LOAD_CONST(True)+RETURN_VALUE stub detection: {:?}",
        pyc_codes
    );
    assert!(
        pyc_codes.contains(&"HIGH_PYC_RECOMPILED_TIMESTAMP_OUTLIER"),
        "missing PEP 552 timestamp outlier detection: {:?}",
        pyc_codes
    );

    let rpm_res = run_rpm_forensics_audit(&tmp_root);
    let rpm_codes: Vec<&str> = rpm_res.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(
        rpm_codes.contains(&"CRITICAL_RPM_BINARY_RPATH_HIJACK"),
        "missing /usr/bin/rpm DT_RPATH hijack detection: {:?}",
        rpm_codes
    );
    assert!(
        rpm_codes.contains(&"CRITICAL_RPM_FILE_DIGEST_MISMATCH"),
        "missing RPMTAG_FILEDIGESTS SHA-256 mismatch on validator.py: {:?}",
        rpm_codes
    );
    assert!(
        rpm_codes.contains(&"CRITICAL_RPM_UNSIGNED_CYOPS_PACKAGE"),
        "missing unsigned cyops-* package detection: {:?}",
        rpm_codes
    );
    // Ensure `%config` file `licensing.conf` did NOT trigger a false-positive mismatch
    assert!(
        !rpm_res
            .findings
            .iter()
            .any(|f| f.target.ends_with("licensing.conf")),
        "%config file edit must be ignored as benign admin configuration"
    );

    // ------------------------------------------------------------------------
    // 5. Verify Full Deterministic JSON Output Schema
    // ------------------------------------------------------------------------
    let full_report = execute_full_audit(&tmp_root, EngineSelection::default());
    let json_text_1 = full_report.clone().into_canonical_json().to_json_string(true);
    let json_text_2 = full_report.into_canonical_json().to_json_string(true);
    assert_eq!(
        json_text_1, json_text_2,
        "JSON serialization must be 100% deterministic across runs"
    );
    assert!(json_text_1.contains("\"status\": \"COMPROMISED_OR_CRACKED\""));

    // Validate strict RFC 8259 JSON syntax using Python's stdlib `json.loads`
    let mut py_check = Command::new("python3")
        .arg("-c")
        .arg("import json, sys; data = json.loads(sys.stdin.read()); assert data['verdict']['critical_count'] >= 7")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("python3 required for JSON validation");
    {
        use std::io::Write;
        py_check
            .stdin
            .as_mut()
            .unwrap()
            .write_all(json_text_1.as_bytes())
            .unwrap();
    }
    let py_status = py_check.wait().unwrap();
    assert!(py_status.success(), "output failed strict RFC 8259 JSON parsing");

    let _ = fs::remove_dir_all(&tmp_root);
}
