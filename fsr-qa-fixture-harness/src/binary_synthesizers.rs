//! Pure-Rust Deterministic Binary Test-Vector Synthesizers (Zero External Tools).
//!
//! Generates inert, spec-compliant mock binary artifacts in memory without invoking
//! external `sqlite3`, `openssl`, `python3`, or `gcc` binaries, ensuring reproducible
//! QA/CI benchmarks on any air-gapped Linux or macOS environment:
//!   - SQLite3 B-Tree + overflow `rpmdb.sqlite` & RPM v4 + OpenPGP v4 RSA headers
//!   - x86_64 `ET_DYN` ELF64 shared objects (clean Intel CET `endbr64` prologues & QA test stubs)
//!   - Python 3.9 & 3.11 PEP 552 `.pyc` headers & marshaled code objects
//!   - RFC 5280 ASN.1 DER + RFC 4648 PEM X.509v3 certificates
//!   - PostgreSQL 8192-byte `pg_control` with Castagnoli CRC-32C
//!   - EXT4 (`0xEF53`) and XFS v5 (`XFSB`) 4096-byte superblock headers
//!   - Linux `x86_64` 384-byte `wtmp` binary records

use fsr_clone_cluster_audit::birthmark_extractor::PG_CONTROL_FILE_SIZE;
use fsr_clone_cluster_audit::time_freeze_audit::{WTMP_RECORD_SIZE_X86_64, WTMP_TV_SEC_OFFSET};
use fsr_deep_audit::crypto::crc32c;
use fsr_deep_audit::rpm_forensics::{
    RPMTAG_ARCH, RPMTAG_BASENAMES, RPMTAG_DIRINDEXES, RPMTAG_DIRNAMES, RPMTAG_FILEDIGESTALGO,
    RPMTAG_FILEDIGESTS, RPMTAG_FILEFLAGS, RPMTAG_NAME, RPMTAG_RELEASE, RPMTAG_RSAHEADER,
    RPMTAG_SIGPGP, RPMTAG_VENDOR, RPMTAG_VERSION,
};

/// Standard benign RHEL/Rocky 8/9 x86_64 function prologue with Intel CET `endbr64`:
/// `endbr64; push r15; push r14; push r13; push r12; push rbp; push rbx; sub rsp, 0x28`
pub const CLEAN_CET_PROLOGUE_X86_64: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0x41, 0x57, // push r15
    0x41, 0x56, // push r14
    0x41, 0x55, // push r13
    0x41, 0x54, // push r12
    0x55, // push rbp
    0x53, // push rbx
    0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28
];

/// Inert QA test byte pattern simulating an Intel CET `endbr64` + `mov eax, 1; ret` stub (`X509_verify_cert`).
pub const QA_CET_RET_ONE_STUB: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xc3, // ret
];

/// Inert QA test byte pattern simulating an Intel CET `endbr64` + `xor eax, eax; ret` stub (`PAM_SUCCESS=0`).
pub const QA_CET_RET_ZERO_STUB: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0x31, 0xc0, // xor eax, eax
    0xc3, // ret
];

/// Default mock Fortinet QA signing key ID (`"FORTINET"`).
pub const QA_FORTINET_PGP_KEY_ID: [u8; 8] = [0x46, 0x4f, 0x52, 0x54, 0x49, 0x4e, 0x45, 0x54];

// ============================================================================
// 1. Pure-Rust SQLite3 `rpmdb.sqlite` + RPM v4 Header Synthesizer
// ============================================================================

/// Builds an RFC 4880 OpenPGP v4 RSA/SHA-256 signature packet carrying `key_id`.
pub fn build_openpgp_v4_rsa_sig_packet(key_id: [u8; 8]) -> Vec<u8> {
    let mut body = vec![
        4,    // v4 signature
        0x00, // binary document signature
        1,    // RSA
        8,    // SHA-256
    ];
    body.extend_from_slice(&10u16.to_be_bytes());
    body.push(9);
    body.push(16); // Issuer Key ID subpacket
    body.extend_from_slice(&key_id);
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&[0xab, 0xcd]);
    body.extend_from_slice(&[0x08, 0x00]);
    body.extend_from_slice(&[0x55; 32]);

    let mut pkt = Vec::with_capacity(2 + body.len());
    pkt.push(0x88);
    pkt.push(body.len() as u8);
    pkt.extend_from_slice(&body);
    pkt
}

/// Builds an exported RPM v4 package header blob (`Packages.blob` column format).
pub fn build_rpm_v4_header_blob(
    name: &str,
    version: &str,
    release: &str,
    signed_key: Option<[u8; 8]>,
    dir_name: &str,
    files: &[(&str, &str, u32)],
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

    if extra_padding_bytes > 0 {
        let pad_off = store.len();
        store.resize(store.len() + extra_padding_bytes, 0x41);
        entries.push((9999, 7, pad_off, extra_padding_bytes));
    }

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

/// Builds a spec-compliant 4096-byte-page SQLite3 `rpmdb.sqlite` database containing
/// `Packages(hnum INTEGER PRIMARY KEY, blob BLOB)` and automatic overflow page chains.
pub fn build_sqlite3_rpmdb_bytes(package_blobs: &[Vec<u8>]) -> Vec<u8> {
    const PAGE_SIZE: usize = 4096;
    const X_MAX: usize = PAGE_SIZE - 35; // 4061
    const M_MIN: usize = ((PAGE_SIZE - 12) * 32 / 255) - 23; // 489

    let mut overflow_pages: Vec<[u8; PAGE_SIZE]> = Vec::new();
    let mut pkg_cells: Vec<Vec<u8>> = Vec::with_capacity(package_blobs.len());

    for (idx, blob) in package_blobs.iter().enumerate() {
        let rowid = (idx + 1) as u64;
        // SQLite record for `(NULL, blob)`:
        // serial_type(NULL) = 0, serial_type(BLOB len N) = 2*N + 12
        let blob_serial = (blob.len() as u64) * 2 + 12;
        let mut st_bytes = Vec::new();
        write_sqlite_varint(&mut st_bytes, 0);
        write_sqlite_varint(&mut st_bytes, blob_serial);

        let hdr_len = (1 + st_bytes.len()) as u64;
        let mut record = Vec::with_capacity(1 + st_bytes.len() + blob.len());
        write_sqlite_varint(&mut record, hdr_len);
        record.extend_from_slice(&st_bytes);
        record.extend_from_slice(blob);

        let payload_len = record.len();
        let mut cell = Vec::new();
        write_sqlite_varint(&mut cell, payload_len as u64);
        write_sqlite_varint(&mut cell, rowid);

        if payload_len <= X_MAX {
            cell.extend_from_slice(&record);
        } else {
            let k = M_MIN + ((payload_len - M_MIN) % (PAGE_SIZE - 4));
            let local_len = if k <= X_MAX { k } else { M_MIN };
            cell.extend_from_slice(&record[..local_len]);

            let first_ovf_page_num = (3 + overflow_pages.len()) as u32;
            cell.extend_from_slice(&first_ovf_page_num.to_be_bytes());

            let mut rem = &record[local_len..];
            while !rem.is_empty() {
                let take = rem.len().min(PAGE_SIZE - 4);
                let has_more = rem.len() > take;
                let next_pg = if has_more {
                    (3 + overflow_pages.len() + 1) as u32
                } else {
                    0u32
                };
                let mut pg = [0u8; PAGE_SIZE];
                pg[0..4].copy_from_slice(&next_pg.to_be_bytes());
                pg[4..4 + take].copy_from_slice(&rem[..take]);
                overflow_pages.push(pg);
                rem = &rem[take..];
            }
        }
        pkg_cells.push(cell);
    }

    let total_pages = (2 + overflow_pages.len()) as u32;
    let mut db = vec![0u8; (total_pages as usize) * PAGE_SIZE];

    // --- Page 1: 100-byte SQLite3 Header + `sqlite_schema` Leaf B-Tree ---
    db[0..16].copy_from_slice(b"SQLite format 3\0");
    db[16..18].copy_from_slice(&(PAGE_SIZE as u16).to_be_bytes());
    db[18] = 1;
    db[19] = 1;
    db[20] = 0; // reserved bytes
    db[21] = 64;
    db[22] = 32;
    db[23] = 32;
    db[28..32].copy_from_slice(&total_pages.to_be_bytes());
    db[40..44].copy_from_slice(&1u32.to_be_bytes()); // schema cookie
    db[44..48].copy_from_slice(&4u32.to_be_bytes()); // schema format 4
    db[56..60].copy_from_slice(&1u32.to_be_bytes()); // UTF-8

    let create_sql = b"CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)";
    let schema_record = build_sqlite_schema_row("table", "Packages", "Packages", 2, create_sql);
    let mut schema_cell = Vec::new();
    write_sqlite_varint(&mut schema_cell, schema_record.len() as u64);
    write_sqlite_varint(&mut schema_cell, 1); // rowid = 1
    schema_cell.extend_from_slice(&schema_record);

    let p1_cell_off = PAGE_SIZE - schema_cell.len();
    db[100] = 0x0d; // Leaf table B-tree
    db[103..105].copy_from_slice(&1u16.to_be_bytes()); // 1 cell
    db[105..107].copy_from_slice(&(p1_cell_off as u16).to_be_bytes());
    db[108..110].copy_from_slice(&(p1_cell_off as u16).to_be_bytes());
    db[p1_cell_off..PAGE_SIZE].copy_from_slice(&schema_cell);

    // --- Page 2: `Packages` Leaf Table B-Tree ---
    let p2 = &mut db[PAGE_SIZE..2 * PAGE_SIZE];
    p2[0] = 0x0d; // Leaf table B-tree
    p2[3..5].copy_from_slice(&(pkg_cells.len() as u16).to_be_bytes());
    let mut cursor = PAGE_SIZE;
    for (idx, cell) in pkg_cells.iter().enumerate() {
        cursor = cursor.checked_sub(cell.len()).expect("cells fit on page 2");
        p2[cursor..cursor + cell.len()].copy_from_slice(cell);
        let ptr_off = 8 + idx * 2;
        p2[ptr_off..ptr_off + 2].copy_from_slice(&(cursor as u16).to_be_bytes());
    }
    p2[5..7].copy_from_slice(&(cursor as u16).to_be_bytes());

    // --- Pages 3..N: Overflow Pages ---
    for (idx, ovf) in overflow_pages.iter().enumerate() {
        let base = (2 + idx) * PAGE_SIZE;
        db[base..base + PAGE_SIZE].copy_from_slice(ovf);
    }

    db
}

fn build_sqlite_schema_row(
    kind: &str,
    name: &str,
    tbl_name: &str,
    rootpage: u8,
    sql: &[u8],
) -> Vec<u8> {
    let mut st = Vec::new();
    write_sqlite_varint(&mut st, (kind.len() as u64) * 2 + 13);
    write_sqlite_varint(&mut st, (name.len() as u64) * 2 + 13);
    write_sqlite_varint(&mut st, (tbl_name.len() as u64) * 2 + 13);
    write_sqlite_varint(&mut st, 1); // 1-byte signed int for rootpage
    write_sqlite_varint(&mut st, (sql.len() as u64) * 2 + 13);

    let mut rec = Vec::new();
    write_sqlite_varint(&mut rec, (1 + st.len()) as u64);
    rec.extend_from_slice(&st);
    rec.extend_from_slice(kind.as_bytes());
    rec.extend_from_slice(name.as_bytes());
    rec.extend_from_slice(tbl_name.as_bytes());
    rec.push(rootpage);
    rec.extend_from_slice(sql);
    rec
}

fn write_sqlite_varint(out: &mut Vec<u8>, mut val: u64) {
    if val <= 0x7f {
        out.push(val as u8);
        return;
    }
    let mut bytes = [0u8; 9];
    let mut n = 0usize;
    bytes[0] = (val & 0x7f) as u8;
    val >>= 7;
    n += 1;
    while val > 0 {
        bytes[n] = ((val & 0x7f) as u8) | 0x80;
        val >>= 7;
        n += 1;
    }
    for i in (0..n).rev() {
        out.push(bytes[i]);
    }
}

// ============================================================================
// 2. Pure-Rust x86_64 ELF64 `ET_DYN` Shared Object Synthesizer
// ============================================================================

/// Builds a spec-compliant `x86_64` ELF64 `ET_DYN` shared library (`.so` / PIE) with:
///   - Exported `.dynsym` functions placed at 64-byte intervals inside `.text` (`0x0400`),
///   - Optional `DT_RPATH` entry in `.dynamic`,
///   - Optional `R_X86_64_JUMP_SLOT` (`7`) relocation in `.rela.plt` targeting `0x2018` (`.got.plt`)
///     for disk-vs-memory VMA & GOT QA vector testing.
pub fn build_elf64_shared_object(
    exported_symbols: &[(&str, &[u8])],
    rpath: Option<&str>,
    include_got_jump_slot: bool,
) -> Vec<u8> {
    let mut buf = vec![0u8; 0x3000];

    let text_off = 0x0400usize;
    for (idx, (_, code)) in exported_symbols.iter().enumerate() {
        let off = text_off + idx * 64;
        buf[off..off + code.len()].copy_from_slice(code);
    }

    // `.dynstr` at 0x0800
    let dynstr_off = 0x0800usize;
    let mut dynstr = vec![0u8];
    let mut sym_name_offsets = Vec::with_capacity(exported_symbols.len());
    for (name, _) in exported_symbols {
        sym_name_offsets.push(dynstr.len() as u32);
        dynstr.extend_from_slice(name.as_bytes());
        dynstr.push(0);
    }
    let libc_name_off = dynstr.len() as u32;
    dynstr.extend_from_slice(b"libc.so.6\0");
    let rpath_off = rpath.map(|rp| {
        let o = dynstr.len() as u32;
        dynstr.extend_from_slice(rp.as_bytes());
        dynstr.push(0);
        o
    });
    buf[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(&dynstr);

    // `.dynsym` at 0x0A00
    let dynsym_off = 0x0A00usize;
    for (idx, (_, code)) in exported_symbols.iter().enumerate() {
        let base = dynsym_off + (idx + 1) * 24;
        let fn_va = (text_off + idx * 64) as u64;
        buf[base..base + 4].copy_from_slice(&sym_name_offsets[idx].to_le_bytes());
        buf[base + 4] = 0x12; // STB_GLOBAL | STT_FUNC
        buf[base + 6..base + 8].copy_from_slice(&1u16.to_le_bytes()); // .text
        buf[base + 8..base + 16].copy_from_slice(&fn_va.to_le_bytes());
        buf[base + 16..base + 24].copy_from_slice(&(code.len().max(16) as u64).to_le_bytes());
    }
    let dynsym_len = (exported_symbols.len() + 1) * 24;

    // `.rela.plt` at 0x0C00 (1 `R_X86_64_JUMP_SLOT = 7` targeting `r_offset = 0x2018`)
    let rela_off = 0x0C00usize;
    if include_got_jump_slot {
        buf[rela_off..rela_off + 8].copy_from_slice(&0x2018u64.to_le_bytes());
        let r_info: u64 = (1u64 << 32) | 7u64;
        buf[rela_off + 8..rela_off + 16].copy_from_slice(&r_info.to_le_bytes());
        // Initial `.got.plt` pointer at `0x2018` pointing inside `.text` (`0x0400`)
        buf[0x2018..0x2020].copy_from_slice(&(text_off as u64).to_le_bytes());
    }

    // `.dynamic` at 0x2100
    let dynamic_off = 0x2100usize;
    let mut dyn_entries: Vec<(i64, u64)> = vec![
        (1, libc_name_off as u64), // DT_NEEDED = libc.so.6
        (5, dynstr_off as u64),    // DT_STRTAB
        (10, dynstr.len() as u64), // DT_STRSZ
    ];
    if let Some(rp_off) = rpath_off {
        dyn_entries.push((15, rp_off as u64)); // DT_RPATH = 15
    }
    dyn_entries.push((0, 0)); // DT_NULL
    for (idx, (tag, val)) in dyn_entries.iter().enumerate() {
        let base = dynamic_off + idx * 16;
        buf[base..base + 8].copy_from_slice(&tag.to_le_bytes());
        buf[base + 8..base + 16].copy_from_slice(&val.to_le_bytes());
    }
    let dynamic_len = dyn_entries.len() * 16;

    // `.shstrtab` at 0x0E00
    let shstr_off = 0x0E00usize;
    let shstr = b"\0.text\0.dynstr\0.dynsym\0.rela.plt\0.got.plt\0.dynamic\0.shstrtab\0";
    buf[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

    // 2 `PT_LOAD` program headers at `0x0040`: RX (`0x0..0x1000`) and RW (`0x2000..0x2800`)
    let phoff = 0x0040usize;
    write_phdr(&mut buf[phoff..phoff + 56], 1, 5, 0, 0, 0x1000);
    write_phdr(
        &mut buf[phoff + 56..phoff + 112],
        1,
        6,
        0x2000,
        0x2000,
        0x0800,
    );

    // 8 Section Headers at `0x2800`
    let shoff = 0x2800usize;
    let text_len = (exported_symbols.len().max(1) * 64) as u64;
    write_shdr(&mut buf[shoff + 64..shoff + 128], 1, 1, 6, text_off as u64, text_len, 0, 0);
    write_shdr(
        &mut buf[shoff + 128..shoff + 192],
        7,
        3,
        2,
        dynstr_off as u64,
        dynstr.len() as u64,
        0,
        0,
    );
    write_shdr(
        &mut buf[shoff + 192..shoff + 256],
        15,
        11,
        2,
        dynsym_off as u64,
        dynsym_len as u64,
        2,
        24,
    );
    write_shdr(
        &mut buf[shoff + 256..shoff + 320],
        23,
        4,
        2,
        rela_off as u64,
        if include_got_jump_slot { 24 } else { 0 },
        3,
        24,
    );
    write_shdr(&mut buf[shoff + 320..shoff + 384], 33, 1, 3, 0x2000, 0x40, 0, 8);
    write_shdr(
        &mut buf[shoff + 384..shoff + 448],
        42,
        6,
        3,
        dynamic_off as u64,
        dynamic_len as u64,
        2,
        16,
    );
    write_shdr(
        &mut buf[shoff + 448..shoff + 512],
        51,
        3,
        0,
        shstr_off as u64,
        shstr.len() as u64,
        0,
        0,
    );

    // ELF64 Header at `0x0000`
    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    buf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[24..32].copy_from_slice(&(text_off as u64).to_le_bytes());
    buf[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
    buf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    buf[52..54].copy_from_slice(&64u16.to_le_bytes());
    buf[54..56].copy_from_slice(&56u16.to_le_bytes());
    buf[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum = 2
    buf[58..60].copy_from_slice(&64u16.to_le_bytes());
    buf[60..62].copy_from_slice(&8u16.to_le_bytes()); // e_shnum = 8
    buf[62..64].copy_from_slice(&7u16.to_le_bytes()); // e_shstrndx = 7

    buf
}

fn write_phdr(slot: &mut [u8], p_type: u32, p_flags: u32, offset: u64, vaddr: u64, size: u64) {
    slot[0..4].copy_from_slice(&p_type.to_le_bytes());
    slot[4..8].copy_from_slice(&p_flags.to_le_bytes());
    slot[8..16].copy_from_slice(&offset.to_le_bytes());
    slot[16..24].copy_from_slice(&vaddr.to_le_bytes());
    slot[24..32].copy_from_slice(&vaddr.to_le_bytes());
    slot[32..40].copy_from_slice(&size.to_le_bytes());
    slot[40..48].copy_from_slice(&size.to_le_bytes());
    slot[48..56].copy_from_slice(&0x1000u64.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn write_shdr(
    slot: &mut [u8],
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    off_and_va: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
) {
    slot[0..4].copy_from_slice(&sh_name.to_le_bytes());
    slot[4..8].copy_from_slice(&sh_type.to_le_bytes());
    slot[8..16].copy_from_slice(&sh_flags.to_le_bytes());
    slot[16..24].copy_from_slice(&off_and_va.to_le_bytes());
    slot[24..32].copy_from_slice(&off_and_va.to_le_bytes());
    slot[32..40].copy_from_slice(&sh_size.to_le_bytes());
    slot[40..44].copy_from_slice(&sh_link.to_le_bytes());
    slot[48..56].copy_from_slice(&8u64.to_le_bytes());
    slot[56..64].copy_from_slice(&sh_entsize.to_le_bytes());
}

// ============================================================================
// 3. Pure-Rust Python PEP 552 `.pyc` Bytecode Synthesizer
// ============================================================================

/// Builds a Python 3.11 (`magic = 3495`) PEP 552 timestamp-validated `.pyc` binary.
pub fn build_pep552_pyc_311(
    timestamp: u32,
    source_size: u32,
    func_name: &str,
    stub_return_true: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&3495u16.to_le_bytes());
    out.extend_from_slice(&[0x0d, 0x0a]);
    out.extend_from_slice(&0u32.to_le_bytes()); // bitfield = 0 (timestamp mode)
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(&source_size.to_le_bytes());

    let fn_code: &[u8] = if stub_return_true {
        &[151, 0, 100, 1, 83, 0] // RESUME 0; LOAD_CONST 1 (True); RETURN_VALUE
    } else {
        &[151, 0, 124, 0, 83, 0] // RESUME 0; LOAD_FAST 0; RETURN_VALUE
    };

    let mut child = Vec::new();
    child.push(b'c');
    child.extend_from_slice(&2i32.to_le_bytes());
    child.extend_from_slice(&0i32.to_le_bytes());
    child.extend_from_slice(&0i32.to_le_bytes());
    child.extend_from_slice(&2i32.to_le_bytes());
    child.extend_from_slice(&67i32.to_le_bytes());
    write_marshal_bytes(&mut child, fn_code);
    child.push(b')');
    child.push(3);
    child.push(b'N');
    child.push(b'T');
    write_marshal_short_ascii(&mut child, "qa_const");
    child.push(b')');
    child.push(1);
    write_marshal_short_ascii(&mut child, "verify");
    child.push(b')');
    child.push(2);
    write_marshal_short_ascii(&mut child, "arg0");
    write_marshal_short_ascii(&mut child, "arg1");
    write_marshal_bytes(&mut child, &[0x20, 0x20]);
    write_marshal_short_ascii(&mut child, "/opt/cyops-licensing/validator.py");
    write_marshal_short_ascii(&mut child, func_name);
    write_marshal_short_ascii(&mut child, func_name);
    child.extend_from_slice(&10i32.to_le_bytes());
    write_marshal_bytes(&mut child, &[]);
    write_marshal_bytes(&mut child, &[]);

    out.push(b'c');
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&1i32.to_le_bytes());
    out.extend_from_slice(&64i32.to_le_bytes());
    write_marshal_bytes(&mut out, &[151, 0, 100, 1, 83, 0]);
    out.push(b')');
    out.push(2);
    out.extend_from_slice(&child);
    out.push(b'N');
    out.push(b')');
    out.push(0);
    out.push(b')');
    out.push(0);
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

// ============================================================================
// 4. Pure-Rust RFC 5280 ASN.1 DER & PEM X.509v3 Certificate Synthesizer
// ============================================================================

/// Builds a pure-Rust RFC 5280 ASN.1 DER X.509v3 self-signed certificate wrapped in PEM.
/// `spki_seed` deterministically selects the synthetic 2048-bit RSA public key bytes so
/// cloned appliances share identical SPKI SHA-256 while distinct roots differ.
pub fn build_x509v3_self_signed_pem(
    serial_bytes: &[u8],
    org: &str,
    cn: &str,
    is_ca: bool,
    san_dns: Option<&str>,
    spki_seed: u8,
) -> String {
    // OID sha256WithRSAEncryption: 1.2.840.113549.1.1.11
    let oid_sha256_rsa = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    // OID rsaEncryption: 1.2.840.113549.1.1.1
    let oid_rsa_enc = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    // OID organizationName (O): 2.5.4.10 -> 55 04 0a
    let oid_org = &[0x55, 0x04, 0x0a];
    // OID commonName (CN): 2.5.4.3 -> 55 04 03
    let oid_cn = &[0x55, 0x04, 0x03];
    // OID basicConstraints: 2.5.29.19 -> 55 1d 13
    let oid_bc = &[0x55, 0x1d, 0x13];
    // OID subjectAltName: 2.5.29.17 -> 55 1d 11
    let oid_san = &[0x55, 0x1d, 0x11];

    let sig_alg = der_tlv(
        0x30,
        &concat_slices(&[&der_tlv(0x06, oid_sha256_rsa), &[0x05, 0x00]]),
    );

    let name_rdn = build_x509_name_der(oid_org, org, oid_cn, cn);

    let validity = der_tlv(
        0x30,
        &concat_slices(&[
            &der_tlv(0x17, b"250101000000Z"),
            &der_tlv(0x17, b"350101000000Z"),
        ]),
    );

    // Deterministic 2048-bit RSAPublicKey stub inside SubjectPublicKeyInfo BIT STRING
    let mut modulus = vec![0x00u8; 257];
    modulus[1] = 0xc0 | (spki_seed & 0x3f);
    for (idx, b) in modulus[2..256].iter_mut().enumerate() {
        *b = spki_seed.wrapping_mul(31).wrapping_add(idx as u8);
    }
    modulus[256] = 0x01;
    let rsa_pub_seq = der_tlv(
        0x30,
        &concat_slices(&[
            &der_tlv(0x02, &modulus),
            &der_tlv(0x02, &[0x01, 0x00, 0x01]), // e = 65537
        ]),
    );
    let mut spki_bits = Vec::with_capacity(1 + rsa_pub_seq.len());
    spki_bits.push(0x00); // 0 unused bits
    spki_bits.extend_from_slice(&rsa_pub_seq);
    let spki = der_tlv(
        0x30,
        &concat_slices(&[
            &der_tlv(
                0x30,
                &concat_slices(&[&der_tlv(0x06, oid_rsa_enc), &[0x05, 0x00]]),
            ),
            &der_tlv(0x03, &spki_bits),
        ]),
    );

    // Extensions
    let mut ext_list = Vec::new();
    let bc_val = if is_ca {
        der_tlv(0x30, &[0x01, 0x01, 0xff]) // SEQUENCE { BOOLEAN TRUE }
    } else {
        der_tlv(0x30, &[])
    };
    let bc_ext = der_tlv(
        0x30,
        &concat_slices(&[
            &der_tlv(0x06, oid_bc),
            &[0x01, 0x01, 0xff], // critical = TRUE
            &der_tlv(0x04, &bc_val),
        ]),
    );
    ext_list.extend_from_slice(&bc_ext);

    if let Some(dns) = san_dns {
        let san_seq = der_tlv(0x30, &der_tlv(0x82, dns.as_bytes())); // [2] dNSName
        let san_ext = der_tlv(
            0x30,
            &concat_slices(&[&der_tlv(0x06, oid_san), &der_tlv(0x04, &san_seq)]),
        );
        ext_list.extend_from_slice(&san_ext);
    }
    let extensions_explicit = der_tlv(0xa3, &der_tlv(0x30, &ext_list));

    // Positive INTEGER serial encoding
    let mut serial_pos = Vec::with_capacity(serial_bytes.len() + 1);
    if serial_bytes.first().map(|b| (b & 0x80) != 0).unwrap_or(true) {
        serial_pos.push(0x00);
    }
    serial_pos.extend_from_slice(serial_bytes);

    let version_v3 = der_tlv(0xa0, &der_tlv(0x02, &[0x02]));
    let tbs = der_tlv(
        0x30,
        &concat_slices(&[
            &version_v3,
            &der_tlv(0x02, &serial_pos),
            &sig_alg,
            &name_rdn,
            &validity,
            &name_rdn,
            &spki,
            &extensions_explicit,
        ]),
    );

    let mut sig_bits = vec![0x00u8; 257];
    for (idx, b) in sig_bits[1..].iter_mut().enumerate() {
        *b = spki_seed.wrapping_add(idx as u8);
    }
    let cert_der = der_tlv(
        0x30,
        &concat_slices(&[&tbs, &sig_alg, &der_tlv(0x03, &sig_bits)]),
    );

    encode_pem_certificate(&cert_der)
}

fn build_x509_name_der(oid_org: &[u8], org: &str, oid_cn: &[u8], cn: &str) -> Vec<u8> {
    let ava_org = der_tlv(
        0x30,
        &concat_slices(&[&der_tlv(0x06, oid_org), &der_tlv(0x0c, org.as_bytes())]),
    );
    let ava_cn = der_tlv(
        0x30,
        &concat_slices(&[&der_tlv(0x06, oid_cn), &der_tlv(0x0c, cn.as_bytes())]),
    );
    der_tlv(
        0x30,
        &concat_slices(&[&der_tlv(0x31, &ava_org), &der_tlv(0x31, &ava_cn)]),
    )
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let len = value.len();
    let mut out = Vec::with_capacity(6 + len);
    out.push(tag);
    if len < 128 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    }
    out.extend_from_slice(value);
    out
}

fn concat_slices(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut out = Vec::with_capacity(total);
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

fn encode_pem_certificate(der: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::with_capacity((der.len() * 4) / 3 + 16);
    let mut i = 0usize;
    while i < der.len() {
        let b0 = der[i];
        let b1 = if i + 1 < der.len() { der[i + 1] } else { 0 };
        let b2 = if i + 2 < der.len() { der[i + 2] } else { 0 };

        b64.push(B64[(b0 >> 2) as usize] as char);
        b64.push(B64[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < der.len() {
            b64.push(B64[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            b64.push('=');
        }
        if i + 2 < der.len() {
            b64.push(B64[(b2 & 0x3f) as usize] as char);
        } else {
            b64.push('=');
        }
        i += 3;
    }

    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

// ============================================================================
// 5. PostgreSQL `pg_control`, EXT4/XFS Superblocks & `wtmp` Synthesizers
// ============================================================================

/// Builds an 8192-byte PostgreSQL 15/16 `pg_control` binary with valid Castagnoli CRC-32C.
pub fn build_pg_control_8192(system_id: u64, control_ts_unix: i64) -> Vec<u8> {
    let mut buf = vec![0u8; PG_CONTROL_FILE_SIZE];
    buf[0..8].copy_from_slice(&system_id.to_le_bytes());
    buf[8..12].copy_from_slice(&1300u32.to_le_bytes());
    buf[12..16].copy_from_slice(&202307071u32.to_le_bytes());
    buf[16..20].copy_from_slice(&1u32.to_le_bytes());
    buf[24..32].copy_from_slice(&control_ts_unix.to_le_bytes());
    buf[32..40].copy_from_slice(&0x0000_0001_0200_0098u64.to_le_bytes());
    let crc = crc32c(&buf[..288]);
    buf[288..292].copy_from_slice(&crc.to_le_bytes());
    buf
}

/// Builds a 4096-byte raw EXT4 superblock header (`0xEF53` at `1024 + 0x38`).
pub fn build_ext4_superblock_4096(
    uuid: [u8; 16],
    mkfs_ts: u32,
    wtime_ts: u32,
    label: &str,
) -> Vec<u8> {
    let mut img = vec![0u8; 4096];
    let sb = &mut img[1024..];
    sb[0x2C..0x30].copy_from_slice(&wtime_ts.to_le_bytes());
    sb[0x30..0x34].copy_from_slice(&wtime_ts.to_le_bytes());
    sb[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    sb[0x68..0x78].copy_from_slice(&uuid);
    let lbl = label.as_bytes();
    sb[0x78..0x78 + lbl.len().min(16)].copy_from_slice(&lbl[..lbl.len().min(16)]);
    sb[0x88..0x89].copy_from_slice(b"/");
    sb[0x108..0x10C].copy_from_slice(&mkfs_ts.to_le_bytes());
    img
}

/// Builds a 4096-byte raw XFS v5 superblock header (`"XFSB"` at `0x00`).
pub fn build_xfs_v5_superblock_4096(uuid: [u8; 16], meta_uuid: [u8; 16], label: &str) -> Vec<u8> {
    let mut img = vec![0u8; 4096];
    img[0..4].copy_from_slice(&0x5846_5342u32.to_be_bytes());
    img[4..8].copy_from_slice(&4096u32.to_be_bytes());
    img[0x20..0x30].copy_from_slice(&uuid);
    img[0x64..0x66].copy_from_slice(&0xB4A5u16.to_be_bytes());
    let lbl = label.as_bytes();
    img[0x6C..0x6C + lbl.len().min(12)].copy_from_slice(&lbl[..lbl.len().min(12)]);
    img[0x140..0x150].copy_from_slice(&meta_uuid);
    img
}

/// Builds a 384-byte `x86_64` Linux `utmp`/`wtmp` binary record.
pub fn build_wtmp_record_x86_64(
    ut_type: i16,
    pid: i32,
    user: &str,
    tv_sec: u32,
) -> [u8; WTMP_RECORD_SIZE_X86_64] {
    let mut rec = [0u8; WTMP_RECORD_SIZE_X86_64];
    rec[0..2].copy_from_slice(&ut_type.to_le_bytes());
    rec[4..8].copy_from_slice(&pid.to_le_bytes());
    let ub = user.as_bytes();
    rec[44..44 + ub.len().min(31)].copy_from_slice(&ub[..ub.len().min(31)]);
    rec[WTMP_TV_SEC_OFFSET..WTMP_TV_SEC_OFFSET + 4].copy_from_slice(&tv_sec.to_le_bytes());
    rec
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsr_deep_audit::rpm_forensics::{extract_blobs_from_rpmdb_sqlite, parse_rpm_header_blob};
    use fsr_net_crypto_audit::asn1_x509::{extract_pem_certificates, parse_x509_der};

    #[test]
    fn test_pure_rust_sqlite3_rpmdb_and_x509_der_synthesizers() {
        // 1. Test SQLite3 rpmdb with both inline and 12 KB overflow RPM blobs
        let b1 = build_rpm_v4_header_blob(
            "cyops-core",
            "7.6.0",
            "1.el9",
            Some(QA_FORTINET_PGP_KEY_ID),
            "/opt/cyops-core/",
            &[(
                "engine.py",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                0,
            )],
            0,
        );
        let b2 = build_rpm_v4_header_blob(
            "cyops-licensing",
            "7.6.0",
            "1.el9",
            Some(QA_FORTINET_PGP_KEY_ID),
            "/opt/cyops-licensing/",
            &[],
            12_000, // Forces multi-page SQLite3 overflow chain
        );
        let sqlite_bytes = build_sqlite3_rpmdb_bytes(&[b1.clone(), b2.clone()]);
        let extracted = extract_blobs_from_rpmdb_sqlite(&sqlite_bytes).unwrap();
        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0], b1);
        assert_eq!(extracted[1], b2);
        assert_eq!(parse_rpm_header_blob(&extracted[0]).unwrap().name, "cyops-core");

        // 2. Test pure-Rust X.509v3 PEM/DER generator against `parse_x509_der`
        let pem = build_x509v3_self_signed_pem(
            &[0x01, 0x02, 0x03, 0x04],
            "DigiCert Inc",
            "DigiCert Global Root G2",
            true,
            None,
            0x42,
        );
        let ders = extract_pem_certificates(&pem);
        assert_eq!(ders.len(), 1);
        let info = parse_x509_der(&ders[0]).unwrap();
        assert_eq!(info.version, 3);
        assert!(info.is_self_signed);
        assert!(info.basic_constraints_ca);
        assert_eq!(info.subject_cn.as_deref(), Some("DigiCert Global Root G2"));
        assert_eq!(info.subject_org.as_deref(), Some("DigiCert Inc"));
    }
}
