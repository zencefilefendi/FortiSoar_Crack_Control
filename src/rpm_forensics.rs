//! Engine 4: RPM Binary Integrity, Pure-Rust SQLite/BDB `rpmdb` Reader & Header Verifier.
//!
//! Audits `/usr/bin/rpm` itself (SHA-256 + ELF64 `.dynamic` `DT_NEEDED`/`DT_RPATH`/`DT_RUNPATH`),
//! reads `cyops-*` Header blobs directly from `/var/lib/rpm/rpmdb.sqlite` (SQLite3 B-Tree +
//! overflow chains), `/var/lib/rpm/Packages.db` (NDB), or `/var/lib/rpm/Packages` (Berkeley DB)
//! without invoking `/usr/bin/rpm`, validates Fortinet RSA/PGP signature tags
//! (`RPMTAG_RSAHEADER = 268`, `RPMTAG_SIGPGP = 259`), and verifies every installed file's
//! live SHA-256 digest against `RPMTAG_FILEDIGESTS` (`1035`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::{hex_digests_equal, hex_encode, sha256_file, sha256_hex};
use crate::elf_vma_diff::parse_elf64_bytes;
use crate::hw_integrity::{join_rooted, raw_syscall_read_file};
use crate::schema::{EngineId, Finding, JsonValue, Severity};

/// RPM Header Tag Constants (`rpmtag.h`).
pub const RPMTAG_SIGPGP: i32 = 259;
pub const RPMTAG_DSAHEADER: i32 = 267;
pub const RPMTAG_RSAHEADER: i32 = 268;
pub const RPMTAG_NAME: i32 = 1000;
pub const RPMTAG_VERSION: i32 = 1001;
pub const RPMTAG_RELEASE: i32 = 1002;
pub const RPMTAG_VENDOR: i32 = 1011;
pub const RPMTAG_ARCH: i32 = 1022;
pub const RPMTAG_OLDFILENAMES: i32 = 1027;
pub const RPMTAG_FILEMODES: i32 = 1030;
pub const RPMTAG_FILEDIGESTS: i32 = 1035;
pub const RPMTAG_FILEFLAGS: i32 = 1037;
pub const RPMTAG_DIRINDEXES: i32 = 1116;
pub const RPMTAG_BASENAMES: i32 = 1117;
pub const RPMTAG_DIRNAMES: i32 = 1118;
pub const RPMTAG_FILEDIGESTALGO: i32 = 5011;

/// RPM Header Index Data Types.
const RPM_INT16_TYPE: u32 = 3;
const RPM_INT32_TYPE: u32 = 4;
const RPM_STRING_TYPE: u32 = 6;
const RPM_BIN_TYPE: u32 = 7;
const RPM_STRING_ARRAY_TYPE: u32 = 8;
const RPM_I18NSTRING_TYPE: u32 = 9;

/// RPM File Attribute Flags (`rpmvf.h`).
const RPMFILE_CONFIG: u32 = 1 << 0;
const RPMFILE_GHOST: u32 = 1 << 6;

/// POSIX `st_mode` file type bitmask for `RPMTAG_FILEMODES`.
const S_IFMT: u16 = 0o170000;
const S_IFREG: u16 = 0o100000;

const RPM_HEADER_MAGIC: [u8; 8] = [0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00];

/// Parsed OpenPGP Tag-2 Signature Packet metadata from `RPMTAG_RSAHEADER` / `RPMTAG_SIGPGP`.
#[derive(Debug, Clone)]
pub struct PgpSignatureInfo {
    pub version: u8,
    pub pubkey_algo: u8,
    pub hash_algo: u8,
    pub issuer_key_id_hex: Option<String>,
}

/// File entry reconstructed from RPM Header `DIRINDEXES` + `DIRNAMES` + `BASENAMES` + `FILEDIGESTS`.
#[derive(Debug, Clone)]
pub struct RpmFileRecord {
    pub path: String,
    pub sha256_digest: String,
    pub flags: u32,
    pub mode: Option<u16>,
}

/// Parsed RPM v4 Package Header.
#[derive(Debug, Clone)]
pub struct RpmPackageHeader {
    pub name: String,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub vendor: Option<String>,
    pub rsa_header_blob: Option<Vec<u8>>,
    pub sig_pgp_blob: Option<Vec<u8>>,
    pub dsa_header_blob: Option<Vec<u8>>,
    pub digest_algo: u32,
    pub files: Vec<RpmFileRecord>,
}

impl RpmPackageHeader {
    pub fn nevra(&self) -> String {
        format!(
            "{}-{}-{}.{}",
            self.name,
            self.version,
            self.release,
            if self.arch.is_empty() {
                "noarch"
            } else {
                &self.arch
            }
        )
    }
}

/// Parses a raw RPM v4 Header blob (with or without the 8-byte `8e ad e8 01` magic prefix).
pub fn parse_rpm_header_blob(blob: &[u8]) -> Result<RpmPackageHeader, String> {
    if blob.len() < 24 {
        return Err("RPM header blob shorter than 24 bytes".to_string());
    }

    let hdr_off = if blob.starts_with(&RPM_HEADER_MAGIC) {
        8usize
    } else {
        0usize
    };

    if blob.len() < hdr_off + 8 {
        return Err("truncated RPM header counts".to_string());
    }

    let index_len = u32::from_be_bytes(blob[hdr_off..hdr_off + 4].try_into().unwrap()) as usize;
    let data_len = u32::from_be_bytes(blob[hdr_off + 4..hdr_off + 8].try_into().unwrap()) as usize;

    if index_len == 0 || index_len > 262_144 {
        return Err(format!("invalid RPM header index count {}", index_len));
    }
    let idx_bytes = index_len
        .checked_mul(16)
        .ok_or_else(|| "RPM index size overflow".to_string())?;
    let store_start = hdr_off
        .checked_add(8)
        .and_then(|v| v.checked_add(idx_bytes))
        .ok_or_else(|| "RPM store offset overflow".to_string())?;
    let store_end = store_start
        .checked_add(data_len)
        .ok_or_else(|| "RPM store end overflow".to_string())?;

    if store_end > blob.len() {
        return Err(format!(
            "RPM header store end {} exceeds blob size {}",
            store_end,
            blob.len()
        ));
    }

    let index_slice = &blob[hdr_off + 8..store_start];
    let store = &blob[store_start..store_end];

    let mut name = String::new();
    let mut version = String::new();
    let mut release = String::new();
    let mut arch = String::new();
    let mut vendor = None;
    let mut rsa_header_blob = None;
    let mut sig_pgp_blob = None;
    let mut dsa_header_blob = None;
    let mut digest_algo = 1u32; // Default MD5 unless RPMTAG_FILEDIGESTALGO (5011) specifies 8 (SHA-256)

    let mut dir_indexes: Vec<u32> = Vec::new();
    let mut base_names: Vec<String> = Vec::new();
    let mut dir_names: Vec<String> = Vec::new();
    let mut old_filenames: Vec<String> = Vec::new();
    let mut file_digests: Vec<String> = Vec::new();
    let mut file_flags: Vec<u32> = Vec::new();
    let mut file_modes: Vec<u16> = Vec::new();

    for i in 0..index_len {
        let e = &index_slice[i * 16..(i + 1) * 16];
        let tag = i32::from_be_bytes([e[0], e[1], e[2], e[3]]);
        let dtype = u32::from_be_bytes([e[4], e[5], e[6], e[7]]);
        let offset_raw = i32::from_be_bytes([e[8], e[9], e[10], e[11]]);
        let count = u32::from_be_bytes([e[12], e[13], e[14], e[15]]) as usize;

        if offset_raw < 0 || (offset_raw as usize) > store.len() {
            continue;
        }
        let offset = offset_raw as usize;

        match (tag, dtype) {
            (RPMTAG_NAME, RPM_STRING_TYPE) => name = read_rpm_cstr(store, offset),
            (RPMTAG_VERSION, RPM_STRING_TYPE) => version = read_rpm_cstr(store, offset),
            (RPMTAG_RELEASE, RPM_STRING_TYPE) => release = read_rpm_cstr(store, offset),
            (RPMTAG_ARCH, RPM_STRING_TYPE) => arch = read_rpm_cstr(store, offset),
            (RPMTAG_VENDOR, RPM_STRING_TYPE | RPM_I18NSTRING_TYPE | RPM_STRING_ARRAY_TYPE) => {
                let v = read_rpm_cstr(store, offset);
                if !v.is_empty() {
                    vendor = Some(v);
                }
            }
            (RPMTAG_RSAHEADER, RPM_BIN_TYPE) => {
                if let Some(b) = store.get(offset..offset.saturating_add(count)) {
                    rsa_header_blob = Some(b.to_vec());
                }
            }
            (RPMTAG_SIGPGP, RPM_BIN_TYPE) => {
                if let Some(b) = store.get(offset..offset.saturating_add(count)) {
                    sig_pgp_blob = Some(b.to_vec());
                }
            }
            (RPMTAG_DSAHEADER, RPM_BIN_TYPE) => {
                if let Some(b) = store.get(offset..offset.saturating_add(count)) {
                    dsa_header_blob = Some(b.to_vec());
                }
            }
            (RPMTAG_FILEDIGESTALGO, RPM_INT32_TYPE) if count >= 1 => {
                if let Some(b) = store.get(offset..offset + 4) {
                    digest_algo = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                }
            }
            (RPMTAG_DIRINDEXES, RPM_INT32_TYPE) => {
                dir_indexes = read_rpm_u32_array(store, offset, count);
            }
            (RPMTAG_BASENAMES, RPM_STRING_ARRAY_TYPE) => {
                base_names = read_rpm_string_array(store, offset, count);
            }
            (RPMTAG_DIRNAMES, RPM_STRING_ARRAY_TYPE) => {
                dir_names = read_rpm_string_array(store, offset, count);
            }
            (RPMTAG_OLDFILENAMES, RPM_STRING_ARRAY_TYPE) => {
                old_filenames = read_rpm_string_array(store, offset, count);
            }
            (RPMTAG_FILEDIGESTS, RPM_STRING_ARRAY_TYPE) => {
                file_digests = read_rpm_string_array(store, offset, count);
            }
            (RPMTAG_FILEFLAGS, RPM_INT32_TYPE) => {
                file_flags = read_rpm_u32_array(store, offset, count);
            }
            (RPMTAG_FILEMODES, RPM_INT16_TYPE) => {
                file_modes = read_rpm_u16_array(store, offset, count);
            }
            _ => {}
        }
    }

    if name.is_empty() {
        return Err("RPM header missing RPMTAG_NAME (1000)".to_string());
    }

    let full_paths: Vec<String> = if !base_names.is_empty() && base_names.len() == dir_indexes.len()
    {
        base_names
            .iter()
            .enumerate()
            .map(|(idx, base)| {
                let d_idx = dir_indexes[idx] as usize;
                let dir = dir_names.get(d_idx).map(|s| s.as_str()).unwrap_or("/");
                format!("{}{}", dir, base)
            })
            .collect()
    } else {
        old_filenames
    };

    let mut files = Vec::with_capacity(full_paths.len());
    for (i, path) in full_paths.into_iter().enumerate() {
        let sha256_digest = file_digests.get(i).cloned().unwrap_or_default();
        let flags = file_flags.get(i).copied().unwrap_or(0);
        let mode = file_modes.get(i).copied();
        files.push(RpmFileRecord {
            path,
            sha256_digest,
            flags,
            mode,
        });
    }

    // Infer SHA-256 if digests are 64 hex chars even when tag 5011 is omitted
    if digest_algo == 1 && files.iter().any(|f| f.sha256_digest.len() == 64) {
        digest_algo = 8;
    }

    Ok(RpmPackageHeader {
        name,
        version,
        release,
        arch,
        vendor,
        rsa_header_blob,
        sig_pgp_blob,
        dsa_header_blob,
        digest_algo,
        files,
    })
}

fn read_rpm_cstr(store: &[u8], offset: usize) -> String {
    let Some(slice) = store.get(offset..) else {
        return String::new();
    };
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

fn read_rpm_string_array(store: &[u8], mut offset: usize, count: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        if offset >= store.len() {
            break;
        }
        let slice = &store[offset..];
        let nul_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        out.push(String::from_utf8_lossy(&slice[..nul_pos]).into_owned());
        offset = offset.saturating_add(nul_pos + 1);
    }
    out
}

fn read_rpm_u32_array(store: &[u8], offset: usize, count: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(count.min(4096));
    let Some(slice) = store.get(offset..) else {
        return out;
    };
    for i in 0..count {
        let Some(b) = slice.get(i * 4..i * 4 + 4) else {
            break;
        };
        out.push(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    }
    out
}

fn read_rpm_u16_array(store: &[u8], offset: usize, count: usize) -> Vec<u16> {
    let mut out = Vec::with_capacity(count.min(4096));
    let Some(slice) = store.get(offset..) else {
        return out;
    };
    for i in 0..count {
        let Some(b) = slice.get(i * 2..i * 2 + 2) else {
            break;
        };
        out.push(u16::from_be_bytes([b[0], b[1]]));
    }
    out
}

/// Validates an RFC 4880 OpenPGP Tag-2 Signature Packet inside `RPMTAG_RSAHEADER` / `RPMTAG_SIGPGP`.
pub fn parse_openpgp_signature_packet(sig: &[u8]) -> Option<PgpSignatureInfo> {
    if sig.len() < 8 || (sig[0] & 0x80) == 0 {
        return None;
    }

    let (pkt_tag, body_off, body_len) = if (sig[0] & 0x40) != 0 {
        // New-format OpenPGP packet header
        let tag = sig[0] & 0x3f;
        let b1 = *sig.get(1)?;
        if b1 < 192 {
            (tag, 2usize, b1 as usize)
        } else if b1 < 224 {
            let b2 = *sig.get(2)?;
            let len = (((b1 as usize) - 192) << 8) + (b2 as usize) + 192;
            (tag, 3usize, len)
        } else if b1 == 255 {
            let l = u32::from_be_bytes(sig.get(2..6)?.try_into().ok()?) as usize;
            (tag, 6usize, l)
        } else {
            return None;
        }
    } else {
        // Old-format OpenPGP packet header (standard for RPM RSAHEADER)
        let tag = (sig[0] & 0x3c) >> 2;
        match sig[0] & 0x03 {
            0 => (tag, 2usize, *sig.get(1)? as usize),
            1 => {
                let l = u16::from_be_bytes([*sig.get(1)?, *sig.get(2)?]) as usize;
                (tag, 3usize, l)
            }
            2 => {
                let l = u32::from_be_bytes(sig.get(1..5)?.try_into().ok()?) as usize;
                (tag, 5usize, l)
            }
            _ => (tag, 1usize, sig.len().saturating_sub(1)),
        }
    };

    if pkt_tag != 2 {
        return None;
    }
    let body_end = body_off.saturating_add(body_len).min(sig.len());
    let body = sig.get(body_off..body_end)?;
    if body.len() < 6 {
        return None;
    }

    let version = body[0];
    match version {
        4 => {
            let pubkey_algo = *body.get(2)?;
            let hash_algo = *body.get(3)?;
            let hashed_len = u16::from_be_bytes([*body.get(4)?, *body.get(5)?]) as usize;
            let mut pos = 6usize;
            let mut issuer_key_id = None;

            if let Some(hashed_sub) = body.get(pos..pos.saturating_add(hashed_len)) {
                issuer_key_id = extract_pgp_issuer_from_subpackets(hashed_sub);
            }
            pos = pos.saturating_add(hashed_len);

            if issuer_key_id.is_none() {
                if let Some(unhashed_hdr) = body.get(pos..pos + 2) {
                    let unhashed_len = u16::from_be_bytes([unhashed_hdr[0], unhashed_hdr[1]]) as usize;
                    if let Some(unhashed_sub) = body.get(pos + 2..pos + 2 + unhashed_len) {
                        issuer_key_id = extract_pgp_issuer_from_subpackets(unhashed_sub);
                    }
                }
            }

            Some(PgpSignatureInfo {
                version,
                pubkey_algo,
                hash_algo,
                issuer_key_id_hex: issuer_key_id,
            })
        }
        3 => {
            if body.len() < 19 || body[1] != 5 {
                return None;
            }
            let key_id = hex_encode(&body[7..15]);
            let pubkey_algo = body[15];
            let hash_algo = body[16];
            Some(PgpSignatureInfo {
                version,
                pubkey_algo,
                hash_algo,
                issuer_key_id_hex: Some(key_id),
            })
        }
        _ => None,
    }
}

fn extract_pgp_issuer_from_subpackets(mut sub: &[u8]) -> Option<String> {
    let mut found = None;
    while !sub.is_empty() {
        let b0 = sub[0];
        let (hdr_bytes, sub_len) = if b0 < 192 {
            (1usize, b0 as usize)
        } else if b0 < 255 {
            if sub.len() < 2 {
                break;
            }
            (2usize, (((b0 as usize) - 192) << 8) + (sub[1] as usize) + 192)
        } else {
            if sub.len() < 5 {
                break;
            }
            let l = u32::from_be_bytes([sub[1], sub[2], sub[3], sub[4]]) as usize;
            (5usize, l)
        };

        if sub_len == 0 || sub.len() < hdr_bytes + sub_len {
            break;
        }
        let sp_type = sub[hdr_bytes] & 0x7f;
        let sp_data = &sub[hdr_bytes + 1..hdr_bytes + sub_len];

        if sp_type == 16 && sp_data.len() == 8 {
            // Subpacket 16: 8-byte Issuer Key ID
            found = Some(hex_encode(sp_data));
        } else if sp_type == 33 && sp_data.len() >= 21 && sp_data[0] == 4 {
            // Subpacket 33: v4 Issuer Fingerprint (trailing 8 bytes equal Key ID)
            found = Some(hex_encode(&sp_data[sp_data.len() - 8..]));
        }

        sub = &sub[hdr_bytes + sub_len..];
    }
    found
}

// ============================================================================
// Pure-Rust SQLite3 B-Tree + Overflow Reader for `/var/lib/rpm/rpmdb.sqlite`
// ============================================================================

#[derive(Debug, Clone)]
enum SqlValue {
    Null,
    Int(i64),
    Text(String),
    Blob(Vec<u8>),
}

/// Extracts all raw RPM Header blobs from the `Packages` table of an `rpmdb.sqlite` file.
pub fn extract_blobs_from_rpmdb_sqlite(db: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if db.len() < 100 || &db[0..16] != b"SQLite format 3\0" {
        return Err("invalid SQLite3 file header magic".to_string());
    }

    let raw_ps = u16::from_be_bytes([db[16], db[17]]);
    let page_size: usize = if raw_ps == 1 { 65536 } else { raw_ps as usize };
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(format!("invalid SQLite3 page size {}", page_size));
    }
    let reserved = db[20] as usize;
    let usable_size = page_size.saturating_sub(reserved);
    if usable_size < 480 {
        return Err("invalid SQLite3 usable page size".to_string());
    }

    // 1. Walk `sqlite_schema` (rooted at Page 1) to locate `Packages` table rootpage
    let mut schema_rows = Vec::new();
    let mut visited_schema = BTreeSet::new();
    walk_sqlite_table_btree(
        db,
        1,
        page_size,
        usable_size,
        &mut visited_schema,
        &mut schema_rows,
    )?;

    let mut packages_rootpage: Option<u32> = None;
    for row in &schema_rows {
        // sqlite_schema columns: (type, name, tbl_name, rootpage, sql)
        let Some(SqlValue::Text(kind)) = row.first() else {
            continue;
        };
        if !kind.eq_ignore_ascii_case("table") {
            continue;
        }
        let tbl_name = match row.get(2).or_else(|| row.get(1)) {
            Some(SqlValue::Text(s)) => s.as_str(),
            _ => continue,
        };
        if tbl_name.eq_ignore_ascii_case("Packages") {
            if let Some(SqlValue::Int(rp)) = row.get(3) {
                if *rp > 0 {
                    packages_rootpage = Some(*rp as u32);
                    break;
                }
            }
        }
    }

    let root_pg = packages_rootpage
        .ok_or_else(|| "SQLite3 rpmdb missing `Packages` table in sqlite_schema".to_string())?;

    // 2. Walk the `Packages` Table B-Tree and collect every `blob` column
    let mut pkg_rows = Vec::new();
    let mut visited_pkgs = BTreeSet::new();
    walk_sqlite_table_btree(
        db,
        root_pg,
        page_size,
        usable_size,
        &mut visited_pkgs,
        &mut pkg_rows,
    )?;

    let mut blobs = Vec::with_capacity(pkg_rows.len());
    for row in pkg_rows {
        for col in row {
            if let SqlValue::Blob(b) = col {
                if b.len() >= 24 {
                    blobs.push(b);
                    break;
                }
            }
        }
    }

    Ok(blobs)
}

fn walk_sqlite_table_btree(
    db: &[u8],
    page_num: u32,
    page_size: usize,
    usable_size: usize,
    visited: &mut BTreeSet<u32>,
    rows_out: &mut Vec<Vec<SqlValue>>,
) -> Result<(), String> {
    if page_num == 0 || !visited.insert(page_num) {
        return Ok(());
    }
    let page_off = (page_num as usize - 1)
        .checked_mul(page_size)
        .ok_or_else(|| "SQLite page offset overflow".to_string())?;
    let Some(page) = db.get(page_off..page_off.saturating_add(usable_size)) else {
        return Err(format!("SQLite page {} out of file bounds", page_num));
    };

    let hdr_off = if page_num == 1 { 100usize } else { 0usize };
    let Some(&page_type) = page.get(hdr_off) else {
        return Err("truncated SQLite B-Tree page header".to_string());
    };

    match page_type {
        0x05 => {
            // Table B-Tree Interior Page (12-byte header)
            if page.len() < hdr_off + 12 {
                return Err("truncated SQLite interior page header".to_string());
            }
            let cell_count =
                u16::from_be_bytes([page[hdr_off + 3], page[hdr_off + 4]]) as usize;
            let right_child = u32::from_be_bytes([
                page[hdr_off + 8],
                page[hdr_off + 9],
                page[hdr_off + 10],
                page[hdr_off + 11],
            ]);
            let ptr_base = hdr_off + 12;

            for i in 0..cell_count {
                let Some(ptr_bytes) = page.get(ptr_base + i * 2..ptr_base + i * 2 + 2) else {
                    break;
                };
                let cell_off = u16::from_be_bytes([ptr_bytes[0], ptr_bytes[1]]) as usize;
                let Some(child_bytes) = page.get(cell_off..cell_off + 4) else {
                    continue;
                };
                let left_child = u32::from_be_bytes([
                    child_bytes[0],
                    child_bytes[1],
                    child_bytes[2],
                    child_bytes[3],
                ]);
                walk_sqlite_table_btree(
                    db,
                    left_child,
                    page_size,
                    usable_size,
                    visited,
                    rows_out,
                )?;
            }

            walk_sqlite_table_btree(db, right_child, page_size, usable_size, visited, rows_out)?;
            Ok(())
        }
        0x0d => {
            // Table B-Tree Leaf Page (8-byte header)
            if page.len() < hdr_off + 8 {
                return Err("truncated SQLite leaf page header".to_string());
            }
            let cell_count =
                u16::from_be_bytes([page[hdr_off + 3], page[hdr_off + 4]]) as usize;
            let ptr_base = hdr_off + 8;

            let x_max = usable_size - 35;
            let m_min = ((usable_size - 12) * 32 / 255) - 23;

            for i in 0..cell_count {
                let Some(ptr_bytes) = page.get(ptr_base + i * 2..ptr_base + i * 2 + 2) else {
                    break;
                };
                let cell_off = u16::from_be_bytes([ptr_bytes[0], ptr_bytes[1]]) as usize;
                let Some(cell_tail) = page.get(cell_off..) else {
                    continue;
                };

                let Some((payload_len_u64, v1_len)) = read_sqlite_varint(cell_tail) else {
                    continue;
                };
                let payload_len = payload_len_u64 as usize;
                if payload_len > 64 * 1024 * 1024 {
                    continue;
                }
                let Some((_rowid, v2_len)) = read_sqlite_varint(&cell_tail[v1_len..]) else {
                    continue;
                };
                let data_start = v1_len + v2_len;

                let full_payload: Vec<u8> = if payload_len <= x_max {
                    let Some(s) = cell_tail.get(data_start..data_start + payload_len) else {
                        continue;
                    };
                    s.to_vec()
                } else {
                    let k = m_min + ((payload_len - m_min) % (usable_size - 4));
                    let local_len = if k <= x_max { k } else { m_min };
                    let Some(local_slice) = cell_tail.get(data_start..data_start + local_len + 4)
                    else {
                        continue;
                    };
                    let mut assembled = Vec::with_capacity(payload_len);
                    assembled.extend_from_slice(&local_slice[..local_len]);

                    let mut next_ovf = u32::from_be_bytes([
                        local_slice[local_len],
                        local_slice[local_len + 1],
                        local_slice[local_len + 2],
                        local_slice[local_len + 3],
                    ]);
                    let mut ovf_guard = 0usize;
                    while next_ovf != 0 && assembled.len() < payload_len && ovf_guard < 32_768 {
                        ovf_guard += 1;
                        let ovf_off = (next_ovf as usize - 1).saturating_mul(page_size);
                        let Some(ovf_page) = db.get(ovf_off..ovf_off.saturating_add(usable_size))
                        else {
                            break;
                        };
                        next_ovf = u32::from_be_bytes([
                            ovf_page[0],
                            ovf_page[1],
                            ovf_page[2],
                            ovf_page[3],
                        ]);
                        let remaining = payload_len - assembled.len();
                        let take = remaining.min(usable_size - 4);
                        assembled.extend_from_slice(&ovf_page[4..4 + take]);
                    }
                    if assembled.len() != payload_len {
                        continue;
                    }
                    assembled
                };

                if let Some(record) = parse_sqlite_record(&full_payload) {
                    rows_out.push(record);
                }
            }
            Ok(())
        }
        other => Err(format!(
            "unexpected SQLite B-Tree page flag 0x{:02x} on page {}",
            other, page_num
        )),
    }
}

fn parse_sqlite_record(payload: &[u8]) -> Option<Vec<SqlValue>> {
    let (hdr_size_u64, mut hdr_pos) = read_sqlite_varint(payload)?;
    let hdr_size = hdr_size_u64 as usize;
    if hdr_size > payload.len() {
        return None;
    }

    let mut serial_types = Vec::new();
    while hdr_pos < hdr_size {
        let (st, n) = read_sqlite_varint(&payload[hdr_pos..hdr_size])?;
        serial_types.push(st);
        hdr_pos += n;
    }

    let mut body_pos = hdr_size;
    let mut values = Vec::with_capacity(serial_types.len());

    for st in serial_types {
        match st {
            0 => values.push(SqlValue::Null),
            1 => {
                let b = *payload.get(body_pos)?;
                body_pos += 1;
                values.push(SqlValue::Int((b as i8) as i64));
            }
            2 => {
                let s = payload.get(body_pos..body_pos + 2)?;
                body_pos += 2;
                values.push(SqlValue::Int(i16::from_be_bytes([s[0], s[1]]) as i64));
            }
            3 => {
                let s = payload.get(body_pos..body_pos + 3)?;
                body_pos += 3;
                let sign = if (s[0] & 0x80) != 0 { 0xffu8 } else { 0x00u8 };
                values.push(SqlValue::Int(
                    i32::from_be_bytes([sign, s[0], s[1], s[2]]) as i64,
                ));
            }
            4 => {
                let s = payload.get(body_pos..body_pos + 4)?;
                body_pos += 4;
                values.push(SqlValue::Int(
                    i32::from_be_bytes([s[0], s[1], s[2], s[3]]) as i64,
                ));
            }
            5 => {
                let s = payload.get(body_pos..body_pos + 6)?;
                body_pos += 6;
                let hi = if (s[0] & 0x80) != 0 { 0xffu8 } else { 0x00u8 };
                values.push(SqlValue::Int(i64::from_be_bytes([
                    hi, hi, s[0], s[1], s[2], s[3], s[4], s[5],
                ])));
            }
            6 => {
                let s = payload.get(body_pos..body_pos + 8)?;
                body_pos += 8;
                values.push(SqlValue::Int(i64::from_be_bytes(s.try_into().ok()?)));
            }
            7 => {
                let _ = payload.get(body_pos..body_pos + 8)?;
                body_pos += 8;
                values.push(SqlValue::Null);
            }
            8 => values.push(SqlValue::Int(0)),
            9 => values.push(SqlValue::Int(1)),
            10 | 11 => return None,
            n if n >= 12 && (n % 2 == 0) => {
                let len = ((n - 12) / 2) as usize;
                let s = payload.get(body_pos..body_pos + len)?;
                body_pos += len;
                values.push(SqlValue::Blob(s.to_vec()));
            }
            n if n >= 13 => {
                let len = ((n - 13) / 2) as usize;
                let s = payload.get(body_pos..body_pos + len)?;
                body_pos += len;
                values.push(SqlValue::Text(String::from_utf8_lossy(s).into_owned()));
            }
            _ => return None,
        }
    }

    Some(values)
}

fn read_sqlite_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut acc = 0u64;
    for (i, &b) in buf.iter().take(9).enumerate() {
        if i == 8 {
            acc = (acc << 8) | (b as u64);
            return Some((acc, 9));
        }
        acc = (acc << 7) | ((b & 0x7f) as u64);
        if (b & 0x80) == 0 {
            return Some((acc, i + 1));
        }
    }
    None
}

// ============================================================================
// Pure-Rust RPM NDB (`Packages.db`) and RHEL 8 Berkeley DB (`Packages`) Readers
// ============================================================================

fn extract_blobs_from_ndb(db: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if db.len() < 32 {
        return Err("Packages.db too small".to_string());
    }
    // NDB Header Magic: 'R' | 'p'<<8 | 'm'<<16 | 'P'<<24
    if &db[0..4] != b"RpmP" {
        return Err("invalid NDB magic".to_string());
    }
    let slot_npages = u32::from_le_bytes([db[16], db[17], db[18], db[19]]) as usize;
    let slot_area_end = (slot_npages * 4096).min(db.len());
    let mut blobs = Vec::new();
    let mut pos = 32usize;

    while pos + 16 <= slot_area_end {
        if &db[pos..pos + 4] == b"Slot" {
            let pkg_idx = u32::from_le_bytes([db[pos + 4], db[pos + 5], db[pos + 6], db[pos + 7]]);
            let blk_off =
                u32::from_le_bytes([db[pos + 8], db[pos + 9], db[pos + 10], db[pos + 11]]) as usize
                    * 16;
            if pkg_idx != 0 && blk_off + 20 <= db.len() && &db[blk_off..blk_off + 4] == b"Blck" {
                let blob_len = u32::from_le_bytes([
                    db[blk_off + 8],
                    db[blk_off + 9],
                    db[blk_off + 10],
                    db[blk_off + 11],
                ]) as usize;
                if let Some(b) = db.get(blk_off + 16..blk_off + 16 + blob_len) {
                    blobs.push(b.to_vec());
                }
            }
        }
        pos += 16;
    }
    Ok(blobs)
}

/// Extracts RPM Header blobs from a RHEL 8 Berkeley DB Hash v8/v9 `Packages` file.
fn extract_blobs_from_bdb_packages(db: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if db.len() < 512 {
        return Err("Berkeley DB Packages file too small".to_string());
    }
    // BDB Hash magic 0x00061561 at offset 12 (LE or BE)
    let magic_le = u32::from_le_bytes([db[12], db[13], db[14], db[15]]);
    if magic_le != 0x0006_1561 {
        return Err("not a little-endian Berkeley DB Hash file".to_string());
    }
    let page_size = u32::from_le_bytes([db[20], db[21], db[22], db[23]]) as usize;
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err("invalid BDB page size".to_string());
    }

    let num_pages = db.len() / page_size;
    let mut blobs = Vec::new();

    // BDB Hash leaf/unsorted pages have page_type == 13 (P_HASH) or 2 (P_HASH_UNSORTED) at offset 25
    for pg in 1..num_pages {
        let p_off = pg * page_size;
        let page = &db[p_off..p_off + page_size];
        let ptype = page[25];
        if ptype != 13 && ptype != 2 {
            continue;
        }
        let entries = u16::from_le_bytes([page[20], page[21]]) as usize;
        // Entries come in (key, value) pairs; odd indices `1, 3, 5, ...` hold the RPM header values!
        let mut idx = 1usize;
        while idx < entries {
            let inp_off = 26 + idx * 2;
            if inp_off + 2 > page.len() {
                break;
            }
            let item_off = u16::from_le_bytes([page[inp_off], page[inp_off + 1]]) as usize;
            if let Some(&entry_type) = page.get(item_off) {
                match entry_type {
                    1 => {
                        // H_KEYDATA: inline value up to next lower offset on page
                        let prev_off = if idx == 0 {
                            page_size
                        } else {
                            let po = 26 + (idx - 1) * 2;
                            u16::from_le_bytes([page[po], page[po + 1]]) as usize
                        };
                        if prev_off > item_off + 1 && prev_off <= page.len() {
                            let val = &page[item_off + 1..prev_off];
                            if val.len() >= 24 {
                                blobs.push(val.to_vec());
                            }
                        }
                    }
                    3 => {
                        // H_OFFPAGE (12 bytes): [type=3, pad(3), pgno: u32 LE, tlen: u32 LE]
                        if let Some(ho) = page.get(item_off..item_off + 12) {
                            let mut ovf_pg =
                                u32::from_le_bytes([ho[4], ho[5], ho[6], ho[7]]) as usize;
                            let tlen =
                                u32::from_le_bytes([ho[8], ho[9], ho[10], ho[11]]) as usize;
                            if (24..=64 * 1024 * 1024).contains(&tlen) {
                                let mut assembled = Vec::with_capacity(tlen);
                                let mut guard = 0usize;
                                while ovf_pg > 0
                                    && ovf_pg < num_pages
                                    && assembled.len() < tlen
                                    && guard < 32_768
                                {
                                    guard += 1;
                                    let op = &db[ovf_pg * page_size..(ovf_pg + 1) * page_size];
                                    if op[25] != 7 {
                                        // P_OVERFLOW == 7
                                        break;
                                    }
                                    let next_pg =
                                        u32::from_le_bytes([op[16], op[17], op[18], op[19]])
                                            as usize;
                                    let chunk_len =
                                        u16::from_le_bytes([op[22], op[23]]) as usize;
                                    let avail = (page_size - 26).min(chunk_len);
                                    let take = avail.min(tlen - assembled.len());
                                    assembled.extend_from_slice(&op[26..26 + take]);
                                    ovf_pg = next_pg;
                                }
                                if assembled.len() == tlen {
                                    blobs.push(assembled);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            idx += 2;
        }
    }

    Ok(blobs)
}

/// Output of Engine 4 (`rpm_forensics`).
pub struct RpmForensicsResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 4 against `/usr/bin/rpm` and `/var/lib/rpm/` under `root`.
pub fn run_rpm_forensics_audit(root: &Path) -> RpmForensicsResult {
    let mut findings = Vec::new();

    // 1. Audit `/usr/bin/rpm` binary SHA-256 and dynamic ELF64 dependencies
    let rpm_bin_path = join_rooted(root, "usr/bin/rpm");
    let rpm_bin_report = audit_rpm_binary(root, &rpm_bin_path, &mut findings);

    // 2. Locate and parse the RPM database (`rpmdb.sqlite`, `Packages.db`, or `Packages`)
    let db_candidates: [(&str, &str); 4] = [
        ("sqlite", "var/lib/rpm/rpmdb.sqlite"),
        ("sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite"),
        ("ndb", "var/lib/rpm/Packages.db"),
        ("bdb", "var/lib/rpm/Packages"),
    ];

    let mut active_db_path = String::from("not_found");
    let mut active_db_format = String::from("none");
    let mut raw_blobs: Vec<Vec<u8>> = Vec::new();

    for (fmt, rel_path) in &db_candidates {
        let full = join_rooted(root, rel_path);
        let Some(bytes) = read_bytes_prefer_raw(&full) else {
            continue;
        };
        let parsed = match *fmt {
            "sqlite" => extract_blobs_from_rpmdb_sqlite(&bytes),
            "ndb" => extract_blobs_from_ndb(&bytes),
            "bdb" => extract_blobs_from_bdb_packages(&bytes),
            _ => continue,
        };
        match parsed {
            Ok(blobs) => {
                active_db_path = format!("/{}", rel_path);
                active_db_format = (*fmt).to_string();
                raw_blobs = blobs;
                break;
            }
            Err(err) => {
                findings.push(
                    Finding::new(
                        EngineId::RpmForensics,
                        "HIGH_RPMDB_CORRUPTED_OR_TAMPERED",
                        Severity::High,
                        format!("/{}", rel_path),
                        format!("Failed to parse RPM database /{}: {}", rel_path, err),
                    )
                    .with_evidence("backend", JsonValue::str(*fmt)),
                );
            }
        }
    }

    // 3. Parse RPM v4 headers, filter `cyops-*` (and `rpm` for self-verification)
    let mut cyops_packages: Vec<RpmPackageHeader> = Vec::new();
    let mut rpm_self_pkg: Option<RpmPackageHeader> = None;

    for blob in &raw_blobs {
        let Ok(pkg) = parse_rpm_header_blob(blob) else {
            continue;
        };
        if pkg.name == "cyops" || pkg.name.starts_with("cyops-") {
            cyops_packages.push(pkg);
        } else if pkg.name == "rpm" {
            rpm_self_pkg = Some(pkg);
        }
    }
    cyops_packages.sort_by_key(|a| a.nevra());

    // Cross-check `/usr/bin/rpm`'s SHA-256 against the `rpm` package's `RPMTAG_FILEDIGESTS` if available
    if let (Some(rpm_pkg), Some(actual_rpm_sha)) = (&rpm_self_pkg, &rpm_bin_report.sha256) {
        if let Some(rec) = rpm_pkg.files.iter().find(|f| f.path == "/usr/bin/rpm") {
            if rec.sha256_digest.len() == 64 && !hex_digests_equal(&rec.sha256_digest, actual_rpm_sha)
            {
                findings.push(
                    Finding::new(
                        EngineId::RpmForensics,
                        "CRITICAL_RPM_BINARY_SHA256_MISMATCH",
                        Severity::Critical,
                        "/usr/bin/rpm",
                        "On-disk /usr/bin/rpm binary SHA-256 does not match its own rpmdb RPMTAG_FILEDIGESTS record (trojanized rpm binary)",
                    )
                    .with_evidence("expected_sha256", JsonValue::str(&rec.sha256_digest))
                    .with_evidence("actual_sha256", JsonValue::str(actual_rpm_sha))
                    .with_evidence("rpm_package_nevra", JsonValue::str(rpm_pkg.nevra())),
                );
            }
        }
    }

    // 4. Determine dominant signing GPG Key ID across `cyops-*` packages to catch repacked single RPMs
    let mut key_counts: BTreeMap<String, usize> = BTreeMap::new();
    for pkg in &cyops_packages {
        if let Some(key_id) = extract_pkg_key_id(pkg) {
            *key_counts.entry(key_id).or_insert(0) += 1;
        }
    }
    let dominant_key_id: Option<String> = key_counts
        .iter()
        .max_by_key(|(_, c)| *c)
        .filter(|(_, c)| **c >= 2)
        .map(|(k, _)| k.clone());

    // 5. Verify Fortinet RSA/PGP signatures & file SHA-256 digests (`RPMTAG_FILEDIGESTS = 1035`)
    let mut verified_files_count = 0u64;
    let mut modified_config_files_count = 0u64;
    let mut package_summaries = Vec::new();

    for pkg in &cyops_packages {
        let nevra = pkg.nevra();
        let has_rsa_268 = pkg
            .rsa_header_blob
            .as_ref()
            .map(|b| !b.is_empty())
            .unwrap_or(false);
        let has_pgp_259 = pkg
            .sig_pgp_blob
            .as_ref()
            .map(|b| !b.is_empty())
            .unwrap_or(false);

        let pgp_info = pkg
            .rsa_header_blob
            .as_deref()
            .and_then(parse_openpgp_signature_packet)
            .or_else(|| {
                pkg.sig_pgp_blob
                    .as_deref()
                    .and_then(parse_openpgp_signature_packet)
            });

        if !has_rsa_268 && !has_pgp_259 {
            findings.push(
                Finding::new(
                    EngineId::RpmForensics,
                    "CRITICAL_RPM_UNSIGNED_CYOPS_PACKAGE",
                    Severity::Critical,
                    &nevra,
                    format!(
                        "FortiSOAR package `{}` lacks both RPMTAG_RSAHEADER (268) and RPMTAG_SIGPGP (259) cryptographic signatures (repacked/cracked RPM)",
                        nevra
                    ),
                )
                .with_evidence("package", JsonValue::str(&nevra))
                .with_evidence("rpmtag_rsaheader_268_present", JsonValue::Bool(false))
                .with_evidence("rpmtag_sigpgp_259_present", JsonValue::Bool(false)),
            );
        } else if pgp_info.is_none() {
            findings.push(
                Finding::new(
                    EngineId::RpmForensics,
                    "CRITICAL_RPM_MALFORMED_PGP_SIGNATURE",
                    Severity::Critical,
                    &nevra,
                    format!(
                        "FortiSOAR package `{}` contains non-RFC4880 or forged signature bytes in RPMTAG_RSAHEADER/RPMTAG_SIGPGP",
                        nevra
                    ),
                )
                .with_evidence("package", JsonValue::str(&nevra)),
            );
        } else if let (Some(dom_key), Some(info)) = (&dominant_key_id, &pgp_info) {
            if let Some(pkg_key) = &info.issuer_key_id_hex {
                if pkg_key != dom_key {
                    findings.push(
                        Finding::new(
                            EngineId::RpmForensics,
                            "CRITICAL_RPM_SIGNING_KEY_MISMATCH",
                            Severity::Critical,
                            &nevra,
                            format!(
                                "FortiSOAR package `{}` is signed by outlier GPG key 0x{} instead of appliance Fortinet key 0x{}",
                                nevra, pkg_key, dom_key
                            ),
                        )
                        .with_evidence("package", JsonValue::str(&nevra))
                        .with_evidence("package_key_id", JsonValue::str(pkg_key))
                        .with_evidence("expected_fortinet_key_id", JsonValue::str(dom_key)),
                    );
                }
            }
        }

        let mut pkg_mismatches = 0u64;
        let mut pkg_checked = 0u64;

        for file_rec in &pkg.files {
            // Skip ghost files, directories, symlinks, and entries without a recorded SHA-256 digest
            if (file_rec.flags & RPMFILE_GHOST) != 0 || file_rec.sha256_digest.is_empty() {
                continue;
            }
            if let Some(mode) = file_rec.mode {
                if (mode & S_IFMT) != S_IFREG {
                    continue;
                }
            }
            if file_rec.sha256_digest.len() != 64 {
                continue;
            }

            let disk_file = join_rooted(root, &file_rec.path);
            let is_config = (file_rec.flags & RPMFILE_CONFIG) != 0;
            let is_code_file = file_rec.path.ends_with(".py")
                || file_rec.path.ends_with(".pyc")
                || file_rec.path.ends_with(".so")
                || file_rec.path.contains(".so.");

            let actual_sha = match compute_disk_sha256(&disk_file) {
                Ok(h) => h,
                Err(_) => {
                    if !is_config {
                        findings.push(
                            Finding::new(
                                EngineId::RpmForensics,
                                "HIGH_RPM_PACKAGE_FILE_MISSING",
                                Severity::High,
                                &file_rec.path,
                                format!(
                                    "Expected file {} from package `{}` is missing or unreadable on disk",
                                    file_rec.path, nevra
                                ),
                            )
                            .with_evidence("package", JsonValue::str(&nevra))
                            .with_evidence(
                                "expected_sha256",
                                JsonValue::str(&file_rec.sha256_digest),
                            ),
                        );
                    }
                    continue;
                }
            };

            pkg_checked += 1;
            verified_files_count += 1;

            if !hex_digests_equal(&file_rec.sha256_digest, &actual_sha) {
                if is_config && !is_code_file {
                    modified_config_files_count += 1;
                } else {
                    pkg_mismatches += 1;
                    findings.push(
                        Finding::new(
                            EngineId::RpmForensics,
                            "CRITICAL_RPM_FILE_DIGEST_MISMATCH",
                            Severity::Critical,
                            &file_rec.path,
                            format!(
                                "Disk SHA-256 mismatch against RPMTAG_FILEDIGESTS (1035) for {} in package `{}`",
                                file_rec.path, nevra
                            ),
                        )
                        .with_evidence("package", JsonValue::str(&nevra))
                        .with_evidence("file_path", JsonValue::str(&file_rec.path))
                        .with_evidence(
                            "expected_rpm_sha256",
                            JsonValue::str(&file_rec.sha256_digest),
                        )
                        .with_evidence("actual_disk_sha256", JsonValue::str(&actual_sha))
                        .with_evidence("rpm_file_flags", JsonValue::Uint(file_rec.flags as u64)),
                    );
                }
            }
        }

        package_summaries.push(JsonValue::OrderedObject(vec![
            ("nevra".to_string(), JsonValue::str(&nevra)),
            (
                "vendor".to_string(),
                pkg.vendor
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "rsaheader_268".to_string(),
                JsonValue::Bool(has_rsa_268),
            ),
            ("sigpgp_259".to_string(), JsonValue::Bool(has_pgp_259)),
            (
                "signing_key_id".to_string(),
                pgp_info
                    .and_then(|p| p.issuer_key_id_hex)
                    .map(|k| JsonValue::str(format!("0x{}", k)))
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "files_verified".to_string(),
                JsonValue::Uint(pkg_checked),
            ),
            (
                "tampered_files".to_string(),
                JsonValue::Uint(pkg_mismatches),
            ),
        ]));
    }

    let summary = JsonValue::OrderedObject(vec![
        ("rpm_binary".to_string(), rpm_bin_report.json),
        (
            "rpmdb_path".to_string(),
            JsonValue::str(&active_db_path),
        ),
        (
            "rpmdb_backend".to_string(),
            JsonValue::str(&active_db_format),
        ),
        (
            "total_rpmdb_headers_parsed".to_string(),
            JsonValue::Uint(raw_blobs.len() as u64),
        ),
        (
            "cyops_packages_audited".to_string(),
            JsonValue::Uint(cyops_packages.len() as u64),
        ),
        (
            "cyops_files_sha256_verified".to_string(),
            JsonValue::Uint(verified_files_count),
        ),
        (
            "modified_config_files_ignored".to_string(),
            JsonValue::Uint(modified_config_files_count),
        ),
        (
            "cyops_package_reports".to_string(),
            JsonValue::Array(package_summaries),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    RpmForensicsResult { summary, findings }
}

struct RpmBinaryAudit {
    sha256: Option<String>,
    json: JsonValue,
}

fn audit_rpm_binary(root: &Path, rpm_path: &Path, findings: &mut Vec<Finding>) -> RpmBinaryAudit {
    let Some(rpm_bytes) = read_bytes_prefer_raw(rpm_path) else {
        return RpmBinaryAudit {
            sha256: None,
            json: JsonValue::OrderedObject(vec![
                ("path".to_string(), JsonValue::str("/usr/bin/rpm")),
                ("present".to_string(), JsonValue::Bool(false)),
            ]),
        };
    };

    let rpm_sha = sha256_hex(&rpm_bytes);
    let mut needed_json = Vec::new();
    let mut resolved_libs = BTreeMap::new();
    let mut rpath_val = JsonValue::Null;
    let mut runpath_val = JsonValue::Null;

    match parse_elf64_bytes(&rpm_bytes) {
        Ok(elf) => {
            if let Some(rp) = &elf.dt_rpath {
                rpath_val = JsonValue::str(rp);
                if is_untrusted_search_path(rp) {
                    findings.push(
                        Finding::new(
                            EngineId::RpmForensics,
                            "CRITICAL_RPM_BINARY_RPATH_HIJACK",
                            Severity::Critical,
                            "/usr/bin/rpm",
                            format!("Untrusted DT_RPATH `{}` injected into /usr/bin/rpm ELF dynamic table", rp),
                        )
                        .with_evidence("dt_rpath", JsonValue::str(rp))
                        .with_evidence("rpm_sha256", JsonValue::str(&rpm_sha)),
                    );
                }
            }
            if let Some(runp) = &elf.dt_runpath {
                runpath_val = JsonValue::str(runp);
                if is_untrusted_search_path(runp) {
                    findings.push(
                        Finding::new(
                            EngineId::RpmForensics,
                            "CRITICAL_RPM_BINARY_RUNPATH_HIJACK",
                            Severity::Critical,
                            "/usr/bin/rpm",
                            format!(
                                "Untrusted DT_RUNPATH `{}` injected into /usr/bin/rpm ELF dynamic table",
                                runp
                            ),
                        )
                        .with_evidence("dt_runpath", JsonValue::str(runp))
                        .with_evidence("rpm_sha256", JsonValue::str(&rpm_sha)),
                    );
                }
            }

            for lib in &elf.dt_needed {
                needed_json.push(JsonValue::str(lib));
                if lib.contains('/') {
                    findings.push(
                        Finding::new(
                            EngineId::RpmForensics,
                            "CRITICAL_RPM_BINARY_DT_NEEDED_INJECTION",
                            Severity::Critical,
                            "/usr/bin/rpm",
                            format!(
                                "Explicit path DT_NEEDED library `{}` linked into /usr/bin/rpm",
                                lib
                            ),
                        )
                        .with_evidence("dt_needed_entry", JsonValue::str(lib)),
                    );
                }

                if let Some((resolved_logical, lib_sha)) = resolve_and_hash_syslib(root, lib) {
                    resolved_libs.insert(
                        lib.clone(),
                        JsonValue::OrderedObject(vec![
                            ("resolved_path".to_string(), JsonValue::str(resolved_logical)),
                            ("sha256".to_string(), JsonValue::str(lib_sha)),
                        ]),
                    );
                }
            }
        }
        Err(err) => {
            findings.push(
                Finding::new(
                    EngineId::RpmForensics,
                    "CRITICAL_RPM_BINARY_NOT_ELF64",
                    Severity::Critical,
                    "/usr/bin/rpm",
                    format!(
                        "/usr/bin/rpm is not a valid x86_64 ELF64 binary ({}) — possible wrapper script replacement!",
                        err
                    ),
                )
                .with_evidence("rpm_sha256", JsonValue::str(&rpm_sha)),
            );
        }
    }

    RpmBinaryAudit {
        sha256: Some(rpm_sha.clone()),
        json: JsonValue::OrderedObject(vec![
            ("path".to_string(), JsonValue::str("/usr/bin/rpm")),
            ("present".to_string(), JsonValue::Bool(true)),
            ("sha256".to_string(), JsonValue::str(rpm_sha)),
            ("dt_rpath".to_string(), rpath_val),
            ("dt_runpath".to_string(), runpath_val),
            ("dt_needed".to_string(), JsonValue::Array(needed_json)),
            (
                "resolved_library_digests".to_string(),
                JsonValue::MapObject(resolved_libs),
            ),
        ]),
    }
}

fn is_untrusted_search_path(rpath: &str) -> bool {
    for seg in rpath.split(':') {
        let s = seg.trim();
        if s.is_empty() {
            continue;
        }
        if s != "/usr/lib64" && s != "/lib64" && s != "/usr/lib64/rpm-plugins" {
            return true;
        }
    }
    false
}

fn resolve_and_hash_syslib(root: &Path, soname: &str) -> Option<(String, String)> {
    for dir in ["usr/lib64", "lib64"] {
        let rel = format!("{}/{}", dir, soname);
        let full: PathBuf = join_rooted(root, &rel);
        if let Ok(digest) = compute_disk_sha256(&full) {
            return Some((format!("/{}", rel), digest));
        }
    }
    None
}

fn extract_pkg_key_id(pkg: &RpmPackageHeader) -> Option<String> {
    pkg.rsa_header_blob
        .as_deref()
        .and_then(parse_openpgp_signature_packet)
        .and_then(|p| p.issuer_key_id_hex)
        .or_else(|| {
            pkg.sig_pgp_blob
                .as_deref()
                .and_then(parse_openpgp_signature_packet)
                .and_then(|p| p.issuer_key_id_hex)
        })
}

fn read_bytes_prefer_raw(path: &Path) -> Option<Vec<u8>> {
    match raw_syscall_read_file(path) {
        Ok(b) => Some(b),
        Err(_) => fs::read(path).ok(),
    }
}

fn compute_disk_sha256(path: &Path) -> std::io::Result<String> {
    if let Ok(raw) = raw_syscall_read_file(path) {
        return Ok(sha256_hex(&raw));
    }
    sha256_file(path)
}
