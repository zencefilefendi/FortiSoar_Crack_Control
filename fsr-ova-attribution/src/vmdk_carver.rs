//! Module 2: VMDK (`KDMV` Stream-Optimized / Sparse / Descriptor) & QCOW2 Header Parser
//! and High-Speed Sliding-Window Binary Signature Carver (`vmdk_carver`).
//!
//! Operates completely in userspace without `mount`, `losetup`, `qemu-nbd`, or `root`
//! privileges, streaming disk image bytes through an overlapping sliding window to carve:
//!   a) PostgreSQL 8192-byte `pg_control` blocks (`pg_control_version` + Castagnoli CRC-32C),
//!   b) EXT4 (`0xEF53`) and XFS (`XFSB` - `0x58465342`) filesystem superblock UUIDs & `s_mkfs_time`,
//!   c) Embedded X.509 DER/PEM certificates (`FGVM` serial numbers, rogue Fortinet Root CA SPKIs,
//!      RDN order & validity profiles) and ELF64 (`libssl.so.3` / `pam_unix.so`) binary patch idioms,
//!   d) PEP 552 `.pyc` license-bypass stubs and SOAR connector credential-skimmer templates.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use fsr_clone_cluster_audit::birthmark_extractor::{
    parse_ext4_superblock, parse_pg_control_bytes, parse_xfs_superblock, PgControlBirthmark,
    SuperblockBirthmark, EXT4_SUPER_MAGIC, EXT4_SUPER_OFFSET, PG_CONTROL_FILE_SIZE,
};
use fsr_clone_cluster_audit::fgvm_license_inspect::{analyze_fgvm_serial, extract_fgvm_tokens};
use fsr_deep_audit::crypto::{hex_digests_equal, hex_encode, sha256_hex};
use fsr_deep_audit::elf_vma_diff::{parse_elf64_bytes, Elf64Info, Elf64Section};
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};
use fsr_net_crypto_audit::asn1_x509::{
    extract_pem_certificates, parse_der_tlv, parse_x509_der, X509CertInfo,
};
use fsr_net_crypto_audit::ca_trust_audit::KNOWN_FORTINET_FACTORY_CA_SPKI_SHA256;

/// Little-endian VMware VMDK4 sparse/streamOptimized magic (`"KDMV"` = `0x564d444b`).
pub const VMDK_SPARSE_MAGIC: u32 = 0x564d_444b;
/// Big-endian QEMU QCOW2 magic (`"QFI\xfb"` = `0x514649fb`).
pub const QCOW2_MAGIC: u32 = 0x5146_49fb;

/// Overlap retained across streaming `read()` chunks so multi-kilobyte structures
/// (`pg_control` 8 KiB, X.509 certs, ELF64 `.so` binaries) straddling chunk boundaries
/// are carved intact.
const CARVER_OVERLAP_BYTES: usize = 64 * 1024;
const STREAM_CHUNK_BYTES: usize = 128 * 1024;

const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const PT_LOAD: u32 = 1;

const TARGET_CARVED_ELF_SYMBOLS: &[&str] = &[
    "SSL_get_verify_result",
    "X509_verify_cert",
    "EVP_VerifyFinal",
    "EVP_DigestVerifyFinal",
    "X509_verify",
    "RSA_verify",
    "pam_sm_authenticate",
    "pam_sm_acct_mgmt",
];

/// Parsed `#pragma pack(1)` VMware `SparseExtentHeader` (`VMDK4` / `KDMV`).
#[derive(Debug, Clone)]
pub struct VmdkSparseHeader {
    pub version: u32,
    pub flags: u32,
    pub capacity_sectors: u64,
    pub capacity_bytes: u64,
    pub grain_size_sectors: u64,
    pub descriptor_offset_sectors: u64,
    pub descriptor_size_sectors: u64,
    pub num_gtes_per_gt: u32,
    pub rgd_offset_sectors: u64,
    pub gd_offset_sectors: u64,
    pub overhead_sectors: u64,
    pub unclean_shutdown: bool,
    pub compress_algorithm: u16,
    pub has_compressed_grains: bool,
    pub has_stream_markers: bool,
}

impl VmdkSparseHeader {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("magic".to_string(), JsonValue::str("KDMV (0x564d444b)")),
            ("version".to_string(), JsonValue::Uint(self.version as u64)),
            (
                "flags_hex".to_string(),
                JsonValue::str(format!("0x{:08x}", self.flags)),
            ),
            (
                "capacity_sectors".to_string(),
                JsonValue::Uint(self.capacity_sectors),
            ),
            (
                "capacity_bytes".to_string(),
                JsonValue::Uint(self.capacity_bytes),
            ),
            (
                "grain_size_sectors".to_string(),
                JsonValue::Uint(self.grain_size_sectors),
            ),
            (
                "descriptor_offset_sectors".to_string(),
                JsonValue::Uint(self.descriptor_offset_sectors),
            ),
            (
                "descriptor_size_sectors".to_string(),
                JsonValue::Uint(self.descriptor_size_sectors),
            ),
            (
                "num_gtes_per_gt".to_string(),
                JsonValue::Uint(self.num_gtes_per_gt as u64),
            ),
            (
                "rgd_offset_sectors".to_string(),
                JsonValue::Uint(self.rgd_offset_sectors),
            ),
            (
                "gd_offset_sectors".to_string(),
                JsonValue::Uint(self.gd_offset_sectors),
            ),
            (
                "overhead_sectors".to_string(),
                JsonValue::Uint(self.overhead_sectors),
            ),
            (
                "unclean_shutdown".to_string(),
                JsonValue::Bool(self.unclean_shutdown),
            ),
            (
                "compress_algorithm".to_string(),
                JsonValue::str(match self.compress_algorithm {
                    0 => "NONE (0)",
                    1 => "DEFLATE_RFC1950 (1)",
                    _ => "UNKNOWN",
                }),
            ),
            (
                "stream_optimized_markers".to_string(),
                JsonValue::Bool(self.has_stream_markers),
            ),
        ])
    }
}

/// Parsed plaintext VMDK descriptor (`# Disk DescriptorFile` or embedded `KDMV` descriptor).
#[derive(Debug, Clone, Default)]
pub struct VmdkDescriptorInfo {
    pub version: Option<u32>,
    pub cid: Option<String>,
    pub parent_cid: Option<String>,
    pub create_type: Option<String>,
    pub ddb_uuid_image: Option<String>,
    pub ddb_adapter_type: Option<String>,
    pub ddb_virtual_hw_version: Option<String>,
    pub extents: Vec<String>,
}

impl VmdkDescriptorInfo {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            (
                "version".to_string(),
                self.version
                    .map(|v| JsonValue::Uint(v as u64))
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "cid".to_string(),
                self.cid
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "parent_cid".to_string(),
                self.parent_cid
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "create_type".to_string(),
                self.create_type
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "ddb_uuid_image".to_string(),
                self.ddb_uuid_image
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "ddb_adapter_type".to_string(),
                self.ddb_adapter_type
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "ddb_virtual_hw_version".to_string(),
                self.ddb_virtual_hw_version
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "extents".to_string(),
                JsonValue::Array(self.extents.iter().map(JsonValue::str).collect()),
            ),
        ])
    }
}

/// Parsed QCOW2 disk header (`QFI\xfb`), supported when inspecting QCOW2 appliances.
#[derive(Debug, Clone)]
pub struct Qcow2HeaderInfo {
    pub version: u32,
    pub cluster_bits: u32,
    pub virtual_size_bytes: u64,
    pub crypt_method: u32,
}

impl Qcow2HeaderInfo {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("magic".to_string(), JsonValue::str("QFI\\xfb (0x514649fb)")),
            ("version".to_string(), JsonValue::Uint(self.version as u64)),
            (
                "cluster_bits".to_string(),
                JsonValue::Uint(self.cluster_bits as u64),
            ),
            (
                "virtual_size_bytes".to_string(),
                JsonValue::Uint(self.virtual_size_bytes),
            ),
            (
                "crypt_method".to_string(),
                JsonValue::Uint(self.crypt_method as u64),
            ),
        ])
    }
}

/// Carved PostgreSQL `pg_control` record with stream byte offset.
#[derive(Debug, Clone)]
pub struct CarvedPgControl {
    pub image_offset: u64,
    pub birthmark: PgControlBirthmark,
}

/// Carved EXT4 or XFS superblock record with stream byte offset.
#[derive(Debug, Clone)]
pub struct CarvedSuperblock {
    pub image_offset: u64,
    pub birthmark: SuperblockBirthmark,
}

/// Detailed X.509 certificate metadata + ASN.1 DNA traits carved from disk bytes.
#[derive(Debug, Clone)]
pub struct CarvedCertificate {
    pub image_offset: u64,
    pub encoding: &'static str, // "DER" or "PEM"
    pub cert: X509CertInfo,
    pub validity_days: Option<i64>,
    pub serial_byte_len: usize,
    pub serial_entropy_class: String,
    pub subject_rdn_order: String,
    pub issuer_rdn_order: String,
    pub sig_alg_oid: String,
    pub fgvm_serials: Vec<String>,
    pub is_rogue_fortinet_ca: bool,
}

/// Carved ELF64 (`libssl.so.3` / `pam_unix.so`) binary patch idiom.
#[derive(Debug, Clone)]
pub struct CarvedElfPatch {
    pub image_offset: u64,
    pub elf_sha256_prefix: String,
    pub component_family: String, // "libssl" or "pam_unix"
    pub symbol_name: String,
    pub symbol_file_offset: u64,
    pub idiom_code: String,
    pub idiom_description: String,
    pub prologue_hex: String,
}

/// Carved PEP 552 `.pyc` bypass stub trait for zero-mount Crack-Kit DNA attribution.
#[derive(Debug, Clone)]
pub struct CarvedPycStub {
    pub image_offset: u64,
    pub magic_u16: u16,
    pub pep552_bitfield: u32,
    pub source_mtime: u32,
    pub stub_idiom: String,
}

/// Carved SOAR connector skimmer lexical trait for zero-mount Crack-Kit DNA attribution.
#[derive(Debug, Clone)]
pub struct CarvedSkimmerTrait {
    pub image_offset: u64,
    pub pattern_signature: String,
}

/// Complete carving result for a single `.vmdk` / `.qcow2` / raw disk stream.
#[derive(Debug, Clone)]
pub struct VmdkCarveReport {
    pub disk_name: String,
    pub total_bytes_streamed: u64,
    pub decompressed_grains_count: u64,
    pub decompressed_bytes_scanned: u64,
    pub format_detected: String,
    pub vmdk_sparse_header: Option<VmdkSparseHeader>,
    pub vmdk_descriptor: Option<VmdkDescriptorInfo>,
    pub qcow2_header: Option<Qcow2HeaderInfo>,
    pub pg_controls: Vec<CarvedPgControl>,
    pub superblocks: Vec<CarvedSuperblock>,
    pub certificates: Vec<CarvedCertificate>,
    pub elf_patches: Vec<CarvedElfPatch>,
    pub pyc_stubs: Vec<CarvedPycStub>,
    pub skimmer_traits: Vec<CarvedSkimmerTrait>,
    pub findings: Vec<Finding>,
}

impl VmdkCarveReport {
    pub fn to_summary_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("disk_name".to_string(), JsonValue::str(&self.disk_name)),
            (
                "format_detected".to_string(),
                JsonValue::str(&self.format_detected),
            ),
            (
                "total_bytes_streamed".to_string(),
                JsonValue::Uint(self.total_bytes_streamed),
            ),
            (
                "decompressed_grains_count".to_string(),
                JsonValue::Uint(self.decompressed_grains_count),
            ),
            (
                "decompressed_bytes_scanned".to_string(),
                JsonValue::Uint(self.decompressed_bytes_scanned),
            ),
            (
                "vmdk_sparse_header".to_string(),
                self.vmdk_sparse_header
                    .as_ref()
                    .map(|h| h.to_json())
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "vmdk_descriptor".to_string(),
                self.vmdk_descriptor
                    .as_ref()
                    .map(|d| d.to_json())
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "qcow2_header".to_string(),
                self.qcow2_header
                    .as_ref()
                    .map(|q| q.to_json())
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "carved_pg_controls".to_string(),
                JsonValue::Array(
                    self.pg_controls
                        .iter()
                        .map(|p| {
                            JsonValue::OrderedObject(vec![
                                ("image_offset".to_string(), JsonValue::Uint(p.image_offset)),
                                (
                                    "system_identifier".to_string(),
                                    JsonValue::str(p.birthmark.system_identifier.to_string()),
                                ),
                                (
                                    "system_identifier_hex".to_string(),
                                    JsonValue::str(&p.birthmark.system_identifier_hex),
                                ),
                                (
                                    "pg_control_version".to_string(),
                                    JsonValue::Uint(p.birthmark.pg_control_version as u64),
                                ),
                                (
                                    "crc32c_valid".to_string(),
                                    JsonValue::Bool(p.birthmark.crc32c_valid),
                                ),
                                (
                                    "stored_crc32c".to_string(),
                                    JsonValue::str(format!("0x{:08x}", p.birthmark.stored_crc32c)),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "carved_superblocks".to_string(),
                JsonValue::Array(
                    self.superblocks
                        .iter()
                        .map(|s| {
                            JsonValue::OrderedObject(vec![
                                ("image_offset".to_string(), JsonValue::Uint(s.image_offset)),
                                ("fs_type".to_string(), JsonValue::str(&s.birthmark.fs_type)),
                                ("uuid".to_string(), JsonValue::str(&s.birthmark.uuid)),
                                (
                                    "meta_uuid".to_string(),
                                    s.birthmark
                                        .meta_uuid
                                        .as_deref()
                                        .map(JsonValue::str)
                                        .unwrap_or(JsonValue::Null),
                                ),
                                (
                                    "volume_label".to_string(),
                                    JsonValue::str(&s.birthmark.volume_label),
                                ),
                                (
                                    "mkfs_time_unix".to_string(),
                                    s.birthmark
                                        .mkfs_time_unix
                                        .map(JsonValue::Uint)
                                        .unwrap_or(JsonValue::Null),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "carved_certificates".to_string(),
                JsonValue::Array(
                    self.certificates
                        .iter()
                        .map(|c| {
                            JsonValue::OrderedObject(vec![
                                ("image_offset".to_string(), JsonValue::Uint(c.image_offset)),
                                ("encoding".to_string(), JsonValue::str(c.encoding)),
                                (
                                    "subject_dn".to_string(),
                                    JsonValue::str(&c.cert.subject_dn),
                                ),
                                ("issuer_dn".to_string(), JsonValue::str(&c.cert.issuer_dn)),
                                (
                                    "spki_sha256".to_string(),
                                    JsonValue::str(&c.cert.spki_sha256),
                                ),
                                (
                                    "validity_days".to_string(),
                                    c.validity_days
                                        .map(JsonValue::Int)
                                        .unwrap_or(JsonValue::Null),
                                ),
                                (
                                    "subject_rdn_order".to_string(),
                                    JsonValue::str(&c.subject_rdn_order),
                                ),
                                (
                                    "is_rogue_fortinet_ca".to_string(),
                                    JsonValue::Bool(c.is_rogue_fortinet_ca),
                                ),
                                (
                                    "fgvm_serials".to_string(),
                                    JsonValue::Array(
                                        c.fgvm_serials.iter().map(JsonValue::str).collect(),
                                    ),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "carved_elf_patches".to_string(),
                JsonValue::Array(
                    self.elf_patches
                        .iter()
                        .map(|e| {
                            JsonValue::OrderedObject(vec![
                                ("image_offset".to_string(), JsonValue::Uint(e.image_offset)),
                                (
                                    "component_family".to_string(),
                                    JsonValue::str(&e.component_family),
                                ),
                                ("symbol_name".to_string(), JsonValue::str(&e.symbol_name)),
                                ("idiom_code".to_string(), JsonValue::str(&e.idiom_code)),
                                ("prologue_hex".to_string(), JsonValue::str(&e.prologue_hex)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

/// Parses a 512-byte VMware `SparseExtentHeader` (`KDMV`, `#pragma pack(1)`).
pub fn parse_vmdk_sparse_header(bytes: &[u8]) -> Option<VmdkSparseHeader> {
    if bytes.len() < 512 {
        return None;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != VMDK_SPARSE_MAGIC {
        return None;
    }
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if !(1..=3).contains(&version) {
        return None;
    }
    let flags = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let capacity_sectors = u64::from_le_bytes([
        bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
    ]);
    let grain_size_sectors = u64::from_le_bytes([
        bytes[20], bytes[21], bytes[22], bytes[23], bytes[24], bytes[25], bytes[26], bytes[27],
    ]);
    let descriptor_offset_sectors = u64::from_le_bytes([
        bytes[28], bytes[29], bytes[30], bytes[31], bytes[32], bytes[33], bytes[34], bytes[35],
    ]);
    let descriptor_size_sectors = u64::from_le_bytes([
        bytes[36], bytes[37], bytes[38], bytes[39], bytes[40], bytes[41], bytes[42], bytes[43],
    ]);
    let num_gtes_per_gt = u32::from_le_bytes([bytes[44], bytes[45], bytes[46], bytes[47]]);
    let rgd_offset_sectors = u64::from_le_bytes([
        bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53], bytes[54], bytes[55],
    ]);
    let gd_offset_sectors = u64::from_le_bytes([
        bytes[56], bytes[57], bytes[58], bytes[59], bytes[60], bytes[61], bytes[62], bytes[63],
    ]);
    let overhead_sectors = u64::from_le_bytes([
        bytes[64], bytes[65], bytes[66], bytes[67], bytes[68], bytes[69], bytes[70], bytes[71],
    ]);
    let unclean_shutdown = bytes[72] != 0;
    let compress_algorithm = u16::from_le_bytes([bytes[77], bytes[78]]);

    Some(VmdkSparseHeader {
        version,
        flags,
        capacity_sectors,
        capacity_bytes: capacity_sectors.saturating_mul(512),
        grain_size_sectors,
        descriptor_offset_sectors,
        descriptor_size_sectors,
        num_gtes_per_gt,
        rgd_offset_sectors,
        gd_offset_sectors,
        overhead_sectors,
        unclean_shutdown,
        compress_algorithm,
        has_compressed_grains: (flags & 0x0001_0000) != 0,
        has_stream_markers: (flags & 0x0002_0000) != 0,
    })
}

/// Parses an ASCII VMDK text descriptor (`# Disk DescriptorFile` or embedded `KDMV` descriptor).
pub fn parse_vmdk_text_descriptor(raw: &[u8]) -> Option<VmdkDescriptorInfo> {
    let trimmed_end = raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or_else(|| raw.len().min(65536));
    let text = std::str::from_utf8(&raw[..trimmed_end]).ok()?;
    if !text.contains("createType")
        && !text.contains("Disk DescriptorFile")
        && !text.contains("parentCID")
    {
        return None;
    }

    let mut info = VmdkDescriptorInfo::default();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let val = v.trim().trim_matches('"').to_string();
            match key {
                "version" => info.version = val.parse::<u32>().ok(),
                "CID" => info.cid = Some(val),
                "parentCID" => info.parent_cid = Some(val),
                "createType" => info.create_type = Some(val),
                "ddb.uuid.image" => info.ddb_uuid_image = Some(val),
                "ddb.adapterType" => info.ddb_adapter_type = Some(val),
                "ddb.virtualHWVersion" => info.ddb_virtual_hw_version = Some(val),
                _ => {}
            }
        } else if line.starts_with("RW ")
            || line.starts_with("RDONLY ")
            || line.starts_with("ZERO ")
        {
            info.extents.push(line.to_string());
        }
    }

    Some(info)
}

/// Parses a big-endian QEMU QCOW2 header (`QFI\xfb`).
pub fn parse_qcow2_header(bytes: &[u8]) -> Option<Qcow2HeaderInfo> {
    if bytes.len() < 72 {
        return None;
    }
    let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != QCOW2_MAGIC {
        return None;
    }
    let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let cluster_bits = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    let virtual_size_bytes = u64::from_be_bytes([
        bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
    ]);
    let crypt_method = u32::from_be_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
    Some(Qcow2HeaderInfo {
        version,
        cluster_bits,
        virtual_size_bytes,
        crypt_method,
    })
}

/// Inspects a standalone `.vmdk`, `.qcow2`, or `.raw` disk file on disk in userspace.
pub fn carve_disk_file(path: &Path, extra_fortinet_spkis: &[String]) -> io::Result<VmdkCarveReport> {
    let file = File::open(path)?;
    let label = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    carve_disk_stream(&label, file, extra_fortinet_spkis)
}

/// Streams any `Read` source through `VmdkStreamCarver` with bounded O(1) memory.
pub fn carve_disk_stream<R: Read>(
    disk_name: &str,
    mut reader: R,
    extra_fortinet_spkis: &[String],
) -> io::Result<VmdkCarveReport> {
    let mut carver = VmdkStreamCarver::new(disk_name, extra_fortinet_spkis);
    let mut chunk = vec![0u8; STREAM_CHUNK_BYTES];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        carver.push_bytes(&chunk[..n]);
    }
    Ok(carver.finish())
}

/// Incremental streaming VMDK/QCOW2/raw disk header parser and binary signature carver.
pub struct VmdkStreamCarver {
    disk_name: String,
    extra_fortinet_spkis: Vec<String>,
    total_bytes_streamed: u64,
    leading_buf: Vec<u8>,
    header_parsed: bool,
    format_detected: String,
    vmdk_sparse_header: Option<VmdkSparseHeader>,
    vmdk_descriptor: Option<VmdkDescriptorInfo>,
    qcow2_header: Option<Qcow2HeaderInfo>,
    raw_carver: SlidingWindowCore,
    /// Optional streamOptimized compressed-grain follower (`KDMV` + `compressAlgorithm == 1`).
    stream_grain_buf: Vec<u8>,
    stream_grain_pos: u64,
    decompressed_grains_count: u64,
    decompressed_bytes_scanned: u64,
    inflated_carver: SlidingWindowCore,
}

impl VmdkStreamCarver {
    pub fn new(disk_name: &str, extra_fortinet_spkis: &[String]) -> Self {
        Self {
            disk_name: disk_name.to_string(),
            extra_fortinet_spkis: extra_fortinet_spkis.to_vec(),
            total_bytes_streamed: 0,
            leading_buf: Vec::with_capacity(16384),
            header_parsed: false,
            format_detected: "raw_or_unknown".to_string(),
            vmdk_sparse_header: None,
            vmdk_descriptor: None,
            qcow2_header: None,
            raw_carver: SlidingWindowCore::new(),
            stream_grain_buf: Vec::new(),
            stream_grain_pos: 0,
            decompressed_grains_count: 0,
            decompressed_bytes_scanned: 0,
            inflated_carver: SlidingWindowCore::new(),
        }
    }

    /// Feeds the next chunk of disk bytes into both the header recognizer and sliding-window carver.
    pub fn push_bytes(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        // Buffer up to 32 KiB of leading bytes to parse VMDK `KDMV` header + embedded ASCII descriptor
        if self.leading_buf.len() < 32 * 1024 {
            let take = (32 * 1024 - self.leading_buf.len()).min(data.len());
            self.leading_buf.extend_from_slice(&data[..take]);
            self.try_parse_headers();
        }

        self.raw_carver
            .feed(data, &self.disk_name, &self.extra_fortinet_spkis);

        // If `streamOptimized` DEFLATE compressed grains are active, also parse grain markers
        // after `overhead_sectors * 512` and scan decompressed grains!
        let maybe_overhead = self.vmdk_sparse_header.as_ref().and_then(|hdr| {
            if hdr.compress_algorithm == 1 && hdr.has_stream_markers && hdr.overhead_sectors > 0 {
                Some((
                    hdr.overhead_sectors.saturating_mul(512),
                    hdr.grain_size_sectors.max(128).saturating_mul(512) as usize,
                ))
            } else {
                None
            }
        });
        if let Some((overhead_byte_off, max_grain_bytes)) = maybe_overhead {
            self.feed_stream_optimized_grains(data, overhead_byte_off, max_grain_bytes);
        }

        self.total_bytes_streamed = self.total_bytes_streamed.saturating_add(data.len() as u64);
    }

    fn try_parse_headers(&mut self) {
        if !self.header_parsed && self.leading_buf.len() >= 512 {
            if let Some(hdr) = parse_vmdk_sparse_header(&self.leading_buf) {
                self.format_detected = if hdr.has_stream_markers && hdr.compress_algorithm == 1 {
                    "vmdk_stream_optimized_deflate".to_string()
                } else {
                    "vmdk_sparse_kdmv".to_string()
                };
                self.vmdk_sparse_header = Some(hdr);
                self.header_parsed = true;
            } else if let Some(qcow) = parse_qcow2_header(&self.leading_buf) {
                self.format_detected = format!("qcow2_v{}", qcow.version);
                self.qcow2_header = Some(qcow);
                self.header_parsed = true;
            } else if let Some(desc) = parse_vmdk_text_descriptor(&self.leading_buf) {
                self.format_detected = "vmdk_text_descriptor".to_string();
                self.vmdk_descriptor = Some(desc);
                self.header_parsed = true;
            } else {
                self.header_parsed = true;
            }
        }

        // Check if embedded VMDK descriptor sectors are now fully buffered inside `leading_buf`
        if self.vmdk_descriptor.is_none() {
            if let Some(hdr) = &self.vmdk_sparse_header {
                if hdr.descriptor_offset_sectors > 0 && hdr.descriptor_size_sectors > 0 {
                    let start = (hdr.descriptor_offset_sectors as usize).saturating_mul(512);
                    let len = (hdr.descriptor_size_sectors as usize)
                        .saturating_mul(512)
                        .min(16384);
                    if start < self.leading_buf.len() {
                        let end = (start + len).min(self.leading_buf.len());
                        self.vmdk_descriptor =
                            parse_vmdk_text_descriptor(&self.leading_buf[start..end]);
                    }
                }
            }
        }
    }

    fn feed_stream_optimized_grains(
        &mut self,
        chunk: &[u8],
        overhead_byte_off: u64,
        max_grain_bytes: usize,
    ) {
        let chunk_start = self.total_bytes_streamed;
        let chunk_end = chunk_start + chunk.len() as u64;
        if chunk_end <= overhead_byte_off {
            return;
        }
        let slice_start = if chunk_start < overhead_byte_off {
            self.stream_grain_pos = overhead_byte_off;
            (overhead_byte_off - chunk_start) as usize
        } else {
            0
        };
        self.stream_grain_buf.extend_from_slice(&chunk[slice_start..]);

        // Process 512-byte aligned streamOptimized markers:
        //   - Compressed Grain Marker: `val: u64` (LBA), `size: u32` (`> 0`), followed by `size` zlib bytes, padded to 512
        //   - Metadata Marker: `val: u64` (sectors), `size: u32 == 0`, `marker_type: u32`, padded to 512 + `val * 512`
        loop {
            if self.stream_grain_buf.len() < 512 {
                break;
            }
            let val = u64::from_le_bytes([
                self.stream_grain_buf[0],
                self.stream_grain_buf[1],
                self.stream_grain_buf[2],
                self.stream_grain_buf[3],
                self.stream_grain_buf[4],
                self.stream_grain_buf[5],
                self.stream_grain_buf[6],
                self.stream_grain_buf[7],
            ]);
            let size = u32::from_le_bytes([
                self.stream_grain_buf[8],
                self.stream_grain_buf[9],
                self.stream_grain_buf[10],
                self.stream_grain_buf[11],
            ]) as usize;

            if size == 0 {
                // Metadata marker (`EOS=0`, `GT=1`, `GD=2`, `FOOTER=3`)
                let marker_type = u32::from_le_bytes([
                    self.stream_grain_buf[12],
                    self.stream_grain_buf[13],
                    self.stream_grain_buf[14],
                    self.stream_grain_buf[15],
                ]);
                let skip_sectors = if marker_type <= 3 && val <= 32768 {
                    1usize.saturating_add(val as usize)
                } else {
                    1usize
                };
                let needed = skip_sectors.saturating_mul(512);
                if self.stream_grain_buf.len() < needed {
                    break;
                }
                self.stream_grain_buf.drain(..needed);
                self.stream_grain_pos = self.stream_grain_pos.saturating_add(needed as u64);
            } else if size <= max_grain_bytes.saturating_add(4096) {
                let total_raw = 12usize.saturating_add(size);
                let padded = total_raw.div_ceil(512) * 512;
                if self.stream_grain_buf.len() < padded {
                    break;
                }
                let zlib_slice = &self.stream_grain_buf[12..12 + size];
                if let Ok(inflated) = inflate_zlib_limited(zlib_slice, max_grain_bytes.max(65536)) {
                    self.decompressed_grains_count += 1;
                    self.decompressed_bytes_scanned += inflated.len() as u64;
                    let grain_label = format!("{}[inflated]", self.disk_name);
                    self.inflated_carver.feed(
                        &inflated,
                        &grain_label,
                        &self.extra_fortinet_spkis,
                    );
                }
                self.stream_grain_buf.drain(..padded);
                self.stream_grain_pos = self.stream_grain_pos.saturating_add(padded as u64);
            } else {
                // Out-of-sync sector; advance 512 bytes safely bounded
                self.stream_grain_buf.drain(..512);
                self.stream_grain_pos = self.stream_grain_pos.saturating_add(512);
            }

            // Cap buffer growth in case a corrupt header claims huge size
            if self.stream_grain_buf.len() > 2 * 1024 * 1024 {
                self.stream_grain_buf.drain(..512);
            }
        }
    }

    /// Finalizes any remaining window bytes and builds the deterministic [`VmdkCarveReport`].
    pub fn finish(mut self) -> VmdkCarveReport {
        self.try_parse_headers();

        let mut pg_controls = self.raw_carver.pg_controls;
        let mut seen_pg: BTreeSet<u64> = pg_controls
            .iter()
            .map(|p| p.birthmark.system_identifier)
            .collect();
        for p in self.inflated_carver.pg_controls {
            if seen_pg.insert(p.birthmark.system_identifier) {
                pg_controls.push(p);
            }
        }

        let mut superblocks = self.raw_carver.superblocks;
        let mut seen_sb: BTreeSet<String> =
            superblocks.iter().map(|s| s.birthmark.uuid.clone()).collect();
        for s in self.inflated_carver.superblocks {
            if seen_sb.insert(s.birthmark.uuid.clone()) {
                superblocks.push(s);
            }
        }

        let mut certificates = self.raw_carver.certificates;
        let mut seen_certs: BTreeSet<String> = certificates
            .iter()
            .map(|c| c.cert.cert_sha256.clone())
            .collect();
        for c in self.inflated_carver.certificates {
            if seen_certs.insert(c.cert.cert_sha256.clone()) {
                certificates.push(c);
            }
        }

        let mut elf_patches = self.raw_carver.elf_patches;
        let mut seen_elf: BTreeSet<String> = elf_patches
            .iter()
            .map(|e| format!("{}:{}:{}", e.elf_sha256_prefix, e.symbol_name, e.idiom_code))
            .collect();
        for e in self.inflated_carver.elf_patches {
            let key = format!("{}:{}:{}", e.elf_sha256_prefix, e.symbol_name, e.idiom_code);
            if seen_elf.insert(key) {
                elf_patches.push(e);
            }
        }

        let mut pyc_stubs = self.raw_carver.pyc_stubs;
        pyc_stubs.extend(self.inflated_carver.pyc_stubs);

        let mut skimmer_traits = self.raw_carver.skimmer_traits;
        skimmer_traits.extend(self.inflated_carver.skimmer_traits);

        let mut findings = self.raw_carver.findings;
        let mut seen_finding_keys: BTreeSet<String> = findings
            .iter()
            .map(|f| format!("{}:{}", f.code, f.summary))
            .collect();
        for f in self.inflated_carver.findings {
            let k = format!("{}:{}", f.code, f.summary);
            if seen_finding_keys.insert(k) {
                findings.push(f);
            }
        }

        VmdkCarveReport {
            disk_name: self.disk_name,
            total_bytes_streamed: self.total_bytes_streamed,
            decompressed_grains_count: self.decompressed_grains_count,
            decompressed_bytes_scanned: self.decompressed_bytes_scanned,
            format_detected: self.format_detected,
            vmdk_sparse_header: self.vmdk_sparse_header,
            vmdk_descriptor: self.vmdk_descriptor,
            qcow2_header: self.qcow2_header,
            pg_controls,
            superblocks,
            certificates,
            elf_patches,
            pyc_stubs,
            skimmer_traits,
            findings,
        }
    }
}

/// Core sliding-window signature scanner operating on contiguous + overlapped byte chunks.
struct SlidingWindowCore {
    window: Vec<u8>,
    window_base_offset: u64,
    scanned_pg_offsets: BTreeSet<u64>,
    scanned_sb_offsets: BTreeSet<u64>,
    seen_cert_sha256: BTreeSet<String>,
    scanned_elf_offsets: BTreeSet<u64>,
    scanned_pyc_offsets: BTreeSet<u64>,
    seen_skimmer_sigs: BTreeSet<String>,
    pub pg_controls: Vec<CarvedPgControl>,
    pub superblocks: Vec<CarvedSuperblock>,
    pub certificates: Vec<CarvedCertificate>,
    pub elf_patches: Vec<CarvedElfPatch>,
    pub pyc_stubs: Vec<CarvedPycStub>,
    pub skimmer_traits: Vec<CarvedSkimmerTrait>,
    pub findings: Vec<Finding>,
}

impl SlidingWindowCore {
    fn new() -> Self {
        Self {
            window: Vec::with_capacity(STREAM_CHUNK_BYTES + CARVER_OVERLAP_BYTES),
            window_base_offset: 0,
            scanned_pg_offsets: BTreeSet::new(),
            scanned_sb_offsets: BTreeSet::new(),
            seen_cert_sha256: BTreeSet::new(),
            scanned_elf_offsets: BTreeSet::new(),
            scanned_pyc_offsets: BTreeSet::new(),
            seen_skimmer_sigs: BTreeSet::new(),
            pg_controls: Vec::new(),
            superblocks: Vec::new(),
            certificates: Vec::new(),
            elf_patches: Vec::new(),
            pyc_stubs: Vec::new(),
            skimmer_traits: Vec::new(),
            findings: Vec::new(),
        }
    }

    fn feed(&mut self, chunk: &[u8], disk_label: &str, extra_fortinet_spkis: &[String]) {
        self.window.extend_from_slice(chunk);
        self.scan_current_window(disk_label, extra_fortinet_spkis);

        if self.window.len() > CARVER_OVERLAP_BYTES {
            let drain_count = self.window.len() - CARVER_OVERLAP_BYTES;
            // Align drain_count down to 512 bytes so sector alignment inside `window` stays simple
            let aligned_drain = (drain_count / 512) * 512;
            if aligned_drain > 0 {
                self.window.drain(..aligned_drain);
                self.window_base_offset += aligned_drain as u64;
            }
        }
    }

    fn scan_current_window(&mut self, disk_label: &str, extra_fortinet_spkis: &[String]) {
        let len = self.window.len();
        if len < 128 {
            return;
        }

        // --------------------------------------------------------------------
        // Pass A: Sector/8-byte aligned structures (`pg_control`, XFS, EXT4)
        // --------------------------------------------------------------------
        let mut pos = 0usize;
        while pos + 512 <= len {
            let abs_off = self.window_base_offset + pos as u64;

            // A1. XFS Superblock (`"XFSB"` = `0x58465342` at `+0..4`)
            if self.window[pos..pos + 4] == [0x58, 0x46, 0x53, 0x42]
                && !self.scanned_sb_offsets.contains(&abs_off)
            {
                let sectsize = u16::from_be_bytes([self.window[pos + 0x66], self.window[pos + 0x67]]);
                if (512..=4096).contains(&sectsize) && sectsize.is_power_of_two() {
                    let src = format!("{}@0x{:x}", disk_label, abs_off);
                    if let Some(sb) = parse_xfs_superblock(&src, &self.window[pos..]) {
                        if sb.uuid != "00000000-0000-0000-0000-000000000000" {
                            self.scanned_sb_offsets.insert(abs_off);
                            self.superblocks.push(CarvedSuperblock {
                                image_offset: abs_off,
                                birthmark: sb,
                            });
                        }
                    }
                }
            }

            // A2. EXT4 Superblock (`0xEF53` little-endian at `+0x38..0x3A`)
            if pos + 0x280 <= len
                && self.window[pos + 0x38] == (EXT4_SUPER_MAGIC as u8)
                && self.window[pos + 0x39] == ((EXT4_SUPER_MAGIC >> 8) as u8)
                && !self.scanned_sb_offsets.contains(&abs_off)
            {
                let inodes = u32::from_le_bytes([
                    self.window[pos],
                    self.window[pos + 1],
                    self.window[pos + 2],
                    self.window[pos + 3],
                ]);
                let blocks = u32::from_le_bytes([
                    self.window[pos + 4],
                    self.window[pos + 5],
                    self.window[pos + 6],
                    self.window[pos + 7],
                ]);
                let log_bsize = u32::from_le_bytes([
                    self.window[pos + 0x18],
                    self.window[pos + 0x19],
                    self.window[pos + 0x1a],
                    self.window[pos + 0x1b],
                ]);
                let rev_level = u32::from_le_bytes([
                    self.window[pos + 0x4c],
                    self.window[pos + 0x4d],
                    self.window[pos + 0x4e],
                    self.window[pos + 0x4f],
                ]);
                if inodes > 0 && blocks > 0 && log_bsize <= 6 && rev_level <= 2 {
                    // `parse_ext4_superblock` expects `EXT4_SUPER_OFFSET` (1024) prefix
                    let mut padded = vec![0u8; EXT4_SUPER_OFFSET + 1024];
                    let copy_len = (len - pos).min(1024);
                    padded[EXT4_SUPER_OFFSET..EXT4_SUPER_OFFSET + copy_len]
                        .copy_from_slice(&self.window[pos..pos + copy_len]);
                    let src = format!("{}@0x{:x}", disk_label, abs_off);
                    if let Some(sb) = parse_ext4_superblock(&src, &padded) {
                        if sb.uuid != "00000000-0000-0000-0000-000000000000" {
                            self.scanned_sb_offsets.insert(abs_off);
                            self.superblocks.push(CarvedSuperblock {
                                image_offset: abs_off,
                                birthmark: sb,
                            });
                        }
                    }
                }
            }

            // A3. PostgreSQL 8192-byte `pg_control` (`pg_control_version` + Castagnoli CRC-32C)
            if pos + PG_CONTROL_FILE_SIZE <= len && !self.scanned_pg_offsets.contains(&abs_off) {
                let sys_id = u64::from_le_bytes([
                    self.window[pos],
                    self.window[pos + 1],
                    self.window[pos + 2],
                    self.window[pos + 3],
                    self.window[pos + 4],
                    self.window[pos + 5],
                    self.window[pos + 6],
                    self.window[pos + 7],
                ]);
                let pg_ver = u32::from_le_bytes([
                    self.window[pos + 8],
                    self.window[pos + 9],
                    self.window[pos + 10],
                    self.window[pos + 11],
                ]);
                let cat_ver = u32::from_le_bytes([
                    self.window[pos + 12],
                    self.window[pos + 13],
                    self.window[pos + 14],
                    self.window[pos + 15],
                ]);
                let db_state = u32::from_le_bytes([
                    self.window[pos + 16],
                    self.window[pos + 17],
                    self.window[pos + 18],
                    self.window[pos + 19],
                ]);

                if sys_id != 0
                    && (940..=1999).contains(&pg_ver)
                    && (201400000..=203500000).contains(&cat_ver)
                    && db_state <= 16
                {
                    let slice = &self.window[pos..pos + PG_CONTROL_FILE_SIZE];
                    let label = format!("{}@0x{:x}[pg_control]", disk_label, abs_off);
                    if let Ok(pg) = parse_pg_control_bytes(&label, slice) {
                        if pg.crc32c_valid {
                            self.scanned_pg_offsets.insert(abs_off);
                            self.pg_controls.push(CarvedPgControl {
                                image_offset: abs_off,
                                birthmark: pg,
                            });
                        } else if slice[512..].iter().all(|&b| b == 0) {
                            self.scanned_pg_offsets.insert(abs_off);
                            self.findings.push(
                                Finding::new(
                                    EngineId::VmdkCarver,
                                    "HIGH_VMDK_CARVED_PG_CONTROL_CRC_TAMPER",
                                    Severity::High,
                                    &label,
                                    format!(
                                        "Carved PostgreSQL pg_control at {} failed Castagnoli CRC-32C validation (stored=0x{:08x}, computed=0x{:08x})",
                                        label, pg.stored_crc32c, pg.computed_crc32c
                                    ),
                                )
                                .with_evidence(
                                    "system_identifier",
                                    JsonValue::str(pg.system_identifier.to_string()),
                                )
                                .with_evidence("image_offset", JsonValue::Uint(abs_off)),
                            );
                            self.pg_controls.push(CarvedPgControl {
                                image_offset: abs_off,
                                birthmark: pg,
                            });
                        }
                    }
                }
            }

            pos += 512;
        }

        // --------------------------------------------------------------------
        // Pass B: Byte-granularity sliding scan for X.509 DER/PEM, ELF64, `.pyc`, and Skimmers
        // --------------------------------------------------------------------
        let mut idx = 0usize;
        while idx + 16 < len {
            let b0 = self.window[idx];

            // B1. Raw ASN.1 DER Certificate (`SEQUENCE` `0x30 0x82 <hi> <lo> 0x30 0x82/0x81`)
            if b0 == 0x30
                && idx + 8 < len
                && self.window[idx + 1] == 0x82
                && self.window[idx + 4] == 0x30
                && (self.window[idx + 5] == 0x82 || self.window[idx + 5] == 0x81)
            {
                let outer_val_len =
                    u16::from_be_bytes([self.window[idx + 2], self.window[idx + 3]]) as usize;
                let total_der_len = 4 + outer_val_len;
                if (180..=16384).contains(&total_der_len) && idx + total_der_len <= len {
                    let der = self.window[idx..idx + total_der_len].to_vec();
                    let abs_off = self.window_base_offset + idx as u64;
                    if self.inspect_carved_x509_der(
                        &der,
                        abs_off,
                        "DER",
                        disk_label,
                        extra_fortinet_spkis,
                    ) {
                        idx += total_der_len;
                        continue;
                    }
                }
            }

            // B2. PEM-encoded Certificate (`-----BEGIN CERTIFICATE-----`)
            if b0 == b'-'
                && idx + 27 < len
                && &self.window[idx..idx + 27] == b"-----BEGIN CERTIFICATE-----"
            {
                let search_end = (idx + 16384).min(len);
                if let Some(rel_end) =
                    find_subslice(&self.window[idx..search_end], b"-----END CERTIFICATE-----")
                {
                    let pem_end = idx + rel_end + 25;
                    if let Ok(pem_str) = std::str::from_utf8(&self.window[idx..pem_end]) {
                        let abs_off = self.window_base_offset + idx as u64;
                        for der in extract_pem_certificates(pem_str) {
                            self.inspect_carved_x509_der(
                                &der,
                                abs_off,
                                "PEM",
                                disk_label,
                                extra_fortinet_spkis,
                            );
                        }
                    }
                    idx = pem_end;
                    continue;
                }
            }

            // B3. ELF64 `ET_DYN` `x86_64` Shared Object (`\x7fELF\x02\x01\x01`)
            if b0 == 0x7f
                && idx + 64 < len
                && &self.window[idx..idx + 7] == b"\x7fELF\x02\x01\x01"
            {
                let e_type = u16::from_le_bytes([self.window[idx + 16], self.window[idx + 17]]);
                let e_machine = u16::from_le_bytes([self.window[idx + 18], self.window[idx + 19]]);
                let abs_off = self.window_base_offset + idx as u64;
                if e_type == 3 && e_machine == 62 && !self.scanned_elf_offsets.contains(&abs_off) {
                    if let Some(elf_len) = estimate_elf64_span(&self.window[idx..]) {
                        if idx + elf_len <= len {
                            self.scanned_elf_offsets.insert(abs_off);
                            let elf_bytes = self.window[idx..idx + elf_len].to_vec();
                            self.inspect_carved_elf64(&elf_bytes, abs_off, disk_label);
                        }
                    }
                }
            }

            // B4. PEP 552 Python 3.9/3.10/3.11/3.12 `.pyc` header (`<magic_le16> \r \n`)
            if idx + 48 <= len && self.window[idx + 2] == 0x0d && self.window[idx + 3] == 0x0a {
                let magic_u16 = u16::from_le_bytes([self.window[idx], self.window[idx + 1]]);
                if matches!(magic_u16, 3425 | 3439 | 3495 | 3531) {
                    let bitfield = u32::from_le_bytes([
                        self.window[idx + 4],
                        self.window[idx + 5],
                        self.window[idx + 6],
                        self.window[idx + 7],
                    ]);
                    let abs_off = self.window_base_offset + idx as u64;
                    if bitfield <= 3 && !self.scanned_pyc_offsets.contains(&abs_off) {
                        let mtime = u32::from_le_bytes([
                            self.window[idx + 8],
                            self.window[idx + 9],
                            self.window[idx + 10],
                            self.window[idx + 11],
                        ]);
                        let scan_end = (idx + 512).min(len);
                        let pyc_slice = &self.window[idx..scan_end];
                        if let Some(stub_idiom) = detect_carved_pyc_true_stub(pyc_slice, magic_u16) {
                            self.scanned_pyc_offsets.insert(abs_off);
                            self.pyc_stubs.push(CarvedPycStub {
                                image_offset: abs_off,
                                magic_u16,
                                pep552_bitfield: bitfield,
                                source_mtime: mtime,
                                stub_idiom,
                            });
                        }
                    }
                }
            }

            // B5. SOAR Connector Credential Skimmer Signature (`config.get(` near outbound HTTP/exec)
            if b0 == b'c'
                && idx + 11 < len
                && &self.window[idx..idx + 11] == b"config.get("
            {
                let snippet_start = idx.saturating_sub(256);
                let snippet_end = (idx + 768).min(len);
                if let Ok(snippet) =
                    std::str::from_utf8(&self.window[snippet_start..snippet_end])
                {
                    if let Some(sig) = classify_skimmer_snippet_signature(snippet) {
                        if self.seen_skimmer_sigs.insert(sig.clone()) {
                            let abs_off = self.window_base_offset + idx as u64;
                            self.skimmer_traits.push(CarvedSkimmerTrait {
                                image_offset: abs_off,
                                pattern_signature: sig,
                            });
                        }
                    }
                }
            }

            // B6. FortiSOAR DAS (`cyops-auth` / `csdassrv.py`) Cython `.so` Shadowing & License Intercept
            if (b0 == b'F'
                && idx + 18 <= len
                && (&self.window[idx..idx + 16] == b"FSRVMPTM99999999"
                    || &self.window[idx..idx + 18] == b"FakeLicenseManager"))
                || (b0 == b'h'
                    && idx + 22 <= len
                    && &self.window[idx..idx + 22] == b"handlerworkers.license")
            {
                let snippet_start = idx.saturating_sub(256);
                let snippet_end = (idx + 768).min(len);
                let slice = &self.window[snippet_start..snippet_end];
                if find_subslice(slice, b"FakeLicenseManager").is_some()
                    || find_subslice(slice, b"FSRVMPTM99999999").is_some()
                    || find_subslice(slice, b"RequestHandler._execute").is_some()
                    || find_subslice(slice, b"MOCK-HARDWARE-UUID-KEY").is_some()
                {
                    let trait_id =
                        "das_bypass:tornado_cython_shadow_FSRVMPTM99999999".to_string();
                    if self.seen_skimmer_sigs.insert(trait_id.clone()) {
                        let abs_off = self.window_base_offset + idx as u64;
                        let target = format!("{}@0x{:x}[das_runtime_bypass]", disk_label, abs_off);
                        self.findings.push(
                            Finding::new(
                                EngineId::VmdkCarver,
                                "CRITICAL_VMDK_CARVED_DAS_RUNTIME_BYPASS",
                                Severity::Critical,
                                &target,
                                format!(
                                    "Carved FortiSOAR `cyops-auth` / `csdassrv.py` runtime license bypass (`FakeLicenseManager` / `FSRVMPTM99999999` / `sys.modules` Cython shadowing) inside unmounted disk {} at 0x{:x}",
                                    disk_label, abs_off
                                ),
                            )
                            .with_evidence("image_offset", JsonValue::Uint(abs_off))
                            .with_evidence("trait_signature", JsonValue::str(&trait_id)),
                        );
                        self.skimmer_traits.push(CarvedSkimmerTrait {
                            image_offset: abs_off,
                            pattern_signature: trait_id,
                        });
                    }
                }
            }

            idx += 1;
        }
    }

    fn inspect_carved_x509_der(
        &mut self,
        der: &[u8],
        abs_off: u64,
        encoding: &'static str,
        disk_label: &str,
        extra_fortinet_spkis: &[String],
    ) -> bool {
        let Ok(cert) = parse_x509_der(der) else {
            return false;
        };
        if !self.seen_cert_sha256.insert(cert.cert_sha256.clone()) {
            return true;
        }

        let dna_meta = extract_x509_dna_metadata(der, &cert);
        let mut fgvm_serials = Vec::new();
        for tok in extract_fgvm_tokens(&format!(
            "{} {} {}",
            cert.subject_dn,
            cert.issuer_dn,
            cert.san_dns_names.join(" ")
        )) {
            if !fgvm_serials.contains(&tok) {
                fgvm_serials.push(tok);
            }
        }

        let target = format!("{}@0x{:x}[x509:{}]", disk_label, abs_off, encoding);

        // Check FGVM serial authenticity
        for serial in &fgvm_serials {
            let analysis = analyze_fgvm_serial(serial, &target);
            if !analysis.format_valid || analysis.keygen_or_pirated_reason.is_some() {
                self.findings.push(
                    Finding::new(
                        EngineId::VmdkCarver,
                        "CRITICAL_VMDK_CARVED_FORGED_FGVM_CERT",
                        Severity::Critical,
                        &target,
                        format!(
                            "Carved X.509 certificate in {} embeds forged/pirated FortiGate VM serial `{}` (Subject=`{}`)",
                            target, serial, cert.subject_dn
                        ),
                    )
                    .with_evidence("fgvm_serial", JsonValue::str(serial.as_str()))
                    .with_evidence("subject_dn", JsonValue::str(&cert.subject_dn))
                    .with_evidence("spki_sha256", JsonValue::str(&cert.spki_sha256))
                    .with_evidence("image_offset", JsonValue::Uint(abs_off)),
                );
            }
        }

        // Check Rogue Fortinet Root CA / Emulator CA
        let is_known_factory_spki = KNOWN_FORTINET_FACTORY_CA_SPKI_SHA256
            .iter()
            .any(|pin| hex_digests_equal(pin, &cert.spki_sha256))
            || extra_fortinet_spkis
                .iter()
                .any(|pin| hex_digests_equal(pin, &cert.spki_sha256));

        let is_rogue_fortinet_ca = !is_known_factory_spki
            && ((cert.mentions_fortinet_identity()
                && (cert.basic_constraints_ca || cert.is_self_signed))
                || (cert.basic_constraints_ca
                    && cert.is_self_signed
                    && cert.subject_dn.to_ascii_lowercase().contains("emulator")));

        if is_rogue_fortinet_ca {
            self.findings.push(
                Finding::new(
                    EngineId::VmdkCarver,
                    "CRITICAL_VMDK_CARVED_ROGUE_CA",
                    Severity::Critical,
                    &target,
                    format!(
                        "Carved rogue Root CA impersonating Fortinet/FDN inside unmounted disk stream {} (Subject=`{}`, SPKI={})",
                        target, cert.subject_dn, cert.spki_sha256
                    ),
                )
                .with_evidence("subject_dn", JsonValue::str(&cert.subject_dn))
                .with_evidence("issuer_dn", JsonValue::str(&cert.issuer_dn))
                .with_evidence("spki_sha256", JsonValue::str(&cert.spki_sha256))
                .with_evidence("cert_sha256", JsonValue::str(&cert.cert_sha256))
                .with_evidence(
                    "validity_days",
                    dna_meta
                        .validity_days
                        .map(JsonValue::Int)
                        .unwrap_or(JsonValue::Null),
                )
                .with_evidence(
                    "subject_rdn_order",
                    JsonValue::str(&dna_meta.subject_rdn_order),
                )
                .with_evidence("image_offset", JsonValue::Uint(abs_off)),
            );
        }

        self.certificates.push(CarvedCertificate {
            image_offset: abs_off,
            encoding,
            cert,
            validity_days: dna_meta.validity_days,
            serial_byte_len: dna_meta.serial_byte_len,
            serial_entropy_class: dna_meta.serial_entropy_class,
            subject_rdn_order: dna_meta.subject_rdn_order,
            issuer_rdn_order: dna_meta.issuer_rdn_order,
            sig_alg_oid: dna_meta.sig_alg_oid,
            fgvm_serials,
            is_rogue_fortinet_ca,
        });

        true
    }

    fn inspect_carved_elf64(&mut self, bytes: &[u8], abs_off: u64, disk_label: &str) {
        let Ok(elf) = parse_elf64_bytes(bytes) else {
            return;
        };
        let elf_hash_prefix = sha256_hex(bytes)[..16].to_string();

        for sec in &elf.sections {
            if sec.sh_type != SHT_DYNSYM && sec.sh_type != SHT_SYMTAB {
                continue;
            }
            let Some(strtab_sec) = elf.sections.get(sec.sh_link as usize) else {
                continue;
            };
            let Some(strtab) = slice_elf_section(bytes, strtab_sec) else {
                continue;
            };
            let Some(symtab) = slice_elf_section(bytes, sec) else {
                continue;
            };
            let entsize = if sec.sh_entsize >= 24 {
                sec.sh_entsize as usize
            } else {
                24
            };
            let mut off = 0usize;
            while off + 24 <= symtab.len() {
                let ent = &symtab[off..off + 24];
                let st_name = u32::from_le_bytes([ent[0], ent[1], ent[2], ent[3]]) as usize;
                let st_shndx = u16::from_le_bytes([ent[6], ent[7]]);
                let st_value = u64::from_le_bytes([
                    ent[8], ent[9], ent[10], ent[11], ent[12], ent[13], ent[14], ent[15],
                ]);
                off += entsize;

                if st_shndx == 0 || st_value == 0 || st_name >= strtab.len() {
                    continue;
                }
                let sym_name = read_elf_cstr(strtab, st_name);
                if !TARGET_CARVED_ELF_SYMBOLS.contains(&sym_name) {
                    continue;
                }
                let Some(file_off) = elf_vaddr_to_offset(&elf, st_value, st_shndx) else {
                    continue;
                };
                let f_off = file_off as usize;
                if f_off + 10 > bytes.len() {
                    continue;
                }
                let end = (f_off + 16).min(bytes.len());
                let prologue = &bytes[f_off..end];
                if let Some((idiom_code, idiom_desc)) = classify_x86_64_patch_idiom(prologue) {
                    let component_family = if sym_name.starts_with("pam_") {
                        "pam_unix"
                    } else {
                        "libssl"
                    };
                    let target = format!(
                        "{}@0x{:x}[elf64:{}!{}]",
                        disk_label, abs_off, component_family, sym_name
                    );
                    let prologue_hex = hex_encode(prologue);

                    self.findings.push(
                        Finding::new(
                            EngineId::VmdkCarver,
                            "CRITICAL_VMDK_CARVED_ELF_PATCH",
                            Severity::Critical,
                            &target,
                            format!(
                                "Carved patched ELF64 `{}` symbol `{}` inside unmounted disk {} (`{}`: `{}`)",
                                component_family, sym_name, disk_label, idiom_code, idiom_desc
                            ),
                        )
                        .with_evidence("component_family", JsonValue::str(component_family))
                        .with_evidence("symbol_name", JsonValue::str(sym_name))
                        .with_evidence("idiom_code", JsonValue::str(idiom_code))
                        .with_evidence("prologue_hex", JsonValue::str(&prologue_hex))
                        .with_evidence("image_offset", JsonValue::Uint(abs_off))
                        .with_evidence("symbol_file_offset", JsonValue::Uint(file_off)),
                    );

                    self.elf_patches.push(CarvedElfPatch {
                        image_offset: abs_off,
                        elf_sha256_prefix: elf_hash_prefix.clone(),
                        component_family: component_family.to_string(),
                        symbol_name: sym_name.to_string(),
                        symbol_file_offset: file_off,
                        idiom_code: idiom_code.to_string(),
                        idiom_description: idiom_desc.to_string(),
                        prologue_hex,
                    });
                }
            }
        }
    }
}

/// Classifies exact x86_64 binary crack prologue idioms (both Intel CET `endbr64` and raw stubs)
/// into deterministic normalized `idiom_code` tokens used by `cracker_attribution`.
pub fn classify_x86_64_patch_idiom(prologue: &[u8]) -> Option<(&'static str, &'static str)> {
    let (has_cet, body) = if prologue.len() >= 4 && prologue[..4] == [0xf3, 0x0f, 0x1e, 0xfa] {
        (true, &prologue[4..])
    } else {
        (false, prologue)
    };

    if body.len() >= 6 && body[..6] == [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3] {
        return Some(if has_cet {
            (
                "CET_ENDBR64_MOV_EAX_1_RET",
                "endbr64; mov eax, 1; ret (f3 0f 1e fa b8 01 00 00 00 c3)",
            )
        } else {
            (
                "RAW_MOV_EAX_1_RET",
                "mov eax, 1; ret (b8 01 00 00 00 c3)",
            )
        });
    }
    if body.len() >= 6 && body[..6] == [0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3] {
        return Some(if has_cet {
            (
                "CET_ENDBR64_MOV_EAX_0_RET",
                "endbr64; mov eax, 0; ret (f3 0f 1e fa b8 00 00 00 00 c3)",
            )
        } else {
            (
                "RAW_MOV_EAX_0_RET",
                "mov eax, 0; ret (b8 00 00 00 00 c3)",
            )
        });
    }
    if body.len() >= 3 && body[..3] == [0x31, 0xc0, 0xc3] {
        return Some(if has_cet {
            (
                "CET_ENDBR64_XOR_EAX_EAX_RET",
                "endbr64; xor eax, eax; ret (f3 0f 1e fa 31 c0 c3)",
            )
        } else {
            (
                "RAW_XOR_EAX_EAX_RET",
                "xor eax, eax; ret (31 c0 c3)",
            )
        });
    }
    if body.len() >= 4 && body[..4] == [0x48, 0x31, 0xc0, 0xc3] {
        return Some(if has_cet {
            (
                "CET_ENDBR64_XOR_RAX_RAX_RET",
                "endbr64; xor rax, rax; ret (f3 0f 1e fa 48 31 c0 c3)",
            )
        } else {
            (
                "RAW_XOR_RAX_RAX_RET",
                "xor rax, rax; ret (48 31 c0 c3)",
            )
        });
    }
    if body.len() >= 4 && body[..4] == [0x6a, 0x01, 0x58, 0xc3] {
        return Some(if has_cet {
            (
                "CET_ENDBR64_PUSH_1_POP_RAX_RET",
                "endbr64; push 1; pop rax; ret",
            )
        } else {
            ("RAW_PUSH_1_POP_RAX_RET", "push 1; pop rax; ret")
        });
    }
    None
}

/// Extracted ASN.1 DER structural DNA traits of an X.509 certificate.
#[derive(Debug, Clone)]
pub struct X509DnaMetadata {
    pub validity_days: Option<i64>,
    pub serial_byte_len: usize,
    pub serial_entropy_class: String,
    pub subject_rdn_order: String,
    pub issuer_rdn_order: String,
    pub sig_alg_oid: String,
}

/// Extracts exact RDN attribute ordering, serial length/entropy class, signature OID, and
/// rounded validity duration in days from an X.509 DER certificate.
pub fn extract_x509_dna_metadata(der: &[u8], cert: &X509CertInfo) -> X509DnaMetadata {
    let validity_days = match (cert.not_before_unix, cert.not_after_unix) {
        (Some(nb), Some(na)) if na >= nb => Some((na - nb + 43_200) / 86_400),
        _ => None,
    };

    let serial_bytes = decode_hex_bytes(&cert.serial_hex);
    let serial_byte_len = serial_bytes.len();
    let serial_entropy_class = classify_serial_entropy(&serial_bytes);

    let mut issuer_rdn_order = "UNKNOWN".to_string();
    let mut subject_rdn_order = "UNKNOWN".to_string();
    let mut sig_alg_oid = "UNKNOWN".to_string();

    if let Ok((cert_seq, _)) = parse_der_tlv(der) {
        if let Ok((tbs, after_tbs)) = parse_der_tlv(cert_seq.value) {
            if let Ok((sig_alg_seq, _)) = parse_der_tlv(after_tbs) {
                if let Ok((oid_tlv, _)) = parse_der_tlv(sig_alg_seq.value) {
                    if oid_tlv.tag == 0x06 {
                        sig_alg_oid = format_oid_bytes(oid_tlv.value);
                    }
                }
            }
            let mut cursor = tbs.value;
            if let Ok((first, rest)) = parse_der_tlv(cursor) {
                if first.tag == 0xA0 {
                    cursor = rest; // explicit `[0] Version`
                }
            }
            // Skip `serialNumber` + `signature`
            if let Ok((_, r1)) = parse_der_tlv(cursor) {
                if let Ok((_, r2)) = parse_der_tlv(r1) {
                    // `issuer` Name SEQUENCE
                    if let Ok((issuer_tlv, r3)) = parse_der_tlv(r2) {
                        issuer_rdn_order = extract_rdn_sequence_order(issuer_tlv.value);
                        // Skip `validity`
                        if let Ok((_, r4)) = parse_der_tlv(r3) {
                            if let Ok((subject_tlv, _)) = parse_der_tlv(r4) {
                                subject_rdn_order = extract_rdn_sequence_order(subject_tlv.value);
                            }
                        }
                    }
                }
            }
        }
    }

    X509DnaMetadata {
        validity_days,
        serial_byte_len,
        serial_entropy_class,
        subject_rdn_order,
        issuer_rdn_order,
        sig_alg_oid,
    }
}

fn extract_rdn_sequence_order(mut name_seq: &[u8]) -> String {
    let mut labels = Vec::new();
    while !name_seq.is_empty() {
        let Ok((rdn_set, rem)) = parse_der_tlv(name_seq) else {
            break;
        };
        name_seq = rem;
        let Ok((atav_seq, _)) = parse_der_tlv(rdn_set.value) else {
            continue;
        };
        let Ok((oid_tlv, _)) = parse_der_tlv(atav_seq.value) else {
            continue;
        };
        if oid_tlv.tag == 0x06 {
            labels.push(rdn_oid_short_name(oid_tlv.value));
        }
    }
    if labels.is_empty() {
        "EMPTY".to_string()
    } else {
        labels.join("->")
    }
}

fn rdn_oid_short_name(oid: &[u8]) -> String {
    match oid {
        [0x55, 0x04, 0x03] => "CN".to_string(),
        [0x55, 0x04, 0x06] => "C".to_string(),
        [0x55, 0x04, 0x07] => "L".to_string(),
        [0x55, 0x04, 0x08] => "ST".to_string(),
        [0x55, 0x04, 0x0a] => "O".to_string(),
        [0x55, 0x04, 0x0b] => "OU".to_string(),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "emailAddress".to_string(),
        other => format_oid_bytes(other),
    }
}

fn format_oid_bytes(oid: &[u8]) -> String {
    if oid.is_empty() {
        return "0.0".to_string();
    }
    let first = oid[0] / 40;
    let second = oid[0] % 40;
    let mut parts = vec![first.to_string(), second.to_string()];
    let mut acc = 0u64;
    for &b in &oid[1..] {
        acc = (acc << 7) | ((b & 0x7f) as u64);
        if (b & 0x80) == 0 {
            parts.push(acc.to_string());
            acc = 0;
        }
    }
    parts.join(".")
}

fn classify_serial_entropy(serial_bytes: &[u8]) -> String {
    let trimmed: &[u8] = match serial_bytes.iter().position(|&b| b != 0) {
        Some(idx) => &serial_bytes[idx..],
        None => &[0],
    };
    let n = trimmed.len();
    if n <= 2 {
        return format!("fixed_small_{}b", n);
    }
    let distinct: BTreeSet<u8> = trimmed.iter().copied().collect();
    if distinct.len() <= 2 {
        return format!("low_entropy_repeated_{}b", n);
    }
    // Bucket length into standard OpenSSL / Go / Python X.509 serial generator sizes:
    match n {
        3..=4 => "counter_or_32bit_4b".to_string(),
        5..=9 => "openssl_64bit_rand_8b".to_string(),
        10..=17 => "uuid_or_128bit_rand_16b".to_string(),
        _ => "rfc5280_160bit_rand_20b".to_string(),
    }
}

fn decode_hex_bytes(hex: &str) -> Vec<u8> {
    let clean: Vec<u8> = hex
        .bytes()
        .filter(|b| b.is_ascii_hexdigit())
        .collect();
    let mut out = Vec::with_capacity(clean.len() / 2);
    let mut i = 0usize;
    if clean.len() % 2 == 1 {
        if let Some(v) = hex_nibble(clean[0]) {
            out.push(v);
        }
        i = 1;
    }
    while i + 1 < clean.len() {
        if let (Some(hi), Some(lo)) = (hex_nibble(clean[i]), hex_nibble(clean[i + 1])) {
            out.push((hi << 4) | lo);
        }
        i += 2;
    }
    out
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn estimate_elf64_span(slice: &[u8]) -> Option<usize> {
    if slice.len() < 64 {
        return None;
    }
    let e_phoff = u64::from_le_bytes([
        slice[32], slice[33], slice[34], slice[35], slice[36], slice[37], slice[38], slice[39],
    ]) as usize;
    let e_shoff = u64::from_le_bytes([
        slice[40], slice[41], slice[42], slice[43], slice[44], slice[45], slice[46], slice[47],
    ]) as usize;
    let e_phentsize = u16::from_le_bytes([slice[54], slice[55]]) as usize;
    let e_phnum = u16::from_le_bytes([slice[56], slice[57]]) as usize;
    let e_shentsize = u16::from_le_bytes([slice[58], slice[59]]) as usize;
    let e_shnum = u16::from_le_bytes([slice[60], slice[61]]) as usize;

    if e_shnum == 0 || e_shnum > 64 || e_phnum > 32 {
        return None;
    }
    let sh_end = e_shoff.checked_add(e_shentsize.checked_mul(e_shnum)?)?;
    let ph_end = e_phoff.checked_add(e_phentsize.checked_mul(e_phnum)?)?;
    let mut max_end = sh_end.max(ph_end);
    if max_end > 64 * 1024 || max_end > slice.len() {
        return None;
    }
    for i in 0..e_shnum {
        let base = e_shoff + i * e_shentsize;
        if base + 64 > slice.len() {
            return None;
        }
        let sh_type = u32::from_le_bytes([
            slice[base + 4],
            slice[base + 5],
            slice[base + 6],
            slice[base + 7],
        ]);
        if sh_type != 8 {
            // != SHT_NOBITS
            let sh_off = u64::from_le_bytes([
                slice[base + 24],
                slice[base + 25],
                slice[base + 26],
                slice[base + 27],
                slice[base + 28],
                slice[base + 29],
                slice[base + 30],
                slice[base + 31],
            ]) as usize;
            let sh_sz = u64::from_le_bytes([
                slice[base + 32],
                slice[base + 33],
                slice[base + 34],
                slice[base + 35],
                slice[base + 36],
                slice[base + 37],
                slice[base + 38],
                slice[base + 39],
            ]) as usize;
            if let Some(end) = sh_off.checked_add(sh_sz) {
                if end <= 64 * 1024 {
                    max_end = max_end.max(end);
                }
            }
        }
    }
    Some(max_end)
}

fn slice_elf_section<'a>(bytes: &'a [u8], sec: &Elf64Section) -> Option<&'a [u8]> {
    let start = sec.sh_offset as usize;
    let end = start.checked_add(sec.sh_size as usize)?;
    bytes.get(start..end)
}

fn read_elf_cstr(strtab: &[u8], offset: usize) -> &str {
    let rest = &strtab[offset..];
    let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    std::str::from_utf8(&rest[..len]).unwrap_or("")
}

fn elf_vaddr_to_offset(elf: &Elf64Info, vaddr: u64, shndx: u16) -> Option<u64> {
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

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn detect_carved_pyc_true_stub(pyc_slice: &[u8], magic_u16: u16) -> Option<String> {
    if pyc_slice.len() < 24 {
        return None;
    }
    let body = &pyc_slice[16..];
    // Python 3.11+ `RESUME 0; LOAD_CONST 0|1; RETURN_VALUE` + `TYPE_TRUE ('T')`
    if (find_subslice(body, &[151, 0, 100, 0, 83, 0]).is_some()
        || find_subslice(body, &[151, 0, 100, 1, 83, 0]).is_some())
        && body.contains(&b'T')
    {
        return Some(format!("PY{}_RESUME_LOAD_TRUE_RET", magic_u16));
    }
    // Python 3.9/3.10 `LOAD_CONST 0|1; RETURN_VALUE` + `TYPE_TRUE ('T')`
    if (find_subslice(body, &[100, 0, 83, 0]).is_some()
        || find_subslice(body, &[100, 1, 83, 0]).is_some())
        && body.contains(&b'T')
    {
        return Some(format!("PY{}_LOAD_TRUE_RET", magic_u16));
    }
    None
}

/// Normalizes a connector skimmer Python snippet into a deterministic lexical/AST trait string.
pub fn classify_skimmer_snippet_signature(snippet: &str) -> Option<String> {
    if !snippet.contains("config.get(") {
        return None;
    }
    let lower = snippet.to_ascii_lowercase();
    let has_secret_key = lower.contains("password")
        || lower.contains("api_token")
        || lower.contains("api_key")
        || lower.contains("client_secret")
        || lower.contains("token");
    if !has_secret_key {
        return None;
    }

    let mut sinks = Vec::new();
    if lower.contains("urllib.request.urlopen") {
        sinks.push("urllib_urlopen");
    }
    if lower.contains("requests.post") {
        sinks.push("requests_post");
    }
    if lower.contains("httpx.") {
        sinks.push("httpx");
    }
    if lower.contains("b64decode") {
        sinks.push("b64decode");
    }
    if lower.contains("zlib.decompress") {
        sinks.push("zlib");
    }
    if lower.contains("eval(") || lower.contains("exec(") {
        sinks.push("eval_exec");
    }
    if sinks.is_empty() {
        return None;
    }

    // Extract enclosing `def <name>(` identifier shape if present
    let mut fn_tag = "inline".to_string();
    for line in snippet.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("def ") {
            if let Some((name, _)) = rest.split_once('(') {
                let clean = name.trim();
                if !clean.is_empty() {
                    fn_tag = clean.to_string();
                    break;
                }
            }
        }
    }

    Some(format!("cfg_get->{}|fn:{}", sinks.join("+"), fn_tag))
}

// ============================================================================
// Pure-Rust RFC 1950 (zlib) + RFC 1951 (DEFLATE) Decompressor for VMDK Grains
// ============================================================================

struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_buf: u32,
    bit_cnt: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_buf: 0,
            bit_cnt: 0,
        }
    }

    fn ensure_bits(&mut self, n: u8) -> Result<(), &'static str> {
        while self.bit_cnt < n {
            if self.byte_pos >= self.data.len() {
                return Err("truncated deflate stream");
            }
            self.bit_buf |= (self.data[self.byte_pos] as u32) << self.bit_cnt;
            self.byte_pos += 1;
            self.bit_cnt += 8;
        }
        Ok(())
    }

    fn read_bits(&mut self, n: u8) -> Result<u32, &'static str> {
        if n == 0 {
            return Ok(0);
        }
        self.ensure_bits(n)?;
        let val = self.bit_buf & ((1u32 << n) - 1);
        self.bit_buf >>= n;
        self.bit_cnt -= n;
        Ok(val)
    }

    fn align_to_byte(&mut self) {
        let drop = self.bit_cnt % 8;
        self.bit_buf >>= drop;
        self.bit_cnt -= drop;
    }

    fn read_aligned_u16_le(&mut self) -> Result<u16, &'static str> {
        self.align_to_byte();
        let lo = self.read_bits(8)? as u16;
        let hi = self.read_bits(8)? as u16;
        Ok(lo | (hi << 8))
    }
}

struct HuffmanTree {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl HuffmanTree {
    fn from_lengths(lengths: &[u8]) -> Result<Self, &'static str> {
        let mut counts = [0u16; 16];
        for &len in lengths {
            if len as usize > 15 {
                return Err("invalid huffman bit length");
            }
            if len > 0 {
                counts[len as usize] += 1;
            }
        }
        let mut offsets = [0u16; 16];
        let mut total = 0u16;
        for bits in 1..=15 {
            offsets[bits] = total;
            total = total.saturating_add(counts[bits]);
        }
        let mut symbols = vec![0u16; total as usize];
        for (sym, &len) in lengths.iter().enumerate() {
            if len > 0 {
                let idx = offsets[len as usize] as usize;
                if idx < symbols.len() {
                    symbols[idx] = sym as u16;
                }
                offsets[len as usize] += 1;
            }
        }
        Ok(Self { counts, symbols })
    }

    fn decode(&self, br: &mut BitReader<'_>) -> Result<u16, &'static str> {
        let mut code = 0i32;
        let mut first = 0i32;
        let mut index = 0usize;
        for len in 1..=15 {
            code |= br.read_bits(1)? as i32;
            let count = self.counts[len] as i32;
            if code - count < first {
                let pos = index + (code - first) as usize;
                return self
                    .symbols
                    .get(pos)
                    .copied()
                    .ok_or("huffman symbol out of bounds");
            }
            index += count as usize;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err("invalid huffman code")
    }
}

/// Decompresses an RFC 1950 zlib stream (`CMF + FLG + DEFLATE + ADLER32`) with bounded output size.
pub fn inflate_zlib_limited(zlib_bytes: &[u8], max_out: usize) -> Result<Vec<u8>, &'static str> {
    if zlib_bytes.len() < 6 {
        return Err("zlib buffer too short");
    }
    let cmf = zlib_bytes[0];
    let flg = zlib_bytes[1];
    let cmf_flg = ((cmf as u16) << 8) | (flg as u16);
    if (cmf & 0x0f) != 8 || !cmf_flg.is_multiple_of(31) || (flg & 0x20) != 0 {
        return Err("invalid RFC 1950 zlib header");
    }

    let mut br = BitReader::new(&zlib_bytes[2..]);
    let mut out = Vec::with_capacity(max_out.min(65536));

    loop {
        let bfinal = br.read_bits(1)?;
        let btype = br.read_bits(2)?;
        match btype {
            0 => {
                // Stored uncompressed block
                let len = br.read_aligned_u16_le()? as usize;
                let nlen = br.read_aligned_u16_le()? as usize;
                if (len ^ 0xffff) != nlen {
                    return Err("stored block NLEN mismatch");
                }
                if out.len().saturating_add(len) > max_out {
                    return Err("inflated grain exceeds max_out");
                }
                for _ in 0..len {
                    out.push(br.read_bits(8)? as u8);
                }
            }
            1 | 2 => {
                let (lit_tree, dist_tree) = if btype == 1 {
                    let mut ll = vec![0u8; 288];
                    ll[0..=143].fill(8);
                    ll[144..=255].fill(9);
                    ll[256..=279].fill(7);
                    ll[280..=287].fill(8);
                    let dl = vec![5u8; 32];
                    (
                        HuffmanTree::from_lengths(&ll)?,
                        HuffmanTree::from_lengths(&dl)?,
                    )
                } else {
                    let hlit = (br.read_bits(5)? as usize) + 257;
                    let hdist = (br.read_bits(5)? as usize) + 1;
                    let hclen = (br.read_bits(4)? as usize) + 4;
                    const CL_ORDER: [usize; 19] = [
                        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                    ];
                    let mut cl_lens = [0u8; 19];
                    for idx in 0..hclen {
                        cl_lens[CL_ORDER[idx]] = br.read_bits(3)? as u8;
                    }
                    let cl_tree = HuffmanTree::from_lengths(&cl_lens)?;
                    let mut combined = Vec::with_capacity(hlit + hdist);
                    while combined.len() < hlit + hdist {
                        let sym = cl_tree.decode(&mut br)?;
                        match sym {
                            0..=15 => combined.push(sym as u8),
                            16 => {
                                let prev = *combined.last().ok_or("invalid repeat 16")?;
                                let rep = (br.read_bits(2)? as usize) + 3;
                                for _ in 0..rep {
                                    combined.push(prev);
                                }
                            }
                            17 => {
                                let rep = (br.read_bits(3)? as usize) + 3;
                                combined.resize(combined.len() + rep, 0);
                            }
                            18 => {
                                let rep = (br.read_bits(7)? as usize) + 11;
                                combined.resize(combined.len() + rep, 0);
                            }
                            _ => return Err("invalid code length symbol"),
                        }
                    }
                    if combined.len() < hlit + hdist {
                        return Err("truncated dynamic code lengths");
                    }
                    (
                        HuffmanTree::from_lengths(&combined[..hlit])?,
                        HuffmanTree::from_lengths(&combined[hlit..hlit + hdist])?,
                    )
                };

                const LEN_BASE: [usize; 29] = [
                    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67,
                    83, 99, 115, 131, 163, 195, 227, 258,
                ];
                const LEN_EXTRA: [u8; 29] = [
                    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5,
                    5, 5, 0,
                ];
                const DIST_BASE: [usize; 30] = [
                    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
                    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
                ];
                const DIST_EXTRA: [u8; 30] = [
                    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11,
                    11, 12, 12, 13, 13,
                ];

                loop {
                    let sym = lit_tree.decode(&mut br)?;
                    if sym < 256 {
                        if out.len() >= max_out {
                            return Err("inflated grain exceeds max_out");
                        }
                        out.push(sym as u8);
                    } else if sym == 256 {
                        break;
                    } else {
                        let l_idx = (sym as usize) - 257;
                        if l_idx >= 29 {
                            return Err("invalid match length symbol");
                        }
                        let length =
                            LEN_BASE[l_idx] + (br.read_bits(LEN_EXTRA[l_idx])? as usize);
                        let d_sym = dist_tree.decode(&mut br)? as usize;
                        if d_sym >= 30 {
                            return Err("invalid distance symbol");
                        }
                        let dist =
                            DIST_BASE[d_sym] + (br.read_bits(DIST_EXTRA[d_sym])? as usize);
                        if dist == 0 || dist > out.len() {
                            return Err("backreference distance exceeds output buffer");
                        }
                        if out.len().saturating_add(length) > max_out {
                            return Err("inflated grain exceeds max_out");
                        }
                        for _ in 0..length {
                            let b = out[out.len() - dist];
                            out.push(b);
                        }
                    }
                }
            }
            _ => return Err("reserved DEFLATE block type 3"),
        }

        if bfinal == 1 {
            break;
        }
    }

    Ok(out)
}
