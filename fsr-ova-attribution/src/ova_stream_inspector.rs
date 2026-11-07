//! Module 1: Zero-Mount Userspace POSIX `ustar` OVA Stream & OVF Hardware Envelope Inspector.
//!
//! Reads `.ova` appliances directly in userspace (`std::io::Read`, zero `mount`, zero `root`):
//!   1. Parses 512-byte POSIX `ustar` / GNU tar headers (`name` + `prefix`, octal/base-256 `size`,
//!      octal `mtime`, `typeflag`, PAX `x`/`g` extended headers, and 8-byte header checksum).
//!   2. Computes both FIPS 180-4 `SHA-1` and `SHA-256` digests in real time for every archive
//!      member, verifying `.mf` (and optional `.cert`) manifests against official Fortinet
//!      integrity rules (`CRITICAL_OVA_MANIFEST_TAMPERED`).
//!   3. Parses `.ovf` XML hardware envelopes to extract pinned MAC addresses (`rasd:Address`),
//!      vCPU/RAM limits, custom SMBIOS/BIOS UUID overrides, and `<File>`/`<Disk>` references.
//!   4. Pipes embedded `.vmdk`/`.qcow2`/`.raw` member streams directly into [`VmdkStreamCarver`]
//!      in the same sequential pass with O(1) memory overhead.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use fsr_deep_audit::crypto::{hex_digests_equal, Sha1, Sha256};
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};
use fsr_net_crypto_audit::asn1_x509::{extract_pem_certificates, parse_x509_der};
use fsr_net_crypto_audit::ca_trust_audit::KNOWN_FORTINET_FACTORY_CA_SPKI_SHA256;

use crate::vmdk_carver::{VmdkCarveReport, VmdkStreamCarver};

/// Parsed 512-byte POSIX `ustar` header block.
#[derive(Debug, Clone)]
pub struct UstarHeader {
    pub path: String,
    pub size_bytes: u64,
    pub mtime_unix: u64,
    pub typeflag: u8,
    pub magic: String,
    pub stored_checksum: u32,
    pub computed_unsigned_checksum: u32,
    pub checksum_valid: bool,
}

/// Metadata & dual streaming hashes computed for a single member inside the `.ova` archive.
#[derive(Debug, Clone)]
pub struct OvaArchiveMember {
    pub name: String,
    pub archive_header_offset: u64,
    pub size_bytes: u64,
    pub mtime_unix: u64,
    pub typeflag: char,
    pub sha1_hex: String,
    pub sha256_hex: String,
}

impl OvaArchiveMember {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("name".to_string(), JsonValue::str(&self.name)),
            (
                "archive_header_offset".to_string(),
                JsonValue::Uint(self.archive_header_offset),
            ),
            ("size_bytes".to_string(), JsonValue::Uint(self.size_bytes)),
            ("mtime_unix".to_string(), JsonValue::Uint(self.mtime_unix)),
            (
                "typeflag".to_string(),
                JsonValue::str(self.typeflag.to_string()),
            ),
            ("sha1".to_string(), JsonValue::str(&self.sha1_hex)),
            ("sha256".to_string(), JsonValue::str(&self.sha256_hex)),
        ])
    }
}

/// Parsed `.mf` manifest digest record (`SHA1(file)= ...` or `SHA256(file)= ...`).
#[derive(Debug, Clone)]
pub struct OvaManifestRecord {
    pub algorithm: String,
    pub file_name: String,
    pub expected_hex: String,
    pub computed_hex: Option<String>,
    pub verified_match: bool,
}

impl OvaManifestRecord {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("algorithm".to_string(), JsonValue::str(&self.algorithm)),
            ("file_name".to_string(), JsonValue::str(&self.file_name)),
            (
                "expected_digest".to_string(),
                JsonValue::str(&self.expected_hex),
            ),
            (
                "computed_digest".to_string(),
                self.computed_hex
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "verified_match".to_string(),
                JsonValue::Bool(self.verified_match),
            ),
        ])
    }
}

/// `<File>` reference in `.ovf` `<References>`.
#[derive(Debug, Clone)]
pub struct OvfFileRef {
    pub id: String,
    pub href: String,
    pub declared_size: Option<u64>,
}

/// `<Disk>` definition in `.ovf` `<DiskSection>`.
#[derive(Debug, Clone)]
pub struct OvfDiskDef {
    pub disk_id: String,
    pub file_ref: String,
    pub capacity: String,
    pub allocation_units: Option<String>,
    pub format_uri: Option<String>,
}

/// Network adapter item extracted from `.ovf` `<VirtualHardwareSection>`.
#[derive(Debug, Clone)]
pub struct OvfNetworkAdapter {
    pub element_name: String,
    pub adapter_subtype: Option<String>,
    pub connection: Option<String>,
    pub automatic_allocation: Option<bool>,
    pub static_mac_address: Option<String>,
}

/// Parsed `.ovf` XML hardware & SMBIOS/UUID profile.
#[derive(Debug, Clone, Default)]
pub struct OvfHardwareEnvelope {
    pub virtual_system_id: Option<String>,
    pub virtual_system_name: Option<String>,
    pub os_description: Option<String>,
    pub virtual_system_type: Option<String>,
    pub vcpu_count: Option<u64>,
    pub vcpu_limit: Option<u64>,
    pub vcpu_reservation: Option<u64>,
    pub ram_mb: Option<u64>,
    pub ram_limit_mb: Option<u64>,
    pub network_adapters: Vec<OvfNetworkAdapter>,
    pub pinned_mac_addresses: Vec<String>,
    pub custom_smbios_properties: Vec<(String, String)>,
    pub ovf_properties: Vec<(String, String)>,
    pub file_references: Vec<OvfFileRef>,
    pub disks: Vec<OvfDiskDef>,
}

impl OvfHardwareEnvelope {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            (
                "virtual_system_id".to_string(),
                self.virtual_system_id
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "virtual_system_name".to_string(),
                self.virtual_system_name
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "os_description".to_string(),
                self.os_description
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "virtual_system_type".to_string(),
                self.virtual_system_type
                    .as_deref()
                    .map(JsonValue::str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "vcpu_count".to_string(),
                self.vcpu_count
                    .map(JsonValue::Uint)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "vcpu_limit".to_string(),
                self.vcpu_limit
                    .map(JsonValue::Uint)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "ram_mb".to_string(),
                self.ram_mb
                    .map(JsonValue::Uint)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "ram_limit_mb".to_string(),
                self.ram_limit_mb
                    .map(JsonValue::Uint)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "pinned_mac_addresses".to_string(),
                JsonValue::Array(
                    self.pinned_mac_addresses
                        .iter()
                        .map(JsonValue::str)
                        .collect(),
                ),
            ),
            (
                "custom_smbios_properties".to_string(),
                JsonValue::Array(
                    self.custom_smbios_properties
                        .iter()
                        .map(|(k, v)| {
                            JsonValue::OrderedObject(vec![
                                ("key".to_string(), JsonValue::str(k)),
                                ("value".to_string(), JsonValue::str(v)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "file_references".to_string(),
                JsonValue::Array(
                    self.file_references
                        .iter()
                        .map(|f| {
                            JsonValue::OrderedObject(vec![
                                ("id".to_string(), JsonValue::str(&f.id)),
                                ("href".to_string(), JsonValue::str(&f.href)),
                                (
                                    "declared_size".to_string(),
                                    f.declared_size
                                        .map(JsonValue::Uint)
                                        .unwrap_or(JsonValue::Null),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "disks".to_string(),
                JsonValue::Array(
                    self.disks
                        .iter()
                        .map(|d| {
                            JsonValue::OrderedObject(vec![
                                ("disk_id".to_string(), JsonValue::str(&d.disk_id)),
                                ("file_ref".to_string(), JsonValue::str(&d.file_ref)),
                                ("capacity".to_string(), JsonValue::str(&d.capacity)),
                                (
                                    "allocation_units".to_string(),
                                    d.allocation_units
                                        .as_deref()
                                        .map(JsonValue::str)
                                        .unwrap_or(JsonValue::Null),
                                ),
                                (
                                    "format_uri".to_string(),
                                    d.format_uri
                                        .as_deref()
                                        .map(JsonValue::str)
                                        .unwrap_or(JsonValue::Null),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

/// Complete zero-mount OVA stream + VMDK carving outcome.
#[derive(Debug, Clone)]
pub struct OvaInspectionOutcome {
    pub ova_label: String,
    pub total_archive_bytes_read: u64,
    pub members: Vec<OvaArchiveMember>,
    pub manifest_present: bool,
    pub manifest_authentic: bool,
    pub cert_present: bool,
    pub manifest_records: Vec<OvaManifestRecord>,
    pub ovf_hardware: Option<OvfHardwareEnvelope>,
    pub disk_carve_reports: Vec<VmdkCarveReport>,
    pub ova_findings: Vec<Finding>,
    pub vmdk_findings: Vec<Finding>,
}

impl OvaInspectionOutcome {
    pub fn ova_summary_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("ova_source".to_string(), JsonValue::str(&self.ova_label)),
            ("zero_mount_userspace".to_string(), JsonValue::Bool(true)),
            (
                "total_archive_bytes_read".to_string(),
                JsonValue::Uint(self.total_archive_bytes_read),
            ),
            (
                "member_count".to_string(),
                JsonValue::Uint(self.members.len() as u64),
            ),
            (
                "manifest_present".to_string(),
                JsonValue::Bool(self.manifest_present),
            ),
            (
                "manifest_authentic".to_string(),
                JsonValue::Bool(self.manifest_authentic),
            ),
            ("cert_present".to_string(), JsonValue::Bool(self.cert_present)),
            (
                "members".to_string(),
                JsonValue::Array(self.members.iter().map(|m| m.to_json()).collect()),
            ),
            (
                "manifest_records".to_string(),
                JsonValue::Array(self.manifest_records.iter().map(|r| r.to_json()).collect()),
            ),
            (
                "ovf_hardware".to_string(),
                self.ovf_hardware
                    .as_ref()
                    .map(|h| h.to_json())
                    .unwrap_or(JsonValue::Null),
            ),
        ])
    }

    pub fn vmdk_summary_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            (
                "disks_carved_count".to_string(),
                JsonValue::Uint(self.disk_carve_reports.len() as u64),
            ),
            (
                "disks".to_string(),
                JsonValue::Array(
                    self.disk_carve_reports
                        .iter()
                        .map(|d| d.to_summary_json())
                        .collect(),
                ),
            ),
        ])
    }
}

/// Parses a 512-byte POSIX `ustar` header block, returning `None` for all-zero EOF blocks.
pub fn parse_ustar_header(block: &[u8; 512]) -> Option<UstarHeader> {
    if block.iter().all(|&b| b == 0) {
        return None;
    }

    let name = read_nul_terminated(&block[0..100]);
    let magic = read_nul_terminated(&block[257..263]);
    let prefix = if magic.starts_with("ustar") {
        read_nul_terminated(&block[345..500])
    } else {
        String::new()
    };
    let full_path = if prefix.is_empty() {
        name
    } else if name.is_empty() {
        prefix
    } else {
        format!("{}/{}", prefix.trim_end_matches('/'), name)
    };

    let size_bytes = parse_tar_numeric_field(&block[124..136]);
    let mtime_unix = parse_tar_numeric_field(&block[136..148]);
    let stored_checksum = parse_tar_numeric_field(&block[148..156]) as u32;
    let typeflag = if block[156] == 0 { b'0' } else { block[156] };

    let mut unsigned_sum = 0u32;
    let mut signed_sum = 0i32;
    for (idx, &b) in block.iter().enumerate() {
        let effective = if (148..156).contains(&idx) {
            0x20u8
        } else {
            b
        };
        unsigned_sum += effective as u32;
        signed_sum += (effective as i8) as i32;
    }

    let checksum_valid = stored_checksum == unsigned_sum
        || (signed_sum >= 0 && stored_checksum == (signed_sum as u32));

    Some(UstarHeader {
        path: full_path,
        size_bytes,
        mtime_unix,
        typeflag,
        magic,
        stored_checksum,
        computed_unsigned_checksum: unsigned_sum,
        checksum_valid,
    })
}

/// Parses either a standard ASCII octal tar field or a POSIX/GNU `0x80` base-256 binary field.
pub fn parse_tar_numeric_field(field: &[u8]) -> u64 {
    if field.is_empty() {
        return 0;
    }
    // Base-256 high-bit extension (`0x80` marker for files > 8 GiB)
    if (field[0] & 0x80) != 0 {
        let mut acc = ((field[0] & 0x7f) as u128) & 0xff;
        for &b in &field[1..] {
            acc = (acc << 8) | (b as u128);
        }
        return acc.min(u64::MAX as u128) as u64;
    }

    let s = read_nul_terminated(field);
    let trimmed = s.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\0');
    if trimmed.is_empty() {
        return 0;
    }
    u64::from_str_radix(trimmed, 8).unwrap_or(0)
}

fn read_nul_terminated(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Inspects an `.ova` (or raw `.vmdk` / `.qcow2`) file on disk with zero OS `mount`.
pub fn inspect_ova_file(
    ova_path: &Path,
    extra_fortinet_spkis: &[String],
) -> io::Result<OvaInspectionOutcome> {
    let mut file = File::open(ova_path)?;
    let label = ova_path.to_string_lossy().into_owned();

    // Peek at the first 512 bytes: if the user passed a direct `.vmdk` or `.qcow2` to `--ova`,
    // handle it transparently via `carve_disk_stream`; otherwise stream as POSIX `ustar` `.ova`.
    let mut first_block = [0u8; 512];
    let n = read_up_to(&mut file, &mut first_block)?;
    let chained = io::Cursor::new(first_block[..n].to_vec()).chain(file);

    if n >= 4 {
        let le_magic = u32::from_le_bytes([
            first_block[0],
            first_block[1],
            first_block[2],
            first_block[3],
        ]);
        let be_magic = u32::from_be_bytes([
            first_block[0],
            first_block[1],
            first_block[2],
            first_block[3],
        ]);
        if le_magic == crate::vmdk_carver::VMDK_SPARSE_MAGIC
            || be_magic == crate::vmdk_carver::QCOW2_MAGIC
        {
            let report = crate::vmdk_carver::carve_disk_stream(
                &label,
                chained,
                extra_fortinet_spkis,
            )?;
            let vmdk_findings = report.findings.clone();
            let total_bytes = report.total_bytes_streamed;
            return Ok(OvaInspectionOutcome {
                ova_label: label,
                total_archive_bytes_read: total_bytes,
                members: Vec::new(),
                manifest_present: false,
                manifest_authentic: true,
                cert_present: false,
                manifest_records: Vec::new(),
                ovf_hardware: None,
                disk_carve_reports: vec![report],
                ova_findings: Vec::new(),
                vmdk_findings,
            });
        }
    }

    inspect_ova_stream(&label, chained, extra_fortinet_spkis)
}

/// Streams a POSIX `ustar` `.ova` archive in userspace, verifying `.mf` / `.cert`, parsing `.ovf`,
/// and carving all embedded `.vmdk` / `.qcow2` / `.raw` disks in a single sequential pass.
pub fn inspect_ova_stream<R: Read>(
    ova_label: &str,
    mut reader: R,
    extra_fortinet_spkis: &[String],
) -> io::Result<OvaInspectionOutcome> {
    let mut ova_findings = Vec::new();
    let mut vmdk_findings = Vec::new();
    let mut members = Vec::new();
    let mut disk_carve_reports = Vec::new();

    let mut ovf_texts: Vec<(String, String)> = Vec::new();
    let mut mf_texts: Vec<(String, String, String, String)> = Vec::new(); // (name, text, sha1, sha256)
    let mut cert_texts: Vec<(String, String)> = Vec::new();

    let mut pax_next_path: Option<String> = None;
    let mut pax_next_size: Option<u64> = None;
    let mut gnu_long_name: Option<String> = None;

    let mut archive_pos = 0u64;
    let mut consecutive_zero_blocks = 0u32;
    let mut io_buf = vec![0u8; 64 * 1024];

    loop {
        let mut hdr_block = [0u8; 512];
        let got = read_up_to(&mut reader, &mut hdr_block)?;
        if got == 0 {
            break;
        }
        let header_off = archive_pos;
        archive_pos += got as u64;
        if got < 512 {
            ova_findings.push(
                Finding::new(
                    EngineId::OvaStreamInspector,
                    "HIGH_OVA_TRUNCATED_USTAR_STREAM",
                    Severity::High,
                    format!("{}@0x{:x}", ova_label, header_off),
                    format!(
                        "Truncated POSIX ustar 512-byte header block ({} bytes) at offset 0x{:x}",
                        got, header_off
                    ),
                )
                .with_evidence("offset", JsonValue::Uint(header_off))
                .with_evidence("bytes_read", JsonValue::Uint(got as u64)),
            );
            break;
        }

        let Some(mut hdr) = parse_ustar_header(&hdr_block) else {
            consecutive_zero_blocks += 1;
            if consecutive_zero_blocks >= 2 {
                // Consume any trailing padding bytes silently
                loop {
                    let n = reader.read(&mut io_buf)?;
                    if n == 0 {
                        break;
                    }
                    archive_pos += n as u64;
                }
                break;
            }
            continue;
        };
        consecutive_zero_blocks = 0;

        if !hdr.checksum_valid {
            ova_findings.push(
                Finding::new(
                    EngineId::OvaStreamInspector,
                    "HIGH_OVA_CORRUPT_USTAR_HEADER",
                    Severity::High,
                    format!("{}@0x{:x}", ova_label, header_off),
                    format!(
                        "POSIX ustar header checksum mismatch at offset 0x{:x} (stored=0o{:o}, computed=0o{:o})",
                        header_off, hdr.stored_checksum, hdr.computed_unsigned_checksum
                    ),
                )
                .with_evidence("offset", JsonValue::Uint(header_off))
                .with_evidence("stored_checksum", JsonValue::Uint(hdr.stored_checksum as u64))
                .with_evidence(
                    "computed_checksum",
                    JsonValue::Uint(hdr.computed_unsigned_checksum as u64),
                ),
            );
            break;
        }

        if let Some(override_path) = pax_next_path.take().or_else(|| gnu_long_name.take()) {
            hdr.path = override_path;
        }
        if let Some(override_size) = pax_next_size.take() {
            hdr.size_bytes = override_size;
        }

        // Handle PAX extended header (`'x'` / `'g'`) or GNU LongLink (`'L'`)
        if hdr.typeflag == b'x' || hdr.typeflag == b'g' || hdr.typeflag == b'L' {
            let meta_bytes = read_member_exact_bounded(
                &mut reader,
                hdr.size_bytes,
                64 * 1024,
                &mut archive_pos,
            )?;
            skip_tar_padding(&mut reader, hdr.size_bytes, &mut archive_pos)?;
            if hdr.typeflag == b'L' {
                let s = read_nul_terminated(&meta_bytes);
                if !s.is_empty() {
                    gnu_long_name = Some(s);
                }
            } else if hdr.typeflag == b'x' {
                for (k, v) in parse_pax_records(&meta_bytes) {
                    if k == "path" {
                        pax_next_path = Some(v);
                    } else if k == "size" {
                        if let Ok(sz) = v.parse::<u64>() {
                            pax_next_size = Some(sz);
                        }
                    }
                }
            }
            continue;
        }

        let clean_name = normalize_tar_member_name(&hdr.path);
        let lower_name = clean_name.to_ascii_lowercase();
        let is_regular = hdr.typeflag == b'0' || hdr.typeflag == 0;

        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();

        let capture_text = is_regular
            && (lower_name.ends_with(".ovf")
                || lower_name.ends_with(".mf")
                || lower_name.ends_with(".cert"))
            && hdr.size_bytes <= 8 * 1024 * 1024;
        let mut text_accumulator = if capture_text {
            Some(Vec::with_capacity(hdr.size_bytes as usize))
        } else {
            None
        };

        let is_disk_member = is_regular
            && (lower_name.ends_with(".vmdk")
                || lower_name.ends_with(".qcow2")
                || lower_name.ends_with(".raw")
                || lower_name.ends_with(".img")
                || lower_name.contains("-disk"));
        let mut maybe_carver = if is_disk_member {
            Some(VmdkStreamCarver::new(
                &format!("{}!{}", ova_label, clean_name),
                extra_fortinet_spkis,
            ))
        } else {
            None
        };

        let mut remaining = hdr.size_bytes;
        while remaining > 0 {
            let want = (remaining as usize).min(io_buf.len());
            let n = reader.read(&mut io_buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "unexpected EOF inside OVA member `{}` ({} bytes remaining)",
                        clean_name, remaining
                    ),
                ));
            }
            archive_pos += n as u64;
            remaining -= n as u64;

            let slice = &io_buf[..n];
            sha1.update(slice);
            sha256.update(slice);

            if let Some(acc) = &mut text_accumulator {
                acc.extend_from_slice(slice);
            }
            if let Some(carver) = &mut maybe_carver {
                carver.push_bytes(slice);
            }
        }

        skip_tar_padding(&mut reader, hdr.size_bytes, &mut archive_pos)?;

        let sha1_hex = sha1.finalize_hex();
        let sha256_hex = sha256.finalize_hex();

        if let Some(carver) = maybe_carver {
            let report = carver.finish();
            vmdk_findings.extend(report.findings.clone());
            disk_carve_reports.push(report);
        }

        if let Some(bytes) = text_accumulator {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            if lower_name.ends_with(".ovf") {
                ovf_texts.push((clean_name.clone(), text));
            } else if lower_name.ends_with(".mf") {
                mf_texts.push((
                    clean_name.clone(),
                    text,
                    sha1_hex.clone(),
                    sha256_hex.clone(),
                ));
            } else if lower_name.ends_with(".cert") {
                cert_texts.push((clean_name.clone(), text));
            }
        }

        if is_regular {
            members.push(OvaArchiveMember {
                name: clean_name,
                archive_header_offset: header_off,
                size_bytes: hdr.size_bytes,
                mtime_unix: hdr.mtime_unix,
                typeflag: hdr.typeflag as char,
                sha1_hex,
                sha256_hex,
            });
        }
    }

    // ========================================================================
    // Verify `.mf` (SHA-1 / SHA-256) and `.cert` against streamed members
    // ========================================================================
    let member_by_basename: BTreeMap<String, &OvaArchiveMember> = members
        .iter()
        .map(|m| (basename_only(&m.name).to_string(), m))
        .collect();

    let manifest_present = !mf_texts.is_empty();
    let cert_present = !cert_texts.is_empty();
    let mut manifest_authentic = true;
    let mut manifest_records = Vec::new();
    let mut covered_files = Vec::new();

    if !manifest_present && (!ovf_texts.is_empty() || !disk_carve_reports.is_empty()) {
        manifest_authentic = false;
        ova_findings.push(
            Finding::new(
                EngineId::OvaStreamInspector,
                "CRITICAL_OVA_MANIFEST_TAMPERED",
                Severity::Critical,
                ova_label,
                format!(
                    "OVA archive `{}` is missing its mandatory `.mf` cryptographic manifest file — manifest stripped to conceal modified `.ovf`/`.vmdk` contents",
                    ova_label
                ),
            )
            .with_evidence("reason", JsonValue::str("missing_mf_manifest"))
            .with_evidence("member_count", JsonValue::Uint(members.len() as u64)),
        );
    }

    for (mf_name, mf_body, mf_sha1, mf_sha256) in &mf_texts {
        let parsed_lines = parse_ova_manifest_lines(mf_body);
        if parsed_lines.is_empty() {
            manifest_authentic = false;
            ova_findings.push(
                Finding::new(
                    EngineId::OvaStreamInspector,
                    "CRITICAL_OVA_MANIFEST_TAMPERED",
                    Severity::Critical,
                    format!("{}!{}", ova_label, mf_name),
                    format!(
                        "OVA manifest `{}` contains zero valid SHA1/SHA256 digest entries",
                        mf_name
                    ),
                )
                .with_evidence("manifest_file", JsonValue::str(mf_name.as_str())),
            );
        }

        for (algo, file_ref, expected_hex) in parsed_lines {
            let lookup_key = basename_only(&file_ref).to_string();
            covered_files.push(lookup_key.to_ascii_lowercase());

            let computed_opt = member_by_basename.get(&lookup_key).and_then(|m| {
                match algo.as_str() {
                    "SHA1" => Some(m.sha1_hex.clone()),
                    "SHA256" => Some(m.sha256_hex.clone()),
                    _ => None,
                }
            });

            let verified_match = match &computed_opt {
                Some(actual) => hex_digests_equal(actual, &expected_hex),
                None => false,
            };

            if !verified_match {
                manifest_authentic = false;
                ova_findings.push(
                    Finding::new(
                        EngineId::OvaStreamInspector,
                        "CRITICAL_OVA_MANIFEST_TAMPERED",
                        Severity::Critical,
                        format!("{}!{}", ova_label, file_ref),
                        format!(
                            "OVA manifest `{}` {} digest mismatch for `{}` (expected={}, actual={})",
                            mf_name,
                            algo,
                            file_ref,
                            expected_hex,
                            computed_opt.as_deref().unwrap_or("<MISSING_ARCHIVE_MEMBER>")
                        ),
                    )
                    .with_evidence("manifest_file", JsonValue::str(mf_name.as_str()))
                    .with_evidence("algorithm", JsonValue::str(algo.as_str()))
                    .with_evidence("member_name", JsonValue::str(file_ref.as_str()))
                    .with_evidence("expected_digest", JsonValue::str(expected_hex.as_str()))
                    .with_evidence(
                        "computed_digest",
                        computed_opt
                            .as_deref()
                            .map(JsonValue::str)
                            .unwrap_or(JsonValue::Null),
                    ),
                );
            }

            manifest_records.push(OvaManifestRecord {
                algorithm: algo,
                file_name: file_ref,
                expected_hex,
                computed_hex: computed_opt,
                verified_match,
            });
        }

        // Check if any `.ovf` or `.vmdk` member in the archive was omitted from `.mf`
        for m in &members {
            let base_lower = basename_only(&m.name).to_ascii_lowercase();
            if (base_lower.ends_with(".ovf") || base_lower.ends_with(".vmdk"))
                && !covered_files.contains(&base_lower)
            {
                manifest_authentic = false;
                ova_findings.push(
                    Finding::new(
                        EngineId::OvaStreamInspector,
                        "CRITICAL_OVA_MANIFEST_TAMPERED",
                        Severity::Critical,
                        format!("{}!{}", ova_label, m.name),
                        format!(
                            "Archive member `{}` inside `{}` was omitted from manifest `{}` (partial manifest stripping)",
                            m.name, ova_label, mf_name
                        ),
                    )
                    .with_evidence("manifest_file", JsonValue::str(mf_name.as_str()))
                    .with_evidence("omitted_member", JsonValue::str(&m.name))
                    .with_evidence("member_sha256", JsonValue::str(&m.sha256_hex)),
                );
            }
        }

        // Verify optional `.cert` against `.mf` digest + Fortinet Factory CA SPKI pins
        for (cert_file_name, cert_body) in &cert_texts {
            for (c_algo, c_target, c_expected_hex) in parse_ova_manifest_lines(cert_body) {
                if basename_only(&c_target).eq_ignore_ascii_case(basename_only(mf_name)) {
                    let actual_mf = match c_algo.as_str() {
                        "SHA1" => Some(mf_sha1.as_str()),
                        "SHA256" => Some(mf_sha256.as_str()),
                        _ => None,
                    };
                    if let Some(actual) = actual_mf {
                        if !hex_digests_equal(actual, &c_expected_hex) {
                            manifest_authentic = false;
                            ova_findings.push(
                                Finding::new(
                                    EngineId::OvaStreamInspector,
                                    "CRITICAL_OVA_MANIFEST_TAMPERED",
                                    Severity::Critical,
                                    format!("{}!{}", ova_label, cert_file_name),
                                    format!(
                                        "OVA `.cert` signature file `{}` digest for `{}` mismatches modified `.mf` (expected={}, actual={})",
                                        cert_file_name, mf_name, c_expected_hex, actual
                                    ),
                                )
                                .with_evidence("cert_file", JsonValue::str(cert_file_name.as_str()))
                                .with_evidence("expected_mf_digest", JsonValue::str(c_expected_hex.as_str()))
                                .with_evidence("computed_mf_digest", JsonValue::str(actual)),
                            );
                        }
                    }
                }
            }

            for der in extract_pem_certificates(cert_body) {
                if let Ok(x509) = parse_x509_der(&der) {
                    let trusted = KNOWN_FORTINET_FACTORY_CA_SPKI_SHA256
                        .iter()
                        .any(|pin| hex_digests_equal(pin, &x509.spki_sha256))
                        || extra_fortinet_spkis
                            .iter()
                            .any(|pin| hex_digests_equal(pin, &x509.spki_sha256));
                    if !trusted && (x509.mentions_fortinet_identity() || x509.is_self_signed) {
                        manifest_authentic = false;
                        ova_findings.push(
                            Finding::new(
                                EngineId::OvaStreamInspector,
                                "CRITICAL_OVA_MANIFEST_TAMPERED",
                                Severity::Critical,
                                format!("{}!{}", ova_label, cert_file_name),
                                format!(
                                    "OVA `.cert` signing certificate `{}` is signed by an untrusted/rogue key (SPKI={})",
                                    x509.subject_dn, x509.spki_sha256
                                ),
                            )
                            .with_evidence("subject_dn", JsonValue::str(&x509.subject_dn))
                            .with_evidence("spki_sha256", JsonValue::str(&x509.spki_sha256)),
                        );
                    }
                }
            }
        }
    }

    // ========================================================================
    // Parse `.ovf` XML Hardware Envelope & Audit Hardware Spoofing Definitions
    // ========================================================================
    let ovf_hardware = if let Some((ovf_name, ovf_xml)) = ovf_texts.first() {
        let hw = parse_ovf_xml_envelope(ovf_xml);
        let ovf_target = format!("{}!{}", ova_label, ovf_name);

        for mac in &hw.pinned_mac_addresses {
            ova_findings.push(
                Finding::new(
                    EngineId::OvaStreamInspector,
                    "HIGH_OVF_PINNED_STATIC_MAC_SPOOF",
                    Severity::High,
                    &ovf_target,
                    format!(
                        "OVF envelope `{}` pins hardcoded static MAC address `{}` (`rasd:Address`) to force identical hardware identity across cloned deployments",
                        ovf_name, mac
                    ),
                )
                .with_evidence("ovf_file", JsonValue::str(ovf_name.as_str()))
                .with_evidence("pinned_mac_address", JsonValue::str(mac.as_str())),
            );
        }

        for (k, v) in &hw.custom_smbios_properties {
            let kl = k.to_ascii_lowercase();
            if kl.contains("uuid") || kl.contains("smbios") || kl.contains("serial") {
                ova_findings.push(
                    Finding::new(
                        EngineId::OvaStreamInspector,
                        "HIGH_OVF_CUSTOM_SMBIOS_UUID_PINNED",
                        Severity::High,
                        &ovf_target,
                        format!(
                            "OVF envelope `{}` injects custom SMBIOS/UUID hardware override `{}={}`",
                            ovf_name, k, v
                        ),
                    )
                    .with_evidence("ovf_file", JsonValue::str(ovf_name.as_str()))
                    .with_evidence("config_key", JsonValue::str(k.as_str()))
                    .with_evidence("config_value", JsonValue::str(v.as_str())),
                );
            }
        }

        for fref in &hw.file_references {
            if let Some(declared_sz) = fref.declared_size {
                let key = basename_only(&fref.href).to_string();
                if let Some(actual_member) = member_by_basename.get(&key) {
                    if actual_member.size_bytes != declared_sz {
                        ova_findings.push(
                            Finding::new(
                                EngineId::OvaStreamInspector,
                                "HIGH_OVF_DISK_SIZE_MISMATCH",
                                Severity::High,
                                &ovf_target,
                                format!(
                                    "OVF `<File href=\"{}\">` declares size {} bytes, but archive member is {} bytes (re-packed disk without OVF update)",
                                    fref.href, declared_sz, actual_member.size_bytes
                                ),
                            )
                            .with_evidence("href", JsonValue::str(&fref.href))
                            .with_evidence("declared_size", JsonValue::Uint(declared_sz))
                            .with_evidence("actual_size", JsonValue::Uint(actual_member.size_bytes)),
                        );
                    }
                }
            }
        }

        Some(hw)
    } else {
        None
    };

    Ok(OvaInspectionOutcome {
        ova_label: ova_label.to_string(),
        total_archive_bytes_read: archive_pos,
        members,
        manifest_present,
        manifest_authentic,
        cert_present,
        manifest_records,
        ovf_hardware,
        disk_carve_reports,
        ova_findings,
        vmdk_findings,
    })
}

/// Parses `.mf` / `.cert` lines of the form `SHA256(FortiSOAR-disk1.vmdk)= <hex>` or `SHA1(...) = <hex>`.
pub fn parse_ova_manifest_lines(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("-----") {
            continue;
        }
        let Some((lhs, rhs)) = line.split_once('=') else {
            continue;
        };
        let lhs = lhs.trim();
        let rhs = rhs.trim();
        let Some((algo_raw, rest)) = lhs.split_once('(') else {
            continue;
        };
        let Some(file_name) = rest.strip_suffix(')') else {
            continue;
        };
        let algo = algo_raw.trim().to_ascii_uppercase();
        if matches!(algo.as_str(), "SHA1" | "SHA256" | "SHA512")
            && !file_name.trim().is_empty()
            && rhs.bytes().all(|b| b.is_ascii_hexdigit())
        {
            out.push((algo, file_name.trim().to_string(), rhs.to_ascii_lowercase()));
        }
    }
    out
}

/// Zero-crate `.ovf` XML hardware envelope parser supporting standard OVF 1.x/2.x namespaces.
pub fn parse_ovf_xml_envelope(xml: &str) -> OvfHardwareEnvelope {
    let mut env = OvfHardwareEnvelope::default();

    // 1. Scan start/self-closing tags for `<File>`, `<Disk>`, `<VirtualSystem>`, `<Config>`, `<Property>`
    let mut cursor = 0usize;
    let bytes = xml.as_bytes();
    while let Some(rel_lt) = xml[cursor..].find('<') {
        let tag_start = cursor + rel_lt;
        if xml[tag_start..].starts_with("<!--") {
            if let Some(end_c) = xml[tag_start + 4..].find("-->") {
                cursor = tag_start + 4 + end_c + 3;
                continue;
            } else {
                break;
            }
        }
        let Some(rel_gt) = xml[tag_start..].find('>') else {
            break;
        };
        let tag_end = tag_start + rel_gt;
        let inside = xml[tag_start + 1..tag_end].trim();
        cursor = tag_end + 1;

        if inside.is_empty() || inside.starts_with('/') || inside.starts_with('?') || inside.starts_with('!') {
            continue;
        }

        let trimmed_inside = inside.trim_end_matches('/').trim();
        let (raw_tag_name, attr_str) = match trimmed_inside.find(char::is_whitespace) {
            Some(pos) => (&trimmed_inside[..pos], trimmed_inside[pos..].trim()),
            None => (trimmed_inside, ""),
        };
        let local_name = strip_xml_ns(raw_tag_name);
        let attrs = parse_xml_attributes(attr_str);

        match local_name {
            "File" => {
                let id = get_attr_local(&attrs, "id").unwrap_or_default();
                let href = get_attr_local(&attrs, "href").unwrap_or_default();
                let declared_size = get_attr_local(&attrs, "size").and_then(|s| s.parse::<u64>().ok());
                if !href.is_empty() {
                    env.file_references.push(OvfFileRef {
                        id,
                        href,
                        declared_size,
                    });
                }
            }
            "Disk" => {
                let disk_id = get_attr_local(&attrs, "diskId").unwrap_or_default();
                let file_ref = get_attr_local(&attrs, "fileRef").unwrap_or_default();
                let capacity = get_attr_local(&attrs, "capacity").unwrap_or_default();
                let allocation_units = get_attr_local(&attrs, "capacityAllocationUnits");
                let format_uri = get_attr_local(&attrs, "format");
                if !disk_id.is_empty() || !file_ref.is_empty() {
                    env.disks.push(OvfDiskDef {
                        disk_id,
                        file_ref,
                        capacity,
                        allocation_units,
                        format_uri,
                    });
                }
            }
            "VirtualSystem" => {
                if env.virtual_system_id.is_none() {
                    env.virtual_system_id = get_attr_local(&attrs, "id");
                }
            }
            "Config" | "ExtraConfig" => {
                if let (Some(k), Some(v)) = (get_attr_local(&attrs, "key"), get_attr_local(&attrs, "value")) {
                    let kl = k.to_ascii_lowercase();
                    if kl.contains("uuid")
                        || kl.contains("smbios")
                        || kl.contains("bios")
                        || kl.contains("serial")
                        || kl.contains("mac")
                        || kl.contains("board")
                    {
                        env.custom_smbios_properties.push((k, v));
                    }
                }
            }
            "Property" => {
                if let Some(k) = get_attr_local(&attrs, "key") {
                    let v = get_attr_local(&attrs, "value").unwrap_or_default();
                    let kl = k.to_ascii_lowercase();
                    if kl.contains("uuid") || kl.contains("smbios") || kl.contains("serial") {
                        env.custom_smbios_properties.push((k.clone(), v.clone()));
                    }
                    env.ovf_properties.push((k, v));
                }
            }
            _ => {}
        }
        let _ = bytes;
    }

    // 2. Extract top-level scalar elements
    env.virtual_system_name = extract_first_xml_element_text(xml, "Name");
    env.os_description = extract_first_xml_element_text(xml, "Description");
    env.virtual_system_type = extract_first_xml_element_text(xml, "VirtualSystemType");
    if let Some(vs_ident) = extract_first_xml_element_text(xml, "VirtualSystemIdentifier") {
        if looks_like_custom_uuid_or_serial(&vs_ident) {
            env.custom_smbios_properties
                .push(("VirtualSystemIdentifier".to_string(), vs_ident));
        }
    }

    // 3. Extract `<Item>` blocks inside `<VirtualHardwareSection>`
    for item_block in extract_all_xml_blocks(xml, "Item") {
        let Some(res_type_str) = extract_first_xml_element_text(item_block, "ResourceType") else {
            continue;
        };
        let res_type = res_type_str.trim().parse::<u32>().unwrap_or(0);
        match res_type {
            3 => {
                // vCPU
                env.vcpu_count = extract_first_xml_element_text(item_block, "VirtualQuantity")
                    .and_then(|s| s.trim().parse::<u64>().ok());
                env.vcpu_limit = extract_first_xml_element_text(item_block, "Limit")
                    .and_then(|s| s.trim().parse::<u64>().ok());
                env.vcpu_reservation = extract_first_xml_element_text(item_block, "Reservation")
                    .and_then(|s| s.trim().parse::<u64>().ok());
            }
            4 => {
                // RAM
                let raw_qty = extract_first_xml_element_text(item_block, "VirtualQuantity")
                    .and_then(|s| s.trim().parse::<u64>().ok());
                let units = extract_first_xml_element_text(item_block, "AllocationUnits")
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                env.ram_mb = raw_qty.map(|q| normalize_memory_to_mb(q, &units));
                env.ram_limit_mb = extract_first_xml_element_text(item_block, "Limit")
                    .and_then(|s| s.trim().parse::<u64>().ok());
            }
            10 => {
                // Network Adapter
                let element_name = extract_first_xml_element_text(item_block, "ElementName")
                    .unwrap_or_else(|| "Network adapter".to_string());
                let adapter_subtype = extract_first_xml_element_text(item_block, "ResourceSubType");
                let connection = extract_first_xml_element_text(item_block, "Connection");
                let automatic_allocation =
                    extract_first_xml_element_text(item_block, "AutomaticAllocation")
                        .map(|s| s.trim().eq_ignore_ascii_case("true"));
                let static_mac_address = extract_first_xml_element_text(item_block, "Address")
                    .map(|s| s.trim().to_string())
                    .filter(|s| is_non_zero_mac_address(s));

                if let Some(mac) = &static_mac_address {
                    if !env.pinned_mac_addresses.contains(mac) {
                        env.pinned_mac_addresses.push(mac.clone());
                    }
                }

                env.network_adapters.push(OvfNetworkAdapter {
                    element_name,
                    adapter_subtype,
                    connection,
                    automatic_allocation,
                    static_mac_address,
                });
            }
            _ => {}
        }
    }

    env
}

fn normalize_memory_to_mb(qty: u64, units_lower: &str) -> u64 {
    if units_lower.contains("2^30") || units_lower.contains("gigabyte") || units_lower == "gb" {
        qty.saturating_mul(1024)
    } else if units_lower.contains("2^10") || units_lower.contains("kilobyte") || units_lower == "kb"
    {
        qty / 1024
    } else {
        qty
    }
}

fn is_non_zero_mac_address(s: &str) -> bool {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        return false;
    }
    let mut any_non_zero = false;
    for part in parts {
        if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        if part != "00" {
            any_non_zero = true;
        }
    }
    any_non_zero
}

fn looks_like_custom_uuid_or_serial(s: &str) -> bool {
    let trimmed = s.trim();
    // Standard 36-char RFC 4122 UUID `8-4-4-4-12` or `FGVM*`
    let parts: Vec<&str> = trimmed.split('-').collect();
    if parts.len() == 5
        && parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && parts
            .iter()
            .all(|p| p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return true;
    }
    trimmed.to_ascii_uppercase().starts_with("FGVM")
}

fn strip_xml_ns(name: &str) -> &str {
    match name.rsplit_once(':') {
        Some((_, local)) => local,
        None => name,
    }
}

fn parse_xml_attributes(mut s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    while !s.is_empty() {
        s = s.trim_start();
        let Some(eq_idx) = s.find('=') else {
            break;
        };
        let key = s[..eq_idx].trim();
        let rest = s[eq_idx + 1..].trim_start();
        let Some(quote) = rest.chars().next() else {
            break;
        };
        if quote != '"' && quote != '\'' {
            break;
        }
        let after_q = &rest[quote.len_utf8()..];
        let Some(end_q) = after_q.find(quote) else {
            break;
        };
        let val = decode_xml_entities(&after_q[..end_q]);
        out.push((key.to_string(), val));
        s = &after_q[end_q + quote.len_utf8()..];
    }
    out
}

fn get_attr_local(attrs: &[(String, String)], target_local: &str) -> Option<String> {
    for (k, v) in attrs {
        if strip_xml_ns(k).eq_ignore_ascii_case(target_local) {
            return Some(v.clone());
        }
    }
    None
}

fn extract_first_xml_element_text(xml: &str, local_tag: &str) -> Option<String> {
    extract_all_xml_blocks(xml, local_tag)
        .into_iter()
        .next()
        .map(|s| decode_xml_entities(s.trim()))
}

fn extract_all_xml_blocks<'a>(xml: &'a str, local_tag: &str) -> Vec<&'a str> {
    let mut blocks = Vec::new();
    let mut pos = 0usize;
    while let Some(rel_lt) = xml[pos..].find('<') {
        let open_start = pos + rel_lt;
        let Some(rel_gt) = xml[open_start..].find('>') else {
            break;
        };
        let open_end = open_start + rel_gt;
        let tag_header = xml[open_start + 1..open_end].trim();
        pos = open_end + 1;

        if tag_header.starts_with('/')
            || tag_header.starts_with('!')
            || tag_header.starts_with('?')
            || tag_header.ends_with('/')
        {
            continue;
        }
        let tag_name = tag_header
            .split_whitespace()
            .next()
            .unwrap_or("");
        if strip_xml_ns(tag_name) == local_tag {
            let close_exact = format!("</{}>", tag_name);
            if let Some(rel_close) = xml[pos..].find(&close_exact) {
                let content_end = pos + rel_close;
                blocks.push(&xml[pos..content_end]);
                pos = content_end + close_exact.len();
            }
        }
    }
    blocks
}

fn decode_xml_entities(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn parse_pax_records(bytes: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(text) = std::str::from_utf8(bytes) else {
        return out;
    };
    for line in text.lines() {
        if let Some((_, kv)) = line.split_once(' ') {
            if let Some((k, v)) = kv.split_once('=') {
                out.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
    }
    out
}

fn normalize_tar_member_name(name: &str) -> String {
    name.trim_start_matches("./").trim_start_matches('/').to_string()
}

fn basename_only(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0usize;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

fn read_member_exact_bounded<R: Read>(
    reader: &mut R,
    size: u64,
    cap: usize,
    archive_pos: &mut u64,
) -> io::Result<Vec<u8>> {
    let keep = (size as usize).min(cap);
    let mut out = vec![0u8; keep];
    let got = read_up_to(reader, &mut out)?;
    *archive_pos += got as u64;
    out.truncate(got);

    let mut rem = size.saturating_sub(got as u64);
    let mut sink = [0u8; 4096];
    while rem > 0 {
        let want = (rem as usize).min(sink.len());
        let n = reader.read(&mut sink[..want])?;
        if n == 0 {
            break;
        }
        *archive_pos += n as u64;
        rem -= n as u64;
    }
    Ok(out)
}

fn skip_tar_padding<R: Read>(reader: &mut R, size: u64, archive_pos: &mut u64) -> io::Result<()> {
    let rem = (size % 512) as usize;
    if rem == 0 {
        return Ok(());
    }
    let pad = 512 - rem;
    let mut discard = [0u8; 512];
    let got = read_up_to(reader, &mut discard[..pad])?;
    *archive_pos += got as u64;
    Ok(())
}
