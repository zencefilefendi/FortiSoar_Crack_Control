//! Engine 1: Deep System, Filesystem Superblock & Database Birthmark Extractor.
//!
//! Extracts immutable / near-immutable Golden Image cryptographic birthmarks from a
//! FortiSOAR or FortiGate VM root filesystem (`--root <path>`):
//!   1. PostgreSQL 8192-byte `pg_control` binary (`system_identifier`, `pg_control_version`,
//!      checkpoint timestamp, and Castagnoli CRC-32C integrity verification).
//!   2. Byte-level EXT4 (`0xEF53` at `1024 + 0x38`, 128-bit `s_uuid` at `1024 + 0x68`,
//!      `s_mkfs_time` at `1024 + 0x108`) and XFS (`0x58465342` "XFSB" at `0x00`, 128-bit
//!      `sb_uuid` at `0x20`, XFS v5 `sb_meta_uuid` at `0x140`) superblock parsers, plus
//!      `/etc/fstab` & `/proc/mounts` discovery.
//!   3. `/etc/machine-id`, `/var/lib/dbus/machine-id`, OpenSSH `/etc/ssh/ssh_host_*_key.pub`
//!      RFC 4253 key-blob SHA-256 digests, and FortiSOAR `/opt/cyops*` `SECRET_KEY` /
//!      Fernet / AES vault keys / salts hashed strictly via deterministic RFC 2104
//!      HMAC-SHA256 without ever exposing plaintext secret material.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use fsr_deep_audit::crypto::{crc32c, format_uuid_bytes, hmac_sha256_hex, sha256_hex};
use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};
use fsr_net_crypto_audit::asn1_x509::base64_decode;

/// Fixed domain-separation key for deterministic cross-appliance HMAC-SHA256 birthmarks.
/// Ensures identical Golden Image vault keys correlate across reports while never exposing
/// raw secret material or unsalted hashes.
pub const BIRTHMARK_HMAC_DOMAIN_KEY: &[u8] = b"fsr-clone-cluster-audit:v1:crypto-seed-birthmark";

pub const PG_CONTROL_FILE_SIZE: usize = 8192;
pub const EXT4_SUPER_OFFSET: usize = 1024;
pub const EXT4_SUPER_MAGIC: u16 = 0xEF53;
pub const XFS_SUPER_MAGIC: u32 = 0x5846_5342; // "XFSB"

/// Parsed PostgreSQL `global/pg_control` binary metadata.
#[derive(Debug, Clone)]
pub struct PgControlBirthmark {
    pub path: String,
    pub file_size: usize,
    pub system_identifier: u64,
    pub system_identifier_hex: String,
    pub pg_control_version: u32,
    pub catalog_version_no: u32,
    pub db_state: u32,
    pub control_timestamp_unix: i64,
    pub checkpoint_lsn: u64,
    pub crc32c_valid: bool,
    pub crc32c_offset: usize,
    pub stored_crc32c: u32,
    pub computed_crc32c: u32,
}

/// Parsed EXT4 or XFS superblock identity (or fstab UUID reference).
#[derive(Debug, Clone)]
pub struct SuperblockBirthmark {
    pub source_path: String,
    pub fs_type: String,
    pub uuid: String,
    pub meta_uuid: Option<String>,
    pub volume_label: String,
    pub last_mounted: String,
    pub mkfs_time_unix: Option<u64>,
    pub last_mount_time_unix: Option<u64>,
    pub last_write_time_unix: Option<u64>,
    pub parsed_from_raw_superblock: bool,
}

/// Parsed OpenSSH host public key fingerprint.
#[derive(Debug, Clone)]
pub struct SshHostKeyBirthmark {
    pub path: String,
    pub algorithm: String,
    pub key_blob_sha256: String,
}

/// Zero-plaintext FortiSOAR cryptographic seed / vault key / salt birthmark.
#[derive(Debug, Clone)]
pub struct CryptoSeedBirthmark {
    pub file_path: String,
    pub parameter_name: String,
    pub seed_kind: String,
    pub hmac_sha256_fingerprint: String,
    pub secret_byte_len: usize,
    pub shannon_entropy_x100: u32,
}

/// Complete single-node birthmark bundle consumed by `time_freeze_audit` and `cluster_correlator`.
#[derive(Debug, Clone, Default)]
pub struct DeviceBirthmarks {
    pub hostname: String,
    pub machine_id: Option<String>,
    pub dbus_machine_id: Option<String>,
    pub pg_controls: Vec<PgControlBirthmark>,
    pub superblocks: Vec<SuperblockBirthmark>,
    pub ssh_host_keys: Vec<SshHostKeyBirthmark>,
    pub crypto_seeds: Vec<CryptoSeedBirthmark>,
}

/// Output of Engine 1 (`birthmark_extractor`).
pub struct BirthmarkExtractResult {
    pub birthmarks: DeviceBirthmarks,
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Executes Engine 1 against `root`.
pub fn run_birthmark_extractor(root: &Path) -> BirthmarkExtractResult {
    let mut findings = Vec::new();

    let hostname = read_trimmed(&join_rooted(root, "etc/hostname"))
        .or_else(|| read_trimmed(&join_rooted(root, "proc/sys/kernel/hostname")))
        .unwrap_or_else(|| "unknown-host".to_string());

    // 1. Machine IDs (`/etc/machine-id` & `/var/lib/dbus/machine-id`)
    let machine_id = read_trimmed(&join_rooted(root, "etc/machine-id"))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());
    let dbus_machine_id = read_trimmed(&join_rooted(root, "var/lib/dbus/machine-id"))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());

    if let (Some(m1), Some(m2)) = (&machine_id, &dbus_machine_id) {
        if m1 != m2 {
            findings.push(
                Finding::new(
                    EngineId::BirthmarkExtractor,
                    "MEDIUM_PARTIAL_MACHINE_ID_SCRUB",
                    Severity::Medium,
                    "/etc/machine-id",
                    "Discrepancy between /etc/machine-id and /var/lib/dbus/machine-id indicates incomplete Golden Image sysprep/scrubbing",
                )
                .with_evidence("etc_machine_id", JsonValue::str(m1.as_str()))
                .with_evidence("dbus_machine_id", JsonValue::str(m2.as_str())),
            );
        }
    }

    // 2. PostgreSQL `pg_control` binary scan
    let pg_controls = scan_pg_control_files(root, &mut findings);

    // 3. Filesystem Superblocks (EXT4 / XFS raw headers + `/etc/fstab` & `/proc/mounts`)
    let superblocks = scan_filesystem_superblocks(root);

    // 4. OpenSSH Host Keys (`/etc/ssh/ssh_host_*_key.pub`)
    let ssh_host_keys = scan_ssh_host_keys(root);

    // 5. FortiSOAR `/opt/cyops*` Cryptographic Seeds (`SECRET_KEY`, Fernet/AES vault keys, salts)
    let crypto_seeds = scan_cyops_cryptographic_seeds(root, &mut findings);

    let birthmarks = DeviceBirthmarks {
        hostname,
        machine_id,
        dbus_machine_id,
        pg_controls,
        superblocks,
        ssh_host_keys,
        crypto_seeds,
    };

    let summary = serialize_birthmarks_to_json(&birthmarks);
    BirthmarkExtractResult {
        birthmarks,
        summary,
        findings,
    }
}

/// Parses an 8192-byte PostgreSQL `global/pg_control` binary buffer (`x86_64` little-endian)
/// and verifies its Castagnoli `CRC-32C` (`pg_crc32c`) checksum.
pub fn parse_pg_control_bytes(path_label: &str, bytes: &[u8]) -> Result<PgControlBirthmark, String> {
    if bytes.len() < 64 {
        return Err(format!(
            "pg_control buffer too short ({} bytes, expected {} bytes)",
            bytes.len(),
            PG_CONTROL_FILE_SIZE
        ));
    }

    let system_identifier = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let pg_control_version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let catalog_version_no = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let db_state = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    // Offset 20..24: 4-byte alignment padding on 64-bit LP64 (`x86_64`) before `pg_time_t time`
    let control_timestamp_unix = i64::from_le_bytes([
        bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
    ]);
    let checkpoint_lsn = u64::from_le_bytes([
        bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
    ]);

    let (crc32c_valid, crc32c_offset, stored_crc32c, computed_crc32c) =
        verify_pg_control_crc32c(bytes, pg_control_version);

    Ok(PgControlBirthmark {
        path: path_label.to_string(),
        file_size: bytes.len(),
        system_identifier,
        system_identifier_hex: format!("0x{:016x}", system_identifier),
        pg_control_version,
        catalog_version_no,
        db_state,
        control_timestamp_unix,
        checkpoint_lsn,
        crc32c_valid,
        crc32c_offset,
        stored_crc32c,
        computed_crc32c,
    })
}

fn verify_pg_control_crc32c(bytes: &[u8], pg_control_version: u32) -> (bool, usize, u32, u32) {
    // Primary `offsetof(ControlFileData, crc)` on 64-bit Linux x86_64 across PostgreSQL 9.5 - 17
    let preferred_offset: usize = match pg_control_version {
        1700..=1999 => 296,
        1200..=1699 => 288, // PostgreSQL 12, 13, 14, 15, 16 (`1201`, `1300`)
        1000..=1199 => 280, // PostgreSQL 10 (`1002`) & 11 (`1100`)
        940..=999 => 272,   // PostgreSQL 9.5 / 9.6
        _ => 288,
    };

    // 1. Check canonical version-specific struct CRC32C offset
    if preferred_offset + 4 <= bytes.len() && bytes[preferred_offset + 4..].iter().all(|&b| b == 0)
    {
        let stored = u32::from_le_bytes([
            bytes[preferred_offset],
            bytes[preferred_offset + 1],
            bytes[preferred_offset + 2],
            bytes[preferred_offset + 3],
        ]);
        let computed = crc32c(&bytes[..preferred_offset]);
        if stored == computed && stored != 0 {
            return (true, preferred_offset, stored, computed);
        }
    }

    // 2. Check full-file trailer CRC32C (`bytes.len() - 4`, e.g. `8188..8192`)
    if bytes.len() >= 68 {
        let trailer_off = bytes.len() - 4;
        let stored = u32::from_le_bytes([
            bytes[trailer_off],
            bytes[trailer_off + 1],
            bytes[trailer_off + 2],
            bytes[trailer_off + 3],
        ]);
        let computed = crc32c(&bytes[..trailer_off]);
        if stored == computed && stored != 0 {
            return (true, trailer_off, stored, computed);
        }
    }

    // 3. Scan 4-byte aligned `ControlFileData` boundaries in `64..=512` where trailing padding is zero
    let max_scan = bytes.len().saturating_sub(4).min(512);
    let mut pos = 64usize;
    while pos <= max_scan {
        if bytes[pos + 4..].iter().all(|&b| b == 0) {
            let stored =
                u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
            if stored != 0 {
                let computed = crc32c(&bytes[..pos]);
                if stored == computed {
                    return (true, pos, stored, computed);
                }
            }
        }
        pos += 4;
    }

    // Fallback diagnostic values at `preferred_offset` when corrupted
    let diag_off = if preferred_offset + 4 <= bytes.len() {
        preferred_offset
    } else {
        bytes.len() - 4
    };
    let stored = u32::from_le_bytes([
        bytes[diag_off],
        bytes[diag_off + 1],
        bytes[diag_off + 2],
        bytes[diag_off + 3],
    ]);
    let computed = crc32c(&bytes[..diag_off]);
    (false, diag_off, stored, computed)
}

/// Parses an EXT4 primary superblock at byte offset `1024` (`s_magic = 0xEF53` at `1024 + 0x38`).
pub fn parse_ext4_superblock(source_label: &str, bytes: &[u8]) -> Option<SuperblockBirthmark> {
    if bytes.len() < EXT4_SUPER_OFFSET + 0x10C {
        return None;
    }
    let sb = &bytes[EXT4_SUPER_OFFSET..];
    let magic = u16::from_le_bytes([sb[0x38], sb[0x39]]);
    if magic != EXT4_SUPER_MAGIC {
        return None;
    }

    let mut raw_uuid = [0u8; 16];
    raw_uuid.copy_from_slice(&sb[0x68..0x78]);
    let uuid = format_uuid_bytes(&raw_uuid);

    let mtime_lo = u32::from_le_bytes([sb[0x2C], sb[0x2D], sb[0x2E], sb[0x2F]]) as u64;
    let wtime_lo = u32::from_le_bytes([sb[0x30], sb[0x31], sb[0x32], sb[0x33]]) as u64;
    let mkfs_lo = u32::from_le_bytes([sb[0x108], sb[0x109], sb[0x10A], sb[0x10B]]) as u64;

    let mkfs_hi = if sb.len() > 0x274 {
        (sb[0x274] as u64) << 32
    } else {
        0
    };
    let mkfs_time = mkfs_hi | mkfs_lo;

    let volume_label = parse_cstr_fixed(&sb[0x78..0x88]);
    let last_mounted = parse_cstr_fixed(&sb[0x88..0xC8]);

    Some(SuperblockBirthmark {
        source_path: source_label.to_string(),
        fs_type: "ext4".to_string(),
        uuid,
        meta_uuid: None,
        volume_label,
        last_mounted,
        mkfs_time_unix: if mkfs_time > 0 { Some(mkfs_time) } else { None },
        last_mount_time_unix: if mtime_lo > 0 { Some(mtime_lo) } else { None },
        last_write_time_unix: if wtime_lo > 0 { Some(wtime_lo) } else { None },
        parsed_from_raw_superblock: true,
    })
}

/// Parses an XFS primary superblock at byte offset `0` (`sb_magicnum = 0x58465342` "XFSB" big-endian).
pub fn parse_xfs_superblock(source_label: &str, bytes: &[u8]) -> Option<SuperblockBirthmark> {
    if bytes.len() < 0x80 {
        return None;
    }
    let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != XFS_SUPER_MAGIC {
        return None;
    }

    let blocksize = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if !(512..=65536).contains(&blocksize) || !blocksize.is_power_of_two() {
        return None;
    }

    let mut raw_uuid = [0u8; 16];
    raw_uuid.copy_from_slice(&bytes[0x20..0x30]);
    let uuid = format_uuid_bytes(&raw_uuid);

    let sb_versionnum = u16::from_be_bytes([bytes[0x64], bytes[0x65]]);
    let xfs_ver = sb_versionnum & 0x000F;
    let volume_label = parse_cstr_fixed(&bytes[0x6C..0x78]);

    // XFS v5 (`CRC` enabled, default on RHEL/Rocky 8/9) stores immutable `sb_meta_uuid` at `0x140..0x150`
    let meta_uuid = if xfs_ver >= 5 && bytes.len() >= 0x150 {
        let mut meta = [0u8; 16];
        meta.copy_from_slice(&bytes[0x140..0x150]);
        if meta.iter().any(|&b| b != 0) {
            Some(format_uuid_bytes(&meta))
        } else {
            None
        }
    } else {
        None
    };

    Some(SuperblockBirthmark {
        source_path: source_label.to_string(),
        fs_type: if xfs_ver >= 5 {
            "xfs_v5".to_string()
        } else {
            "xfs".to_string()
        },
        uuid,
        meta_uuid,
        volume_label,
        last_mounted: String::new(),
        mkfs_time_unix: None,
        last_mount_time_unix: None,
        last_write_time_unix: None,
        parsed_from_raw_superblock: true,
    })
}

/// Auto-detects and parses either an EXT4 or XFS superblock from the leading bytes of a partition/image.
pub fn parse_filesystem_superblock(
    source_label: &str,
    bytes: &[u8],
) -> Option<SuperblockBirthmark> {
    parse_xfs_superblock(source_label, bytes).or_else(|| parse_ext4_superblock(source_label, bytes))
}

fn scan_pg_control_files(root: &Path, findings: &mut Vec<Finding>) -> Vec<PgControlBirthmark> {
    let mut candidate_roots = Vec::new();
    for rel in ["var/lib/pgsql", "var/lib/postgresql", "opt"] {
        let p = join_rooted(root, rel);
        if p.is_dir() {
            candidate_roots.push(p);
        }
    }

    let mut found_files = Vec::new();
    for base in &candidate_roots {
        collect_named_files_bounded(base, "pg_control", 7, &mut found_files);
    }
    found_files.sort();
    found_files.dedup();

    let mut results = Vec::new();
    for path in found_files {
        // Verify parent directory is `global` (`.../global/pg_control`)
        let is_global = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            == Some("global");
        if !is_global {
            continue;
        }

        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let label = display_under_root(root, &path);
        match parse_pg_control_bytes(&label, &bytes) {
            Ok(pg) => {
                if !pg.crc32c_valid || pg.file_size != PG_CONTROL_FILE_SIZE {
                    findings.push(
                        Finding::new(
                            EngineId::BirthmarkExtractor,
                            "HIGH_PG_CONTROL_CRC32C_MISMATCH",
                            Severity::High,
                            &label,
                            format!(
                                "PostgreSQL pg_control file {} failed structural/CRC-32C validation (size={}, stored=0x{:08x}, computed=0x{:08x}) — manual hex-edit tampering suspected",
                                label, pg.file_size, pg.stored_crc32c, pg.computed_crc32c
                            ),
                        )
                        .with_evidence("system_identifier", JsonValue::str(pg.system_identifier.to_string()))
                        .with_evidence("file_size", JsonValue::Uint(pg.file_size as u64))
                        .with_evidence("crc32c_offset", JsonValue::Uint(pg.crc32c_offset as u64))
                        .with_evidence("stored_crc32c", JsonValue::str(format!("0x{:08x}", pg.stored_crc32c)))
                        .with_evidence("computed_crc32c", JsonValue::str(format!("0x{:08x}", pg.computed_crc32c))),
                    );
                }
                results.push(pg);
            }
            Err(err) => {
                findings.push(
                    Finding::new(
                        EngineId::BirthmarkExtractor,
                        "MEDIUM_MALFORMED_PG_CONTROL",
                        Severity::Medium,
                        &label,
                        format!("Malformed PostgreSQL pg_control file {}: {}", label, err),
                    )
                    .with_evidence("error", JsonValue::str(err)),
                );
            }
        }
    }

    results
}

fn scan_filesystem_superblocks(root: &Path) -> Vec<SuperblockBirthmark> {
    let mut superblocks = Vec::new();
    let mut candidate_devs: BTreeSet<PathBuf> = BTreeSet::new();
    let mut seen_uuids: BTreeSet<String> = BTreeSet::new();

    // 1. Parse `/etc/fstab` for `UUID=...` declarations and `/dev/...` block paths
    let fstab_path = join_rooted(root, "etc/fstab");
    let mut fstab_uuid_entries: Vec<(String, String, String)> = Vec::new();
    if let Ok(fstab_text) = fs::read_to_string(&fstab_path) {
        for raw_line in fstab_text.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 3 {
                continue;
            }
            let spec = cols[0];
            let mnt = cols[1];
            let fstype = cols[2];
            if let Some(uuid_val) = spec.strip_prefix("UUID=") {
                let clean = uuid_val.trim_matches('"').trim_matches('\'').to_ascii_lowercase();
                if is_canonical_uuid(&clean) {
                    fstab_uuid_entries.push((clean, mnt.to_string(), fstype.to_string()));
                }
            } else if let Some(rel_dev) = spec.strip_prefix('/') {
                candidate_devs.insert(join_rooted(root, rel_dev));
            }
        }
    }

    // 2. Parse `/proc/mounts` for active `/dev/...` block devices
    let mounts_path = join_rooted(root, "proc/mounts");
    if let Ok(mounts_text) = fs::read_to_string(&mounts_path) {
        for line in mounts_text.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 3 && cols[0].starts_with("/dev/") {
                if let Some(rel_dev) = cols[0].strip_prefix('/') {
                    candidate_devs.insert(join_rooted(root, rel_dev));
                }
            }
        }
    }

    // 3. Scan `<root>/dev` (non-recursive + `mapper/`) and `<root>/var/lib/fs_images` for block/raw headers
    for rel_dir in ["dev", "dev/mapper", "var/lib/fs_images"] {
        let dir = join_rooted(root, rel_dir);
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("sd")
                    || name.starts_with("vd")
                    || name.starts_with("nvme")
                    || name.starts_with("xvda")
                    || name.starts_with("loop")
                    || name.starts_with("dm-")
                    || rel_dir == "dev/mapper"
                    || rel_dir == "var/lib/fs_images"
                    || name.ends_with(".img")
                    || name.ends_with(".raw")
                {
                    candidate_devs.insert(p);
                }
            }
        }
    }

    // Read leading 4096 bytes of each candidate device/header and run byte-level EXT4/XFS parser
    for dev_path in candidate_devs {
        let Ok(mut f) = File::open(&dev_path) else {
            continue;
        };
        let mut header = [0u8; 4096];
        let mut read_total = 0usize;
        while read_total < header.len() {
            match f.read(&mut header[read_total..]) {
                Ok(0) => break,
                Ok(n) => read_total += n,
                Err(_) => break,
            }
        }
        if read_total < 128 {
            continue;
        }
        let label = display_under_root(root, &dev_path);
        if let Some(sb) = parse_filesystem_superblock(&label, &header[..read_total]) {
            seen_uuids.insert(sb.uuid.clone());
            superblocks.push(sb);
        }
    }

    // Include `/etc/fstab` UUID declarations not already covered by direct block device reads
    // (critical when running unprivileged or against a mounted directory tree without `/dev` block nodes)
    for (uuid, mnt, fstype) in fstab_uuid_entries {
        if fstype == "swap" || seen_uuids.contains(&uuid) {
            continue;
        }
        seen_uuids.insert(uuid.clone());
        superblocks.push(SuperblockBirthmark {
            source_path: format!("/etc/fstab ({})", mnt),
            fs_type: fstype,
            uuid,
            meta_uuid: None,
            volume_label: String::new(),
            last_mounted: mnt,
            mkfs_time_unix: None,
            last_mount_time_unix: None,
            last_write_time_unix: None,
            parsed_from_raw_superblock: false,
        });
    }

    superblocks.sort_by(|a, b| a.uuid.cmp(&b.uuid).then_with(|| a.source_path.cmp(&b.source_path)));
    superblocks
}

fn scan_ssh_host_keys(root: &Path) -> Vec<SshHostKeyBirthmark> {
    let ssh_dir = join_rooted(root, "etc/ssh");
    let Ok(entries) = fs::read_dir(&ssh_dir) else {
        return Vec::new();
    };

    let mut keys = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("ssh_host_") || !name.ends_with("_key.pub") {
            continue;
        }
        let path = entry.path();
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let algo = parts[0].to_string();
                let digest = if let Ok(raw_blob) = base64_decode(parts[1]) {
                    sha256_hex(&raw_blob)
                } else {
                    sha256_hex(parts[1].as_bytes())
                };
                keys.push(SshHostKeyBirthmark {
                    path: display_under_root(root, &path),
                    algorithm: algo,
                    key_blob_sha256: digest,
                });
                break;
            }
        }
    }

    keys.sort_by(|a, b| a.path.cmp(&b.path));
    keys
}

fn scan_cyops_cryptographic_seeds(
    root: &Path,
    findings: &mut Vec<Finding>,
) -> Vec<CryptoSeedBirthmark> {
    let opt_dir = join_rooted(root, "opt");
    let Ok(entries) = fs::read_dir(&opt_dir) else {
        return Vec::new();
    };

    let mut cyops_roots = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "cyops" || name.starts_with("cyops-") || name.starts_with("cyops_") {
            let p = entry.path();
            if p.is_dir() {
                cyops_roots.push(p);
            }
        }
    }
    cyops_roots.sort();

    let mut candidate_files = Vec::new();
    for cr in &cyops_roots {
        collect_seed_config_files_bounded(cr, 7, &mut candidate_files);
    }
    candidate_files.sort();
    candidate_files.dedup();

    let mut seeds = Vec::new();
    for file_path in candidate_files {
        // Limit to <= 2 MiB config/source files
        let Ok(meta) = fs::metadata(&file_path) else {
            continue;
        };
        if meta.len() > 2 * 1024 * 1024 {
            continue;
        }
        let Ok(text) = fs::read_to_string(&file_path) else {
            continue;
        };
        let rel_label = display_under_root(root, &file_path);

        for raw_line in text.lines() {
            let Some((param_name, seed_kind, secret_value)) = extract_seed_assignment(raw_line)
            else {
                continue;
            };

            let hmac_fp = hmac_sha256_hex(BIRTHMARK_HMAC_DOMAIN_KEY, secret_value.as_bytes());
            let entropy_x100 = compute_shannon_entropy_x100(secret_value.as_bytes());

            // Flag dangerously short / weak hardcoded FortiSOAR vault keys on single node too
            if secret_value.len() < 16 || entropy_x100 < 220 {
                findings.push(
                    Finding::new(
                        EngineId::BirthmarkExtractor,
                        "HIGH_WEAK_HARDCODED_CRYPTO_SEED",
                        Severity::High,
                        format!("{}::{}", rel_label, param_name),
                        format!(
                            "Weak or low-entropy cryptographic seed `{}` (len={}, entropy={}.{:02} bits/byte) in {}",
                            param_name,
                            secret_value.len(),
                            entropy_x100 / 100,
                            entropy_x100 % 100,
                            rel_label
                        ),
                    )
                    .with_evidence("parameter_name", JsonValue::str(&param_name))
                    .with_evidence("hmac_sha256_fingerprint", JsonValue::str(&hmac_fp))
                    .with_evidence("secret_byte_len", JsonValue::Uint(secret_value.len() as u64)),
                );
            }

            seeds.push(CryptoSeedBirthmark {
                file_path: rel_label.clone(),
                parameter_name: param_name,
                seed_kind,
                hmac_sha256_fingerprint: hmac_fp,
                secret_byte_len: secret_value.len(),
                shannon_entropy_x100: entropy_x100,
            });
        }
    }

    seeds.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then_with(|| a.parameter_name.cmp(&b.parameter_name))
            .then_with(|| a.hmac_sha256_fingerprint.cmp(&b.hmac_sha256_fingerprint))
    });
    seeds.dedup_by(|a, b| {
        a.file_path == b.file_path
            && a.parameter_name == b.parameter_name
            && a.hmac_sha256_fingerprint == b.hmac_sha256_fingerprint
    });
    seeds
}

/// Extracts `(parameter_name, seed_kind, secret_literal)` without retaining plaintext anywhere in caller output.
fn extract_seed_assignment(raw_line: &str) -> Option<(String, String, String)> {
    let trimmed = raw_line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") || trimmed.starts_with(';') {
        return None;
    }
    let line = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();

    // Support `KEY = "value"`, `KEY="value"`, `"KEY": "value"`
    let (lhs_raw, rhs_raw) = line.split_once('=').or_else(|| line.split_once(':'))?;
    let key_clean = lhs_raw
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim();

    if key_clean.is_empty()
        || !key_clean
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
    {
        return None;
    }

    let upper = key_clean.to_ascii_uppercase();
    let seed_kind = if upper == "SECRET_KEY" || upper.ends_with("_SECRET_KEY") || upper == "DJANGO_SECRET_KEY" {
        "django_or_app_secret_key"
    } else if upper.contains("FERNET")
        || upper.contains("VAULT_KEY")
        || upper.contains("VAULT_MASTER")
        || upper.contains("MASTER_KEY")
        || upper.contains("AES_KEY")
        || upper.contains("ENCRYPTION_KEY")
        || upper.contains("DEK_KEY")
    {
        "vault_encryption_master_key"
    } else if upper.ends_with("_SALT")
        || upper == "SALT"
        || upper == "PASSWORD_SALT"
        || upper == "SECURITY_PASSWORD_SALT"
    {
        "cryptographic_salt"
    } else {
        return None;
    };

    // Strip inline `#` comment only if outside quotes
    let val_part = strip_unquoted_comment(rhs_raw).trim().trim_end_matches(',').trim();
    if val_part.is_empty() {
        return None;
    }

    // Ignore dynamic code expressions like `os.environ.get(...)`, `env(...)`, `None`, `${...}`
    let lower_val = val_part.to_ascii_lowercase();
    if lower_val == "none"
        || lower_val == "null"
        || lower_val == "true"
        || lower_val == "false"
        || lower_val.starts_with("os.")
        || lower_val.starts_with("env(")
        || lower_val.starts_with("getenv(")
        || lower_val.starts_with("${")
    {
        return None;
    }

    // Handle Python byte literals `b'...'` or `b"..."` as well as standard quoted/unquoted values
    let unquoted = if (val_part.starts_with("b'") && val_part.ends_with('\'') && val_part.len() >= 3)
        || (val_part.starts_with("b\"") && val_part.ends_with('"') && val_part.len() >= 3)
    {
        &val_part[2..val_part.len() - 1]
    } else if (val_part.starts_with('"') && val_part.ends_with('"') && val_part.len() >= 2)
        || (val_part.starts_with('\'') && val_part.ends_with('\'') && val_part.len() >= 2)
    {
        &val_part[1..val_part.len() - 1]
    } else {
        // For `.py` files, unquoted RHS identifiers (`SECRET_KEY = MY_VAR`) are variable references, not literals
        if val_part.contains('(') || val_part.contains(' ') {
            return None;
        }
        val_part
    };

    let clean_secret = unquoted.trim();
    if clean_secret.len() < 6 {
        return None;
    }

    Some((
        key_clean.to_string(),
        seed_kind.to_string(),
        clean_secret.to_string(),
    ))
}

fn strip_unquoted_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_backslash = false;

    for (idx, &b) in bytes.iter().enumerate() {
        if prev_backslash {
            prev_backslash = false;
            continue;
        }
        if b == b'\\' {
            prev_backslash = true;
            continue;
        }
        if b == b'\'' && !in_double {
            in_single = !in_single;
        } else if b == b'"' && !in_single {
            in_double = !in_double;
        } else if b == b'#' && !in_single && !in_double {
            return &s[..idx];
        }
    }
    s
}

fn compute_shannon_entropy_x100(bytes: &[u8]) -> u32 {
    if bytes.is_empty() {
        return 0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut ent = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            ent -= p * p.log2();
        }
    }
    (ent * 100.0).round() as u32
}

pub fn serialize_birthmarks_to_json(bm: &DeviceBirthmarks) -> JsonValue {
    let pg_arr: Vec<JsonValue> = bm
        .pg_controls
        .iter()
        .map(|pg| {
            JsonValue::OrderedObject(vec![
                ("path".to_string(), JsonValue::str(&pg.path)),
                (
                    "system_identifier".to_string(),
                    JsonValue::str(pg.system_identifier.to_string()),
                ),
                (
                    "system_identifier_hex".to_string(),
                    JsonValue::str(&pg.system_identifier_hex),
                ),
                (
                    "pg_control_version".to_string(),
                    JsonValue::Uint(pg.pg_control_version as u64),
                ),
                (
                    "catalog_version_no".to_string(),
                    JsonValue::Uint(pg.catalog_version_no as u64),
                ),
                ("db_state".to_string(), JsonValue::Uint(pg.db_state as u64)),
                (
                    "control_timestamp_unix".to_string(),
                    JsonValue::Int(pg.control_timestamp_unix),
                ),
                (
                    "checkpoint_lsn".to_string(),
                    JsonValue::str(format!("0x{:016x}", pg.checkpoint_lsn)),
                ),
                ("crc32c_valid".to_string(), JsonValue::Bool(pg.crc32c_valid)),
                (
                    "crc32c_offset".to_string(),
                    JsonValue::Uint(pg.crc32c_offset as u64),
                ),
                (
                    "stored_crc32c".to_string(),
                    JsonValue::str(format!("0x{:08x}", pg.stored_crc32c)),
                ),
            ])
        })
        .collect();

    let sb_arr: Vec<JsonValue> = bm
        .superblocks
        .iter()
        .map(|sb| {
            JsonValue::OrderedObject(vec![
                ("source_path".to_string(), JsonValue::str(&sb.source_path)),
                ("fs_type".to_string(), JsonValue::str(&sb.fs_type)),
                ("uuid".to_string(), JsonValue::str(&sb.uuid)),
                (
                    "meta_uuid".to_string(),
                    match &sb.meta_uuid {
                        Some(m) => JsonValue::str(m.as_str()),
                        None => JsonValue::Null,
                    },
                ),
                ("volume_label".to_string(), JsonValue::str(&sb.volume_label)),
                ("last_mounted".to_string(), JsonValue::str(&sb.last_mounted)),
                (
                    "mkfs_time_unix".to_string(),
                    match sb.mkfs_time_unix {
                        Some(t) => JsonValue::Uint(t),
                        None => JsonValue::Null,
                    },
                ),
                (
                    "last_write_time_unix".to_string(),
                    match sb.last_write_time_unix {
                        Some(t) => JsonValue::Uint(t),
                        None => JsonValue::Null,
                    },
                ),
                (
                    "parsed_from_raw_superblock".to_string(),
                    JsonValue::Bool(sb.parsed_from_raw_superblock),
                ),
            ])
        })
        .collect();

    let ssh_arr: Vec<JsonValue> = bm
        .ssh_host_keys
        .iter()
        .map(|k| {
            JsonValue::OrderedObject(vec![
                ("path".to_string(), JsonValue::str(&k.path)),
                ("algorithm".to_string(), JsonValue::str(&k.algorithm)),
                (
                    "key_blob_sha256".to_string(),
                    JsonValue::str(&k.key_blob_sha256),
                ),
            ])
        })
        .collect();

    let seeds_arr: Vec<JsonValue> = bm
        .crypto_seeds
        .iter()
        .map(|s| {
            JsonValue::OrderedObject(vec![
                ("file_path".to_string(), JsonValue::str(&s.file_path)),
                (
                    "parameter_name".to_string(),
                    JsonValue::str(&s.parameter_name),
                ),
                ("seed_kind".to_string(), JsonValue::str(&s.seed_kind)),
                (
                    "hmac_sha256_fingerprint".to_string(),
                    JsonValue::str(&s.hmac_sha256_fingerprint),
                ),
                (
                    "secret_byte_len".to_string(),
                    JsonValue::Uint(s.secret_byte_len as u64),
                ),
                (
                    "shannon_entropy_x100".to_string(),
                    JsonValue::Uint(s.shannon_entropy_x100 as u64),
                ),
            ])
        })
        .collect();

    JsonValue::OrderedObject(vec![
        ("hostname".to_string(), JsonValue::str(&bm.hostname)),
        (
            "machine_id".to_string(),
            match &bm.machine_id {
                Some(m) => JsonValue::str(m.as_str()),
                None => JsonValue::Null,
            },
        ),
        (
            "dbus_machine_id".to_string(),
            match &bm.dbus_machine_id {
                Some(m) => JsonValue::str(m.as_str()),
                None => JsonValue::Null,
            },
        ),
        (
            "pg_controls_count".to_string(),
            JsonValue::Uint(bm.pg_controls.len() as u64),
        ),
        ("pg_controls".to_string(), JsonValue::Array(pg_arr)),
        (
            "superblocks_count".to_string(),
            JsonValue::Uint(bm.superblocks.len() as u64),
        ),
        ("superblocks".to_string(), JsonValue::Array(sb_arr)),
        (
            "ssh_host_keys_count".to_string(),
            JsonValue::Uint(bm.ssh_host_keys.len() as u64),
        ),
        ("ssh_host_keys".to_string(), JsonValue::Array(ssh_arr)),
        (
            "crypto_seeds_count".to_string(),
            JsonValue::Uint(bm.crypto_seeds.len() as u64),
        ),
        ("crypto_seeds".to_string(), JsonValue::Array(seeds_arr)),
    ])
}

fn collect_named_files_bounded(
    dir: &Path,
    target_name: &str,
    max_depth: usize,
    out: &mut Vec<PathBuf>,
) {
    if max_depth == 0 {
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
            collect_named_files_bounded(&p, target_name, max_depth - 1, out);
        } else if ft.is_file() && entry.file_name().to_str() == Some(target_name) {
            out.push(p);
        }
    }
}

fn collect_seed_config_files_bounded(dir: &Path, max_depth: usize, out: &mut Vec<PathBuf>) {
    if max_depth == 0 {
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
        let name = entry.file_name().to_string_lossy().into_owned();
        if ft.is_dir() {
            // Skip Python third-party site-packages / static assets / __pycache__ to focus on appliance code & config
            if name == "site-packages"
                || name == "dist-packages"
                || name == "__pycache__"
                || name == "node_modules"
                || name == ".git"
            {
                continue;
            }
            collect_seed_config_files_bounded(&entry.path(), max_depth - 1, out);
        } else if ft.is_file() {
            let matches_ext = name.ends_with(".py")
                || name.ends_with(".conf")
                || name.ends_with(".env")
                || name.starts_with(".env")
                || name.ends_with(".ini")
                || name.ends_with(".cfg")
                || name.ends_with(".yml")
                || name.ends_with(".yaml");
            if matches_ext {
                out.push(entry.path());
            }
        }
    }
}

fn parse_cstr_fixed(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).trim().to_string()
}

fn is_canonical_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    for (idx, b) in s.bytes().enumerate() {
        if idx == 8 || idx == 13 || idx == 18 || idx == 23 {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

pub fn join_rooted(root: &Path, rel: &str) -> PathBuf {
    let clean = rel.trim_start_matches('/');
    if clean.is_empty() {
        root.to_path_buf()
    } else {
        root.join(clean)
    }
}

pub fn display_under_root(root: &Path, full: &Path) -> String {
    if root == Path::new("/") {
        return full.to_string_lossy().into_owned();
    }
    if let Ok(stripped) = full.strip_prefix(root) {
        format!("/{}", stripped.to_string_lossy())
    } else {
        full.to_string_lossy().into_owned()
    }
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}
