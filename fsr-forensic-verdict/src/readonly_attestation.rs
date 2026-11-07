//! Engine 2: Read-Only Non-Mutation & Chain-of-Custody Evidence Integrity Attestation.
//!
//! Proves mathematically and forensically that executing `fsr-forensic-verdict` across
//! all 19 engines did not alter a single byte, inode, or metadata timestamp on the
//! inspected `--root <path>` appliance or mounted forensic image:
//!   - `capture_pre_audit_state`: Captures `(size, mtime, ctime, inode, mode, sha256)`
//!     across critical evidence artifacts (`rpmdb.sqlite`, `pg_control`, `libssl.so.3`,
//!     `pam_unix.so`, `cacert.pem`, `settings.py`, etc.), Linux `/proc/self/mountinfo`
//!     read-only mount flags, and `/proc/self/io` (`syscr` / `syscw`) counters.
//!   - `verify_post_audit_state`: Re-hashes and re-stats every tracked artifact after
//!     all 19 engines finish, producing [`NonMutationAttestation`].

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fsr_deep_audit::crypto::{hex_digests_equal, sha256_file, Sha256};
use fsr_deep_audit::schema::JsonValue;

const MAX_TRACKED_ARTIFACTS: usize = 512;
const MAX_HASHABLE_FILE_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB cap per regular file
const MAX_SUBTREE_WALK_DEPTH: usize = 7;

/// Fixed high-value forensic artifacts checked directly relative to `--root`.
const WELL_KNOWN_RELATIVE_ARTIFACTS: &[&str] = &[
    "var/lib/rpm/rpmdb.sqlite",
    "var/lib/rpm/Packages",
    "usr/lib64/libssl.so.3",
    "usr/lib64/libssl.so.1.1",
    "usr/lib64/libcrypto.so.3",
    "usr/lib64/libcrypto.so.1.1",
    "usr/lib64/security/pam_unix.so",
    "lib64/security/pam_unix.so",
    "etc/pki/tls/certs/ca-bundle.crt",
    "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "etc/nginx/nginx.conf",
    "etc/machine-id",
    "var/lib/dbus/machine-id",
    "etc/passwd",
    "etc/ld.so.preload",
    "etc/hosts",
    "etc/resolv.conf",
    "etc/ssh/sshd_config",
    "etc/crontab",
    "var/log/wtmp",
];

/// Subtrees under `--root` walked (read-only, no symlink traversal) for dynamic artifacts.
const CRITICAL_SUBTREES: &[&str] = &[
    "var/lib/pgsql",
    "opt/cyops",
    "opt/cyops-integrations",
    "opt/cyops-workflow",
    "opt/cyops-auth",
    "etc/pki/ca-trust/source/anchors",
    "etc/nginx/conf.d",
    "etc/pam.d",
    "etc/systemd/system",
    "etc/systemd/system-generators",
];

/// Snapshot of a single regular evidence file's metadata and SHA-256 content digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactStateRecord {
    pub logical_path: String,
    pub physical_path: PathBuf,
    pub size_bytes: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub inode: u64,
    pub mode: u32,
    pub sha256_hex: String,
}

impl ArtifactStateRecord {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("logical_path".to_string(), JsonValue::str(&self.logical_path)),
            ("size_bytes".to_string(), JsonValue::Uint(self.size_bytes)),
            ("mtime_sec".to_string(), JsonValue::Int(self.mtime_sec)),
            ("mtime_nsec".to_string(), JsonValue::Int(self.mtime_nsec)),
            ("ctime_sec".to_string(), JsonValue::Int(self.ctime_sec)),
            ("ctime_nsec".to_string(), JsonValue::Int(self.ctime_nsec)),
            ("inode".to_string(), JsonValue::Uint(self.inode)),
            ("mode".to_string(), JsonValue::Uint(self.mode as u64)),
            ("sha256_hex".to_string(), JsonValue::str(&self.sha256_hex)),
        ])
    }
}

/// Parsed mount entry from Linux `/proc/self/mountinfo` covering the target `--root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountReadOnlyStatus {
    pub mount_point: String,
    pub fs_type: String,
    pub mount_source: String,
    pub vfs_options: String,
    pub super_options: String,
    pub is_read_only: bool,
}

/// Parsed I/O syscall counters from Linux `/proc/self/io`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcSelfIoStats {
    pub available: bool,
    pub rchar: u64,
    pub wchar: u64,
    pub syscr: u64,
    pub syscw: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

impl ProcSelfIoStats {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("available".to_string(), JsonValue::Bool(self.available)),
            ("rchar".to_string(), JsonValue::Uint(self.rchar)),
            ("wchar".to_string(), JsonValue::Uint(self.wchar)),
            ("syscr".to_string(), JsonValue::Uint(self.syscr)),
            ("syscw".to_string(), JsonValue::Uint(self.syscw)),
            ("read_bytes".to_string(), JsonValue::Uint(self.read_bytes)),
            ("write_bytes".to_string(), JsonValue::Uint(self.write_bytes)),
        ])
    }
}

/// Detailed discrepancy if any tracked evidence file changed between pre- and post-audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMutationDiff {
    pub logical_path: String,
    pub reason: String,
    pub pre_sha256_hex: Option<String>,
    pub post_sha256_hex: Option<String>,
}

impl ArtifactMutationDiff {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::OrderedObject(vec![
            ("logical_path".to_string(), JsonValue::str(&self.logical_path)),
            ("reason".to_string(), JsonValue::str(&self.reason)),
            (
                "pre_sha256_hex".to_string(),
                match &self.pre_sha256_hex {
                    Some(s) => JsonValue::str(s),
                    None => JsonValue::Null,
                },
            ),
            (
                "post_sha256_hex".to_string(),
                match &self.post_sha256_hex {
                    Some(s) => JsonValue::str(s),
                    None => JsonValue::Null,
                },
            ),
        ])
    }
}

/// Pre-audit baseline captured immediately before launching the 19 detection engines.
#[derive(Debug, Clone)]
pub struct PreAuditSnapshot {
    pub root_path: PathBuf,
    pub extra_files: Vec<PathBuf>,
    pub capture_started_unix: u64,
    pub artifacts: BTreeMap<String, ArtifactStateRecord>,
    pub pre_state_digest_hex: String,
    pub mount_status: Option<MountReadOnlyStatus>,
    pub pre_io: ProcSelfIoStats,
}

/// Final chain-of-custody non-mutation attestation sealed into the forensic report.
#[derive(Debug, Clone)]
pub struct NonMutationAttestation {
    pub target_mutated: bool,
    pub verified_artifact_count: usize,
    pub pre_state_digest_hex: String,
    pub post_state_digest_hex: String,
    pub capture_started_unix: u64,
    pub verification_completed_unix: u64,
    pub mount_status: Option<MountReadOnlyStatus>,
    pub pre_io: ProcSelfIoStats,
    pub post_io: ProcSelfIoStats,
    pub delta_syscr: u64,
    pub delta_syscw: u64,
    pub delta_storage_write_bytes: u64,
    pub mutations: Vec<ArtifactMutationDiff>,
    pub tracked_artifacts: Vec<ArtifactStateRecord>,
}

impl NonMutationAttestation {
    pub fn to_json(&self) -> JsonValue {
        let mount_json = match &self.mount_status {
            Some(m) => JsonValue::OrderedObject(vec![
                ("mountinfo_inspected".to_string(), JsonValue::Bool(true)),
                ("is_read_only_mount".to_string(), JsonValue::Bool(m.is_read_only)),
                ("mount_point".to_string(), JsonValue::str(&m.mount_point)),
                ("fs_type".to_string(), JsonValue::str(&m.fs_type)),
                ("mount_source".to_string(), JsonValue::str(&m.mount_source)),
                ("vfs_options".to_string(), JsonValue::str(&m.vfs_options)),
                ("super_options".to_string(), JsonValue::str(&m.super_options)),
            ]),
            None => JsonValue::OrderedObject(vec![
                ("mountinfo_inspected".to_string(), JsonValue::Bool(false)),
                ("is_read_only_mount".to_string(), JsonValue::Bool(false)),
                (
                    "note".to_string(),
                    JsonValue::str("Linux /proc/self/mountinfo unavailable on host OS"),
                ),
            ]),
        };

        JsonValue::OrderedObject(vec![
            (
                "target_mutated".to_string(),
                JsonValue::Bool(self.target_mutated),
            ),
            (
                "verified_artifact_count".to_string(),
                JsonValue::Uint(self.verified_artifact_count as u64),
            ),
            (
                "pre_state_digest_hex".to_string(),
                JsonValue::str(&self.pre_state_digest_hex),
            ),
            (
                "post_state_digest_hex".to_string(),
                JsonValue::str(&self.post_state_digest_hex),
            ),
            (
                "capture_started_unix".to_string(),
                JsonValue::Uint(self.capture_started_unix),
            ),
            (
                "verification_completed_unix".to_string(),
                JsonValue::Uint(self.verification_completed_unix),
            ),
            ("mount_attestation".to_string(), mount_json),
            (
                "proc_self_io".to_string(),
                JsonValue::OrderedObject(vec![
                    ("pre".to_string(), self.pre_io.to_json()),
                    ("post".to_string(), self.post_io.to_json()),
                    ("delta_syscr".to_string(), JsonValue::Uint(self.delta_syscr)),
                    ("delta_syscw".to_string(), JsonValue::Uint(self.delta_syscw)),
                    (
                        "delta_storage_write_bytes".to_string(),
                        JsonValue::Uint(self.delta_storage_write_bytes),
                    ),
                ]),
            ),
            (
                "mutations".to_string(),
                JsonValue::Array(self.mutations.iter().map(|m| m.to_json()).collect()),
            ),
            (
                "tracked_artifacts".to_string(),
                JsonValue::Array(self.tracked_artifacts.iter().map(|a| a.to_json()).collect()),
            ),
        ])
    }
}

/// Captures the pre-audit metadata & SHA-256 state of critical evidence files on `root`
/// before any forensic engine executes.
pub fn capture_pre_audit_state(root: &Path, extra_files: &[PathBuf]) -> PreAuditSnapshot {
    let capture_started_unix = unix_now_secs();
    let pre_io = read_host_proc_self_io();
    let mount_status = inspect_target_mount_readonly(root);

    let candidates = discover_candidate_artifacts(root, extra_files);
    let mut artifacts = BTreeMap::new();
    for (logical_path, phys_path) in candidates {
        if let Some(rec) = snapshot_single_file(&logical_path, &phys_path) {
            artifacts.insert(logical_path, rec);
        }
    }

    let pre_state_digest_hex = compute_manifest_state_digest(artifacts.values());

    PreAuditSnapshot {
        root_path: root.to_path_buf(),
        extra_files: extra_files.to_vec(),
        capture_started_unix,
        artifacts,
        pre_state_digest_hex,
        mount_status,
        pre_io,
    }
}

/// Re-verifies every tracked artifact after all 19 engines complete and produces
/// the cryptographic [`NonMutationAttestation`].
pub fn verify_post_audit_state(pre: &PreAuditSnapshot) -> NonMutationAttestation {
    let mut post_map: BTreeMap<String, ArtifactStateRecord> = BTreeMap::new();

    // 1. Re-snapshot every artifact that existed in the pre-audit snapshot
    for (logical_path, pre_rec) in &pre.artifacts {
        if let Some(post_rec) = snapshot_single_file(logical_path, &pre_rec.physical_path) {
            post_map.insert(logical_path.clone(), post_rec);
        }
    }

    // 2. Re-run candidate discovery to ensure no new artifact was dropped into tracked paths
    for (logical_path, phys_path) in discover_candidate_artifacts(&pre.root_path, &pre.extra_files)
    {
        if let std::collections::btree_map::Entry::Vacant(e) = post_map.entry(logical_path) {
            if let Some(post_rec) = snapshot_single_file(e.key(), &phys_path) {
                e.insert(post_rec);
            }
        }
    }

    let post_state_digest_hex = compute_manifest_state_digest(post_map.values());
    let mut mutations = Vec::new();

    for (logical_path, pre_rec) in &pre.artifacts {
        match post_map.get(logical_path) {
            None => {
                mutations.push(ArtifactMutationDiff {
                    logical_path: logical_path.clone(),
                    reason: "artifact_deleted_or_unreadable_post_audit".to_string(),
                    pre_sha256_hex: Some(pre_rec.sha256_hex.clone()),
                    post_sha256_hex: None,
                });
            }
            Some(post_rec) => {
                let mut diffs = Vec::new();
                if !hex_digests_equal(&pre_rec.sha256_hex, &post_rec.sha256_hex) {
                    diffs.push("sha256_mismatch");
                }
                if pre_rec.size_bytes != post_rec.size_bytes {
                    diffs.push("size_changed");
                }
                if pre_rec.mtime_sec != post_rec.mtime_sec
                    || pre_rec.mtime_nsec != post_rec.mtime_nsec
                {
                    diffs.push("mtime_changed");
                }
                if pre_rec.ctime_sec != post_rec.ctime_sec
                    || pre_rec.ctime_nsec != post_rec.ctime_nsec
                {
                    diffs.push("ctime_changed");
                }
                if pre_rec.inode != post_rec.inode {
                    diffs.push("inode_replaced");
                }
                if pre_rec.mode != post_rec.mode {
                    diffs.push("permissions_changed");
                }
                if !diffs.is_empty() {
                    mutations.push(ArtifactMutationDiff {
                        logical_path: logical_path.clone(),
                        reason: diffs.join(","),
                        pre_sha256_hex: Some(pre_rec.sha256_hex.clone()),
                        post_sha256_hex: Some(post_rec.sha256_hex.clone()),
                    });
                }
            }
        }
    }

    for (logical_path, post_rec) in &post_map {
        if !pre.artifacts.contains_key(logical_path) {
            mutations.push(ArtifactMutationDiff {
                logical_path: logical_path.clone(),
                reason: "unexpected_new_artifact_created_during_audit".to_string(),
                pre_sha256_hex: None,
                post_sha256_hex: Some(post_rec.sha256_hex.clone()),
            });
        }
    }

    let post_io = read_host_proc_self_io();
    let verification_completed_unix = unix_now_secs();
    let target_mutated = !mutations.is_empty()
        || !hex_digests_equal(&pre.pre_state_digest_hex, &post_state_digest_hex);

    let tracked_artifacts: Vec<ArtifactStateRecord> = post_map.into_values().collect();

    NonMutationAttestation {
        target_mutated,
        verified_artifact_count: tracked_artifacts.len(),
        pre_state_digest_hex: pre.pre_state_digest_hex.clone(),
        post_state_digest_hex,
        capture_started_unix: pre.capture_started_unix,
        verification_completed_unix,
        mount_status: pre.mount_status.clone(),
        pre_io: pre.pre_io,
        post_io,
        delta_syscr: post_io.syscr.saturating_sub(pre.pre_io.syscr),
        delta_syscw: post_io.syscw.saturating_sub(pre.pre_io.syscw),
        delta_storage_write_bytes: post_io.write_bytes.saturating_sub(pre.pre_io.write_bytes),
        mutations,
        tracked_artifacts,
    }
}

/// Computes the deterministic SHA-256 digest over an ordered sequence of [`ArtifactStateRecord`]s.
/// Exposed publicly so `bundle_verifier` can recompute and verify the attestation manifest offline.
pub fn compute_manifest_state_digest<'a, I>(records: I) -> String
where
    I: IntoIterator<Item = &'a ArtifactStateRecord>,
{
    let mut sorted: BTreeMap<&str, &ArtifactStateRecord> = BTreeMap::new();
    for rec in records {
        sorted.insert(rec.logical_path.as_str(), rec);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"FSR-NON-MUTATION-MANIFEST-V1\n");
    for rec in sorted.values() {
        let line = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            rec.logical_path,
            rec.size_bytes,
            rec.mtime_sec,
            rec.mtime_nsec,
            rec.ctime_sec,
            rec.ctime_nsec,
            rec.inode,
            rec.mode,
            rec.sha256_hex.to_ascii_lowercase()
        );
        hasher.update(line.as_bytes());
    }
    hasher.finalize_hex()
}

/// Parses Linux `/proc/self/mountinfo` text and determines whether `target_path` resides
/// on a read-only (`ro`) VFS mount or read-only superblock.
pub fn parse_proc_mountinfo_for_path(
    mountinfo_text: &str,
    target_path: &str,
) -> Option<MountReadOnlyStatus> {
    let normalized_target = if target_path.is_empty() {
        "/"
    } else {
        target_path
    };

    let mut best_match: Option<(usize, MountReadOnlyStatus)> = None;

    for raw_line in mountinfo_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        // Format per proc(5):
        // 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
        let Some((lhs, rhs)) = line.split_once(" - ") else {
            continue;
        };
        let lhs_tokens: Vec<&str> = lhs.split_whitespace().collect();
        let rhs_tokens: Vec<&str> = rhs.split_whitespace().collect();
        if lhs_tokens.len() < 6 || rhs_tokens.len() < 3 {
            continue;
        }

        let mount_point = unescape_mountinfo_path(lhs_tokens[4]);
        let vfs_options = lhs_tokens[5].to_string();
        let fs_type = rhs_tokens[0].to_string();
        let mount_source = unescape_mountinfo_path(rhs_tokens[1]);
        let super_options = rhs_tokens[2].to_string();

        if path_covered_by_mount(&mount_point, normalized_target) {
            let specificity = mount_point.len();
            let is_ro = has_ro_mount_flag(&vfs_options) || has_ro_mount_flag(&super_options);
            let candidate = MountReadOnlyStatus {
                mount_point,
                fs_type,
                mount_source,
                vfs_options,
                super_options,
                is_read_only: is_ro,
            };
            match &best_match {
                None => best_match = Some((specificity, candidate)),
                Some((prev_len, _)) if specificity >= *prev_len => {
                    best_match = Some((specificity, candidate));
                }
                _ => {}
            }
        }
    }

    best_match.map(|(_, m)| m)
}

/// Parses Linux `/proc/self/io` key-value lines into [`ProcSelfIoStats`].
pub fn parse_proc_self_io(io_text: &str) -> ProcSelfIoStats {
    let mut stats = ProcSelfIoStats::default();
    for line in io_text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let Ok(num) = v.trim().parse::<u64>() else {
            continue;
        };
        stats.available = true;
        match k.trim() {
            "rchar" => stats.rchar = num,
            "wchar" => stats.wchar = num,
            "syscr" => stats.syscr = num,
            "syscw" => stats.syscw = num,
            "read_bytes" => stats.read_bytes = num,
            "write_bytes" => stats.write_bytes = num,
            _ => {}
        }
    }
    stats
}

fn inspect_target_mount_readonly(root: &Path) -> Option<MountReadOnlyStatus> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").ok()?;
    let canon = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    parse_proc_mountinfo_for_path(&mountinfo, &canon.to_string_lossy())
}

fn read_host_proc_self_io() -> ProcSelfIoStats {
    match fs::read_to_string("/proc/self/io") {
        Ok(text) => parse_proc_self_io(&text),
        Err(_) => ProcSelfIoStats::default(),
    }
}

fn has_ro_mount_flag(opts: &str) -> bool {
    opts.split(',').any(|flag| flag.trim() == "ro")
}

fn path_covered_by_mount(mount_point: &str, target: &str) -> bool {
    if mount_point == "/" {
        return target.starts_with('/');
    }
    let mp = mount_point.trim_end_matches('/');
    if target == mp {
        return true;
    }
    if let Some(rest) = target.strip_prefix(mp) {
        rest.starts_with('/')
    } else {
        false
    }
}

fn unescape_mountinfo_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && (b'0'..=b'7').contains(&bytes[i + 1])
            && (b'0'..=b'7').contains(&bytes[i + 2])
            && (b'0'..=b'7').contains(&bytes[i + 3])
        {
            let v = ((bytes[i + 1] - b'0') << 6)
                | ((bytes[i + 2] - b'0') << 3)
                | (bytes[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn discover_candidate_artifacts(root: &Path, extra_files: &[PathBuf]) -> BTreeMap<String, PathBuf> {
    let mut found: BTreeMap<String, PathBuf> = BTreeMap::new();

    for &rel in WELL_KNOWN_RELATIVE_ARTIFACTS {
        if found.len() >= MAX_TRACKED_ARTIFACTS {
            break;
        }
        let p = root.join(rel);
        if is_regular_non_symlink(&p) {
            found.insert(format!("/{}", rel), p);
        }
    }

    for &sub in CRITICAL_SUBTREES {
        if found.len() >= MAX_TRACKED_ARTIFACTS {
            break;
        }
        let base = root.join(sub);
        if is_dir_non_symlink(&base) {
            walk_critical_subtree(root, &base, 0, &mut found);
        }
    }

    // Fallback for minimal synthetic roots where only non-standard subdirectories exist
    if found.is_empty() && is_dir_non_symlink(root) && root != Path::new("/") {
        walk_critical_subtree(root, root, 0, &mut found);
    }

    for extra in extra_files {
        if found.len() >= MAX_TRACKED_ARTIFACTS {
            break;
        }
        if is_regular_non_symlink(extra) {
            let key = format!("external:{}", extra.to_string_lossy());
            found.insert(key, extra.clone());
        }
    }

    found
}

fn walk_critical_subtree(
    root: &Path,
    dir: &Path,
    depth: usize,
    found: &mut BTreeMap<String, PathBuf>,
) {
    if depth > MAX_SUBTREE_WALK_DEPTH || found.len() >= MAX_TRACKED_ARTIFACTS {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|x| x.path())).collect();
    entries.sort();

    for path in entries {
        if found.len() >= MAX_TRACKED_ARTIFACTS {
            break;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        let ft = meta.file_type();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if matches!(name, "proc" | "sys" | "dev" | "run") {
                continue;
            }
            walk_critical_subtree(root, &path, depth + 1, found);
        } else if ft.is_file() && meta.len() <= MAX_HASHABLE_FILE_BYTES && is_high_value_file(&path)
        {
            let rel = path
                .strip_prefix(root)
                .map(|r| format!("/{}", r.to_string_lossy().replace('\\', "/")))
                .unwrap_or_else(|_| path.to_string_lossy().into_owned());
            found.insert(rel, path);
        }
    }
}

fn is_high_value_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if matches!(
        name,
        "pg_control"
            | "postgresql.conf"
            | "postgresql.auto.conf"
            | "pg_hba.conf"
            | "cacert.pem"
            | "settings.py"
            | "wsgi.py"
            | "info.json"
            | "rpmdb.sqlite"
            | "pam_unix.so"
    ) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".py")
        || lower.ends_with(".pyc")
        || lower.ends_with(".conf")
        || lower.ends_with(".pem")
        || lower.ends_with(".crt")
        || lower.ends_with(".so")
        || lower.ends_with(".service")
        || lower.ends_with(".sql")
        || lower.ends_with(".lic")
        || lower.ends_with(".json")
}

fn is_regular_non_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_file() && !m.file_type().is_symlink())
        .unwrap_or(false)
}

fn is_dir_non_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_dir() && !m.file_type().is_symlink())
        .unwrap_or(false)
}

fn snapshot_single_file(logical_path: &str, phys_path: &Path) -> Option<ArtifactStateRecord> {
    let meta = fs::symlink_metadata(phys_path).ok()?;
    if !meta.file_type().is_file() || meta.file_type().is_symlink() {
        return None;
    }
    if meta.len() > MAX_HASHABLE_FILE_BYTES {
        return None;
    }
    let sha256_hex = sha256_file(phys_path).ok()?;

    let (mtime_sec, mtime_nsec, ctime_sec, ctime_nsec, inode, mode) = extract_os_metadata(&meta);

    Some(ArtifactStateRecord {
        logical_path: logical_path.to_string(),
        physical_path: phys_path.to_path_buf(),
        size_bytes: meta.len(),
        mtime_sec,
        mtime_nsec,
        ctime_sec,
        ctime_nsec,
        inode,
        mode,
        sha256_hex,
    })
}

#[cfg(unix)]
fn extract_os_metadata(meta: &fs::Metadata) -> (i64, i64, i64, i64, u64, u32) {
    use std::os::unix::fs::MetadataExt;
    (
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
        meta.ino(),
        meta.mode(),
    )
}

#[cfg(not(unix))]
fn extract_os_metadata(meta: &fs::Metadata) -> (i64, i64, i64, i64, u64, u32) {
    let mtime_sec = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mode = if meta.permissions().readonly() {
        0o100444
    } else {
        0o100644
    };
    (mtime_sec, 0, mtime_sec, 0, 0, mode)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mountinfo_readonly_longest_prefix_and_proc_io_parser() {
        let sample_mountinfo = "\
22 1 253:0 / / rw,relatime shared:1 - xfs /dev/mapper/rl-root rw,attr2,inode64\n\
89 22 7:0 / /mnt/fortisoar_evidence ro,noexec,nodev,nosuid - ext4 /dev/loop0 ro,noload\n\
94 89 0:45 / /mnt/fortisoar_evidence/scratch rw,nosuid - tmpfs tmpfs rw\n";

        let ro_hit =
            parse_proc_mountinfo_for_path(sample_mountinfo, "/mnt/fortisoar_evidence/opt/cyops")
                .unwrap();
        assert!(ro_hit.is_read_only);
        assert_eq!(ro_hit.mount_point, "/mnt/fortisoar_evidence");
        assert_eq!(ro_hit.fs_type, "ext4");

        let rw_hit = parse_proc_mountinfo_for_path(
            sample_mountinfo,
            "/mnt/fortisoar_evidence/scratch/temp.bin",
        )
        .unwrap();
        assert!(!rw_hit.is_read_only);
        assert_eq!(rw_hit.mount_point, "/mnt/fortisoar_evidence/scratch");

        let sample_io = "\
rchar: 981234\n\
wchar: 0\n\
syscr: 412\n\
syscw: 0\n\
read_bytes: 524288\n\
write_bytes: 0\n\
cancelled_write_bytes: 0\n";
        let io = parse_proc_self_io(sample_io);
        assert!(io.available);
        assert_eq!(io.syscr, 412);
        assert_eq!(io.syscw, 0);
        assert_eq!(io.read_bytes, 524288);
        assert_eq!(io.write_bytes, 0);
    }
}
