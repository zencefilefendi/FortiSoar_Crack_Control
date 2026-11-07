//! Engine 2: Time-Freeze, Snapshot Rollback & Trial License Abuse Detector.
//!
//! Detects RTC / system clock rewinds, VM snapshot time-freezes, `libfaketime`
//! userland interposition, and NTP sabotage used to perpetually extend `FGVMEV`
//! 15-day evaluations or expiring FortiSOAR licenses:
//!   - Parses binary `/var/log/wtmp` (`384`-byte `x86_64` `struct utmp`) and
//!     `/var/log/lastlog` (`292`-byte `x86_64` `struct lastlog`) records.
//!   - Cross-checks EXT4 `s_mkfs_time`/`s_wtime`, filesystem inode `mtime` bounds,
//!     PostgreSQL `pg_control` checkpoint timestamps, `wtmp`/`lastlog` latest timestamps,
//!     and appliance/license X.509 `NotBefore`/`NotAfter` validity windows against the
//!     active/reference system clock.
//!   - Detects `libfaketime` / `FAKETIME` hooks and intentionally masked `chronyd`/`ntpd`
//!     services, emitting `CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE`.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};
use fsr_net_crypto_audit::asn1_x509::{extract_pem_certificates, parse_x509_der};

use crate::birthmark_extractor::{display_under_root, join_rooted, DeviceBirthmarks};

/// `sizeof(struct utmp)` on 64-bit `x86_64` Linux (`__WORDSIZE_TIME64_COMPAT32 == 1`).
pub const WTMP_RECORD_SIZE_X86_64: usize = 384;
/// Byte offset of `ut_tv.tv_sec` (`int32_t`) inside `x86_64` `struct utmp`.
pub const WTMP_TV_SEC_OFFSET: usize = 340;
/// `sizeof(struct lastlog)` on 64-bit `x86_64` Linux.
pub const LASTLOG_RECORD_SIZE_X86_64: usize = 292;

const PLAUSIBLE_MIN_UNIX: i64 = 946_684_800; // 2000-01-01T00:00:00Z
const PLAUSIBLE_MAX_UNIX: i64 = 4_102_444_800; // 2100-01-01T00:00:00Z
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 300; // 5 minutes

/// Backward clock jump observed inside `/var/log/wtmp`.
#[derive(Debug, Clone)]
pub struct WtmpBackwardJump {
    pub record_index: usize,
    pub previous_timestamp_unix: i64,
    pub new_timestamp_unix: i64,
    pub rewind_seconds: i64,
    pub explicit_time_change_record: bool,
}

/// Summary of binary `/var/log/wtmp` inspection.
#[derive(Debug, Clone, Default)]
pub struct WtmpScanSummary {
    pub records_parsed: usize,
    pub earliest_timestamp_unix: Option<i64>,
    pub latest_timestamp_unix: Option<i64>,
    pub backward_jumps: Vec<WtmpBackwardJump>,
}

/// Output of Engine 2 (`time_freeze_audit`).
pub struct TimeFreezeAuditResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 2 chronological consistency, `wtmp`/`lastlog`, `libfaketime`, and NTP sabotage checks.
pub fn run_time_freeze_audit(
    root: &Path,
    birthmarks: &DeviceBirthmarks,
    explicit_reference_now_unix: Option<i64>,
    extra_cert_files: &[&Path],
) -> TimeFreezeAuditResult {
    let mut findings = Vec::new();

    // Determine effective reference clock:
    // 1. Explicit `--reference-time` if provided,
    // 2. Offline `/proc/driver/rtc` (`rtc_date` + `rtc_time`) if present inside a captured root snapshot,
    // 3. Host `SystemTime::now()`.
    let (reference_now_unix, clock_source) = if let Some(ts) = explicit_reference_now_unix {
        (ts, "explicit_reference_time")
    } else if let Some(rtc_ts) = parse_proc_driver_rtc(&join_rooted(root, "proc/driver/rtc")) {
        (rtc_ts, "proc_driver_rtc")
    } else {
        let host_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        (host_now, "system_wall_clock")
    };

    // 1. Parse binary `/var/log/wtmp`
    let wtmp_path = join_rooted(root, "var/log/wtmp");
    let wtmp_summary = fs::read(&wtmp_path)
        .ok()
        .map(|b| parse_wtmp_bytes(&b))
        .unwrap_or_default();

    for jump in &wtmp_summary.backward_jumps {
        findings.push(
            Finding::new(
                EngineId::TimeFreezeAudit,
                "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
                Severity::Critical,
                "/var/log/wtmp",
                format!(
                    "Backward system clock rewind of {} seconds ({} -> {}) recorded in binary /var/log/wtmp at record #{}",
                    jump.rewind_seconds,
                    jump.previous_timestamp_unix,
                    jump.new_timestamp_unix,
                    jump.record_index
                ),
            )
            .with_evidence("record_index", JsonValue::Uint(jump.record_index as u64))
            .with_evidence("previous_timestamp_unix", JsonValue::Int(jump.previous_timestamp_unix))
            .with_evidence("new_timestamp_unix", JsonValue::Int(jump.new_timestamp_unix))
            .with_evidence("rewind_seconds", JsonValue::Int(jump.rewind_seconds))
            .with_evidence("explicit_old_new_time_event", JsonValue::Bool(jump.explicit_time_change_record)),
        );
    }

    // 2. Parse binary `/var/log/lastlog`
    let lastlog_path = join_rooted(root, "var/log/lastlog");
    let (lastlog_records_nonzero, latest_lastlog_unix, latest_lastlog_uid) =
        parse_lastlog_file(&lastlog_path);

    // 3. Sample filesystem inode `mtime` bounds + superblock `s_mkfs_time`/`s_wtime`
    let (earliest_inode_mtime, latest_inode_mtime, latest_inode_path) =
        sample_filesystem_mtime_bounds(root);

    let earliest_mkfs_unix: Option<i64> = birthmarks
        .superblocks
        .iter()
        .filter_map(|sb| sb.mkfs_time_unix.map(|t| t as i64))
        .min();
    let latest_sb_write_unix: Option<i64> = birthmarks
        .superblocks
        .iter()
        .filter_map(|sb| sb.last_write_time_unix.map(|t| t as i64))
        .max();

    // 4. Compare historical high-water marks against `reference_now_unix`
    //    (Only compare against wall clock when `root == "/"` OR explicit reference/RTC clock was provided)
    let compare_against_clock =
        explicit_reference_now_unix.is_some() || clock_source == "proc_driver_rtc" || root == Path::new("/");

    if compare_against_clock && reference_now_unix > 0 {
        for pg in &birthmarks.pg_controls {
            if pg.control_timestamp_unix > reference_now_unix + CLOCK_SKEW_TOLERANCE_SECS
                && pg.control_timestamp_unix <= PLAUSIBLE_MAX_UNIX
            {
                let delta = pg.control_timestamp_unix - reference_now_unix;
                findings.push(
                    Finding::new(
                        EngineId::TimeFreezeAudit,
                        "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
                        Severity::Critical,
                        &pg.path,
                        format!(
                            "PostgreSQL pg_control checkpoint timestamp ({}) is {} seconds AHEAD of active system clock ({}) — system clock rewound/frozen to bypass license expiry",
                            pg.control_timestamp_unix, delta, reference_now_unix
                        ),
                    )
                    .with_evidence("pg_control_timestamp_unix", JsonValue::Int(pg.control_timestamp_unix))
                    .with_evidence("reference_clock_unix", JsonValue::Int(reference_now_unix))
                    .with_evidence("clock_source", JsonValue::str(clock_source))
                    .with_evidence("future_skew_seconds", JsonValue::Int(delta)),
                );
            }
        }

        if let Some(wtmp_max) = wtmp_summary.latest_timestamp_unix {
            if wtmp_max > reference_now_unix + CLOCK_SKEW_TOLERANCE_SECS {
                let delta = wtmp_max - reference_now_unix;
                findings.push(
                    Finding::new(
                        EngineId::TimeFreezeAudit,
                        "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
                        Severity::Critical,
                        "/var/log/wtmp",
                        format!(
                            "Latest /var/log/wtmp login timestamp ({}) is {} seconds AHEAD of active system clock ({}) — RTC/system time rolled back",
                            wtmp_max, delta, reference_now_unix
                        ),
                    )
                    .with_evidence("latest_wtmp_unix", JsonValue::Int(wtmp_max))
                    .with_evidence("reference_clock_unix", JsonValue::Int(reference_now_unix))
                    .with_evidence("future_skew_seconds", JsonValue::Int(delta)),
                );
            }
        }

        if let Some(ll_max) = latest_lastlog_unix {
            if ll_max > reference_now_unix + CLOCK_SKEW_TOLERANCE_SECS {
                let delta = ll_max - reference_now_unix;
                findings.push(
                    Finding::new(
                        EngineId::TimeFreezeAudit,
                        "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
                        Severity::Critical,
                        "/var/log/lastlog",
                        format!(
                            "Latest /var/log/lastlog UID {} login timestamp ({}) is {} seconds AHEAD of active system clock ({})",
                            latest_lastlog_uid.unwrap_or(0),
                            ll_max,
                            delta,
                            reference_now_unix
                        ),
                    )
                    .with_evidence("latest_lastlog_unix", JsonValue::Int(ll_max))
                    .with_evidence("uid", JsonValue::Uint(latest_lastlog_uid.unwrap_or(0) as u64))
                    .with_evidence("reference_clock_unix", JsonValue::Int(reference_now_unix))
                    .with_evidence("future_skew_seconds", JsonValue::Int(delta)),
                );
            }
        }

        if let Some(mkfs_ts) = earliest_mkfs_unix {
            if mkfs_ts > reference_now_unix + CLOCK_SKEW_TOLERANCE_SECS {
                findings.push(
                    Finding::new(
                        EngineId::TimeFreezeAudit,
                        "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
                        Severity::Critical,
                        "superblock:s_mkfs_time",
                        format!(
                            "System clock ({}) predates filesystem creation timestamp s_mkfs_time ({}) — severe RTC rollback",
                            reference_now_unix, mkfs_ts
                        ),
                    )
                    .with_evidence("s_mkfs_time_unix", JsonValue::Int(mkfs_ts))
                    .with_evidence("reference_clock_unix", JsonValue::Int(reference_now_unix)),
                );
            }
        }

        if let Some(sb_wtime) = latest_sb_write_unix {
            if sb_wtime > reference_now_unix + CLOCK_SKEW_TOLERANCE_SECS {
                findings.push(
                    Finding::new(
                        EngineId::TimeFreezeAudit,
                        "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
                        Severity::Critical,
                        "superblock:s_wtime",
                        format!(
                            "Superblock last-write timestamp s_wtime ({}) is ahead of active system clock ({})",
                            sb_wtime, reference_now_unix
                        ),
                    )
                    .with_evidence("s_wtime_unix", JsonValue::Int(sb_wtime))
                    .with_evidence("reference_clock_unix", JsonValue::Int(reference_now_unix)),
                );
            }
        }
    }

    // 5. Internal artifact-vs-artifact chronological checks (works even on purely offline disk images
    //    without `--reference-time`!)
    //    Check appliance/license X.509 `NotBefore`/`NotAfter` vs `pg_control` / `wtmp` / `s_mkfs_time` / clock
    let cert_windows = collect_appliance_cert_windows(root, extra_cert_files);
    let max_observed_activity_ts = [
        birthmarks
            .pg_controls
            .iter()
            .map(|p| p.control_timestamp_unix)
            .filter(|&t| (PLAUSIBLE_MIN_UNIX..=PLAUSIBLE_MAX_UNIX).contains(&t))
            .max(),
        wtmp_summary.latest_timestamp_unix,
        latest_lastlog_unix,
        latest_sb_write_unix,
    ]
    .into_iter()
    .flatten()
    .max();

    for (cert_source, cn, not_before, not_after) in &cert_windows {
        if compare_against_clock && reference_now_unix > 0 {
            if let Some(nb) = *not_before {
                if reference_now_unix + CLOCK_SKEW_TOLERANCE_SECS < nb {
                    findings.push(
                        Finding::new(
                            EngineId::TimeFreezeAudit,
                            "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
                            Severity::Critical,
                            cert_source,
                            format!(
                                "Active system clock ({}) precedes appliance/license certificate `{}` NotBefore ({}) — clock rewound past issuance date",
                                reference_now_unix, cn, nb
                            ),
                        )
                        .with_evidence("certificate_cn", JsonValue::str(cn.as_str()))
                        .with_evidence("not_before_unix", JsonValue::Int(nb))
                        .with_evidence("reference_clock_unix", JsonValue::Int(reference_now_unix)),
                    );
                }
            }
            if let (Some(na), Some(max_act)) = (*not_after, max_observed_activity_ts) {
                // Disk/DB proves appliance already operated AFTER certificate/trial expiry `na`,
                // yet current clock is rewound back inside `<= na`!
                if max_act > na + 3600 && reference_now_unix <= na {
                    findings.push(
                        Finding::new(
                            EngineId::TimeFreezeAudit,
                            "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
                            Severity::Critical,
                            cert_source,
                            format!(
                                "Appliance DB/log high-water timestamp ({}) exceeds certificate/license `{}` expiry NotAfter ({}), while active clock ({}) was rewound inside validity window",
                                max_act, cn, na, reference_now_unix
                            ),
                        )
                        .with_evidence("certificate_cn", JsonValue::str(cn.as_str()))
                        .with_evidence("not_after_unix", JsonValue::Int(na))
                        .with_evidence("max_historical_activity_unix", JsonValue::Int(max_act))
                        .with_evidence("reference_clock_unix", JsonValue::Int(reference_now_unix)),
                    );
                }
            }
        }
    }

    // 6. Scan for `libfaketime` / `FAKETIME` hooks
    let faketime_hits = scan_libfaketime_traces(root, &mut findings);

    // 7. Scan for intentional NTP / `chronyd` / hypervisor time-sync disabling
    let ntp_sabotage_hits = scan_ntp_and_rtc_sabotage(
        root,
        !faketime_hits.is_empty() || !wtmp_summary.backward_jumps.is_empty(),
        &mut findings,
    );

    let summary = JsonValue::OrderedObject(vec![
        (
            "reference_clock_unix".to_string(),
            JsonValue::Int(reference_now_unix),
        ),
        ("clock_source".to_string(), JsonValue::str(clock_source)),
        (
            "wtmp_records_parsed".to_string(),
            JsonValue::Uint(wtmp_summary.records_parsed as u64),
        ),
        (
            "latest_wtmp_unix".to_string(),
            opt_i64_json(wtmp_summary.latest_timestamp_unix),
        ),
        (
            "wtmp_backward_jumps_count".to_string(),
            JsonValue::Uint(wtmp_summary.backward_jumps.len() as u64),
        ),
        (
            "lastlog_active_uids".to_string(),
            JsonValue::Uint(lastlog_records_nonzero as u64),
        ),
        (
            "latest_lastlog_unix".to_string(),
            opt_i64_json(latest_lastlog_unix),
        ),
        (
            "earliest_mkfs_time_unix".to_string(),
            opt_i64_json(earliest_mkfs_unix),
        ),
        (
            "earliest_sampled_inode_mtime_unix".to_string(),
            opt_i64_json(earliest_inode_mtime),
        ),
        (
            "latest_sampled_inode_mtime_unix".to_string(),
            opt_i64_json(latest_inode_mtime),
        ),
        (
            "latest_sampled_inode_path".to_string(),
            match latest_inode_path {
                Some(p) => JsonValue::str(p),
                None => JsonValue::Null,
            },
        ),
        (
            "libfaketime_indicators_count".to_string(),
            JsonValue::Uint(faketime_hits.len() as u64),
        ),
        (
            "ntp_sabotage_indicators_count".to_string(),
            JsonValue::Uint(ntp_sabotage_hits as u64),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    TimeFreezeAuditResult { summary, findings }
}

/// Parses binary `x86_64` `/var/log/wtmp` (`384`-byte `struct utmp` records).
pub fn parse_wtmp_bytes(bytes: &[u8]) -> WtmpScanSummary {
    let mut summary = WtmpScanSummary::default();
    if bytes.len() < WTMP_RECORD_SIZE_X86_64 {
        return summary;
    }

    let total_records = bytes.len() / WTMP_RECORD_SIZE_X86_64;
    let mut prev_ts: Option<i64> = None;
    let mut pending_old_time: Option<i64> = None;

    for idx in 0..total_records {
        let rec = &bytes[idx * WTMP_RECORD_SIZE_X86_64..(idx + 1) * WTMP_RECORD_SIZE_X86_64];
        let ut_type = i16::from_le_bytes([rec[0], rec[1]]);
        if !(1..=9).contains(&ut_type) {
            continue;
        }
        let raw_sec = u32::from_le_bytes([
            rec[WTMP_TV_SEC_OFFSET],
            rec[WTMP_TV_SEC_OFFSET + 1],
            rec[WTMP_TV_SEC_OFFSET + 2],
            rec[WTMP_TV_SEC_OFFSET + 3],
        ]) as i64;

        if !(PLAUSIBLE_MIN_UNIX..=PLAUSIBLE_MAX_UNIX).contains(&raw_sec) {
            continue;
        }

        summary.records_parsed += 1;
        summary.earliest_timestamp_unix = Some(match summary.earliest_timestamp_unix {
            Some(cur) => cur.min(raw_sec),
            None => raw_sec,
        });
        summary.latest_timestamp_unix = Some(match summary.latest_timestamp_unix {
            Some(cur) => cur.max(raw_sec),
            None => raw_sec,
        });

        // `OLD_TIME` (4) followed by `NEW_TIME` (3) is written by `date -s` / `settimeofday`
        if ut_type == 4 {
            pending_old_time = Some(raw_sec);
        } else if ut_type == 3 {
            if let Some(old_ts) = pending_old_time.take() {
                if raw_sec + CLOCK_SKEW_TOLERANCE_SECS < old_ts {
                    summary.backward_jumps.push(WtmpBackwardJump {
                        record_index: idx,
                        previous_timestamp_unix: old_ts,
                        new_timestamp_unix: raw_sec,
                        rewind_seconds: old_ts - raw_sec,
                        explicit_time_change_record: true,
                    });
                    prev_ts = Some(raw_sec);
                    continue;
                }
            }
        }

        if let Some(prev) = prev_ts {
            // Sequential append-only `wtmp` jump backwards by > 1 hour
            if raw_sec + 3600 < prev {
                summary.backward_jumps.push(WtmpBackwardJump {
                    record_index: idx,
                    previous_timestamp_unix: prev,
                    new_timestamp_unix: raw_sec,
                    rewind_seconds: prev - raw_sec,
                    explicit_time_change_record: false,
                });
            }
        }
        prev_ts = Some(raw_sec);
    }

    summary
}

/// Streams `/var/log/lastlog` (`292`-byte `struct lastlog` per UID) to find the latest login timestamp.
pub fn parse_lastlog_file(path: &Path) -> (usize, Option<i64>, Option<u32>) {
    let Ok(mut file) = File::open(path) else {
        return (0, None, None);
    };

    let mut active_count = 0usize;
    let mut max_ts: Option<i64> = None;
    let mut max_uid: Option<u32> = None;
    let mut uid: u32 = 0;

    let mut buf = [0u8; LASTLOG_RECORD_SIZE_X86_64 * 64];
    let mut carry = Vec::with_capacity(LASTLOG_RECORD_SIZE_X86_64);

    while let Ok(n) = file.read(&mut buf) {
        if n == 0 {
            break;
        }
        carry.extend_from_slice(&buf[..n]);
        let full_recs = carry.len() / LASTLOG_RECORD_SIZE_X86_64;
        for i in 0..full_recs {
            let base = i * LASTLOG_RECORD_SIZE_X86_64;
            let ts = u32::from_le_bytes([
                carry[base],
                carry[base + 1],
                carry[base + 2],
                carry[base + 3],
            ]) as i64;
            if (PLAUSIBLE_MIN_UNIX..=PLAUSIBLE_MAX_UNIX).contains(&ts) {
                active_count += 1;
                if max_ts.is_none_or(|cur| ts > cur) {
                    max_ts = Some(ts);
                    max_uid = Some(uid);
                }
            }
            uid = uid.saturating_add(1);
        }
        let consumed = full_recs * LASTLOG_RECORD_SIZE_X86_64;
        carry.drain(..consumed);
    }

    (active_count, max_ts, max_uid)
}

fn scan_libfaketime_traces(root: &Path, findings: &mut Vec<Finding>) -> Vec<String> {
    let mut hits = Vec::new();

    // 1. Direct `/etc/faketimerc` or `/etc/ld.so.preload`
    for rel in [
        "etc/faketimerc",
        "root/.faketimerc",
        "etc/ld.so.preload",
        "etc/environment",
        "etc/profile",
    ] {
        let p = join_rooted(root, rel);
        if let Ok(text) = fs::read_to_string(&p) {
            let label = display_under_root(root, &p);
            if rel.ends_with("faketimerc") && !text.trim().is_empty() {
                hits.push(label.clone());
                findings.push(
                    Finding::new(
                        EngineId::TimeFreezeAudit,
                        "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
                        Severity::Critical,
                        &label,
                        format!(
                            "Active libfaketime configuration file `{}` (`{}`) detected — clock frozen for license bypass",
                            label,
                            text.lines().next().unwrap_or("").trim()
                        ),
                    )
                    .with_evidence("faketime_spec", JsonValue::str(text.lines().next().unwrap_or("").trim())),
                );
            } else if contains_faketime_marker(&text) {
                hits.push(label.clone());
                findings.push(
                    Finding::new(
                        EngineId::TimeFreezeAudit,
                        "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
                        Severity::Critical,
                        &label,
                        format!("libfaketime / FAKETIME hook directive injected into `{}`", label),
                    )
                    .with_evidence("matched_file", JsonValue::str(&label)),
                );
            }
        }
    }

    // 2. Scan systemd unit files & drop-in overrides (`*.service`, `*.conf`)
    for rel_dir in [
        "etc/systemd/system",
        "usr/lib/systemd/system",
        "etc/sysconfig",
        "etc/profile.d",
    ] {
        let dir = join_rooted(root, rel_dir);
        scan_dir_for_faketime(&dir, root, 3, &mut hits, findings);
    }

    // 3. Scan `/proc/<pid>/environ` and `/proc/<pid>/maps`
    let proc_dir = join_rooted(root, "proc");
    if let Ok(entries) = fs::read_dir(&proc_dir) {
        for entry in entries.flatten() {
            let pid_str = entry.file_name().to_string_lossy().into_owned();
            if !pid_str.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let p_dir = entry.path();
            for sub in ["maps", "environ"] {
                let f = p_dir.join(sub);
                if let Ok(raw) = fs::read(&f) {
                    let lossy = String::from_utf8_lossy(&raw);
                    if contains_faketime_marker(&lossy) {
                        let target = format!("/proc/{}/{}", pid_str, sub);
                        hits.push(target.clone());
                        findings.push(
                            Finding::new(
                                EngineId::TimeFreezeAudit,
                                "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
                                Severity::Critical,
                                &target,
                                format!(
                                    "Live process PID {} has active `libfaketime` / `FAKETIME` time-interposition hook in {}",
                                    pid_str, sub
                                ),
                            )
                            .with_evidence("pid", JsonValue::str(&pid_str))
                            .with_evidence("proc_artifact", JsonValue::str(sub)),
                        );
                    }
                }
            }
        }
    }

    hits
}

fn scan_dir_for_faketime(
    dir: &Path,
    root: &Path,
    depth: usize,
    hits: &mut Vec<String>,
    findings: &mut Vec<Finding>,
) {
    if depth == 0 {
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
            scan_dir_for_faketime(&p, root, depth - 1, hits, findings);
        } else if ft.is_file() {
            if let Ok(text) = fs::read_to_string(&p) {
                if contains_faketime_marker(&text) {
                    let label = display_under_root(root, &p);
                    hits.push(label.clone());
                    findings.push(
                        Finding::new(
                            EngineId::TimeFreezeAudit,
                            "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
                            Severity::Critical,
                            &label,
                            format!(
                                "Systemd unit / environment file `{}` injects libfaketime / FAKETIME to freeze service clock",
                                label
                            ),
                        )
                        .with_evidence("unit_file", JsonValue::str(&label)),
                    );
                }
            }
        }
    }
}

fn contains_faketime_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("libfaketime")
        || text.contains("FAKETIME=")
        || text.contains("FAKETIME_NO_CACHE")
        || text.contains("FAKETIME_TIMESTAMP_FILE")
        || text.contains("DONT_FAKE_MONOTONIC")
}

fn scan_ntp_and_rtc_sabotage(
    root: &Path,
    corroborated_by_time_anomaly: bool,
    findings: &mut Vec<Finding>,
) -> usize {
    let mut count = 0usize;

    // 1. Check systemd masked NTP services (`/etc/systemd/system/chronyd.service -> /dev/null`)
    for svc in [
        "chronyd.service",
        "ntpd.service",
        "systemd-timesyncd.service",
        "vmtoolsd.service",
    ] {
        let unit_path = join_rooted(root, &format!("etc/systemd/system/{}", svc));
        let is_masked = if let Ok(link_target) = fs::read_link(&unit_path) {
            link_target == Path::new("/dev/null")
        } else if let Ok(meta) = fs::metadata(&unit_path) {
            meta.is_file() && meta.len() == 0
        } else {
            false
        };

        if is_masked {
            count += 1;
            let sev = if corroborated_by_time_anomaly {
                Severity::Critical
            } else {
                Severity::High
            };
            let code = if corroborated_by_time_anomaly {
                "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE"
            } else {
                "HIGH_NTP_TIME_SYNC_INTENTIONALLY_MASKED"
            };
            findings.push(
                Finding::new(
                    EngineId::TimeFreezeAudit,
                    code,
                    sev,
                    format!("/etc/systemd/system/{}", svc),
                    format!(
                        "Time synchronization service `{}` is explicitly masked to /dev/null to prevent real-time clock correction",
                        svc
                    ),
                )
                .with_evidence("masked_service", JsonValue::str(svc)),
            );
        }
    }

    // 2. Check `/etc/chrony.conf` for stripped upstream NTP servers + `local stratum` freeze
    let chrony_path = join_rooted(root, "etc/chrony.conf");
    if let Ok(chrony_text) = fs::read_to_string(&chrony_path) {
        let mut active_upstreams = 0usize;
        let mut has_local_stratum = false;
        for raw_line in chrony_text.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.starts_with("server ") || line.starts_with("pool ") || line.starts_with("peer ") {
                active_upstreams += 1;
            }
            if line.starts_with("local ") && line.contains("stratum") {
                has_local_stratum = true;
            }
        }
        if active_upstreams == 0 && has_local_stratum {
            count += 1;
            findings.push(
                Finding::new(
                    EngineId::TimeFreezeAudit,
                    "CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE",
                    Severity::Critical,
                    "/etc/chrony.conf",
                    "All upstream NTP servers removed from /etc/chrony.conf with `local stratum` enabled to lock frozen local clock",
                )
                .with_evidence("active_ntp_upstreams", JsonValue::Uint(0))
                .with_evidence("local_stratum_forced", JsonValue::Bool(true)),
            );
        }
    }

    count
}

fn collect_appliance_cert_windows(
    root: &Path,
    extra_cert_files: &[&Path],
) -> Vec<(String, String, Option<i64>, Option<i64>)> {
    let mut candidate_files = Vec::new();
    for &p in extra_cert_files {
        candidate_files.push(p.to_path_buf());
    }

    for rel_dir in ["etc/pki/tls/certs", "etc/nginx", "etc/httpd/conf.d", "opt"] {
        let d = join_rooted(root, rel_dir);
        collect_cert_files_bounded(&d, 4, &mut candidate_files);
    }

    let mut windows = Vec::new();
    for file in candidate_files {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        if !text.contains("-----BEGIN CERTIFICATE-----") {
            continue;
        }
        let label = display_under_root(root, &file);
        for der in extract_pem_certificates(&text) {
            if let Ok(info) = parse_x509_der(&der) {
                // Skip long-lived public Root CAs (`BasicConstraints CA:TRUE`); focus on leaf/appliance/license certs
                if info.basic_constraints_ca {
                    continue;
                }
                let cn = info
                    .subject_cn
                    .unwrap_or_else(|| info.subject_dn.clone());
                windows.push((label.clone(), cn, info.not_before_unix, info.not_after_unix));
            }
        }
    }
    windows
}

fn collect_cert_files_bounded(dir: &Path, depth: usize, out: &mut Vec<std::path::PathBuf>) {
    if depth == 0 {
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
            if name == "ca-trust" || name == "site-packages" || name == "__pycache__" {
                continue;
            }
            collect_cert_files_bounded(&entry.path(), depth - 1, out);
        } else if ft.is_file()
            && (name.ends_with(".crt") || name.ends_with(".pem") || name.ends_with(".cer"))
        {
            // Skip system ca-bundle.crt
            if name.contains("ca-bundle") {
                continue;
            }
            out.push(entry.path());
        }
    }
}

fn sample_filesystem_mtime_bounds(root: &Path) -> (Option<i64>, Option<i64>, Option<String>) {
    let mut earliest: Option<i64> = None;
    let mut latest: Option<i64> = None;
    let mut latest_path: Option<String> = None;

    for rel in [
        "etc/machine-id",
        "etc/hostname",
        "etc/passwd",
        "etc/ssh",
        "var/lib/pgsql",
        "var/log",
        "opt",
    ] {
        let p = join_rooted(root, rel);
        if let Ok(meta) = fs::metadata(&p) {
            if let Ok(mtime) = meta.modified() {
                if let Ok(dur) = mtime.duration_since(UNIX_EPOCH) {
                    let ts = dur.as_secs() as i64;
                    if (PLAUSIBLE_MIN_UNIX..=PLAUSIBLE_MAX_UNIX).contains(&ts) {
                        earliest = Some(earliest.map_or(ts, |c| c.min(ts)));
                        if latest.is_none_or(|c| ts > c) {
                            latest = Some(ts);
                            latest_path = Some(display_under_root(root, &p));
                        }
                    }
                }
            }
        }
    }

    (earliest, latest, latest_path)
}

fn parse_proc_driver_rtc(path: &Path) -> Option<i64> {
    let text = fs::read_to_string(path).ok()?;
    let mut time_hms: Option<(u32, u32, u32)> = None;
    let mut date_ymd: Option<(i32, u32, u32)> = None;

    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim();
        if key == "rtc_time" {
            let parts: Vec<&str> = val.split(':').collect();
            if parts.len() == 3 {
                time_hms = Some((
                    parts[0].parse().ok()?,
                    parts[1].parse().ok()?,
                    parts[2].parse().ok()?,
                ));
            }
        } else if key == "rtc_date" {
            let parts: Vec<&str> = val.split('-').collect();
            if parts.len() == 3 {
                date_ymd = Some((
                    parts[0].parse().ok()?,
                    parts[1].parse().ok()?,
                    parts[2].parse().ok()?,
                ));
            }
        }
    }

    let ((y, mo, d), (h, mi, s)) = (date_ymd?, time_hms?);
    civil_to_unix_utc(y, mo, d, h, mi, s)
}

fn civil_to_unix_utc(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let y = (year as i64) - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i64;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + (day as i64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86_400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64))
}

fn opt_i64_json(v: Option<i64>) -> JsonValue {
    match v {
        Some(n) => JsonValue::Int(n),
        None => JsonValue::Null,
    }
}
