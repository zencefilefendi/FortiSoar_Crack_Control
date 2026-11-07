//! Engine 3: PostgreSQL Database Persistence, Preload Library & HBA Backdoor Auditor.
//!
//! Performs read-only inspection of PostgreSQL configuration, host-based authentication,
//! and SQL schema/dump artifacts across `/var/lib/pgsql/**/data/`, `/var/lib/postgresql/**`,
//! and `/opt/cyops*/**/*.sql`:
//!   a) `shared_preload_libraries`, `local_preload_libraries`, `session_preload_libraries`,
//!      and tampered `dynamic_library_path` (`CRITICAL_PG_PRELOAD_LIBRARY_IMPLANT`),
//!   b) `archive_command`, `restore_command`, `ssl_passphrase_command` shell/network/tmp
//!      implants in `postgresql.conf` and `postgresql.auto.conf` (`CRITICAL_PG_COMMAND_EXECUTION_HOOK`),
//!   c) `pg_hba.conf` network `trust` authentication rules on `0.0.0.0/0`, `::/0`, or `all`
//!      (`CRITICAL_PG_HBA_TRUST_BACKDOOR`),
//!   d) Untrusted procedural languages (`plperlu`, `plpythonu`, `plpython3u`, `plsh`),
//!      rogue `LANGUAGE C` shared-object functions, `COPY ... PROGRAM`, and credential-table
//!      `CREATE TRIGGER` implants.

use std::fs;
use std::path::{Path, PathBuf};

use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};

use crate::connector_skimmer_audit::{collect_files_with_exts, display_under_root, join_rooted};

/// Legitimate PostgreSQL contrib preload modules seen on RHEL/Rocky FortiSOAR deployments.
const ALLOWED_PG_PRELOAD_LIBS: &[&str] = &[
    "pg_stat_statements",
    "pgaudit",
    "auto_explain",
    "auth_delay",
    "passwordcheck",
    "pg_cron",
    "timescaledb",
    "pgcrypto",
    "plpgsql",
];

/// Sensitive FortiSOAR / Django authentication & vault tables targeted by SQL trigger skimmers.
const SENSITIVE_AUTH_VAULT_TABLES: &[&str] = &[
    "auth_user",
    "users",
    "cs_user",
    "sealab_user",
    "user_profile",
    "credentials",
    "credential",
    "vault",
    "secret",
    "connector",
    "config",
    "apikey",
    "api_key",
    "accesstoken",
    "token",
];

/// Output of Engine 3 (`postgres_persistence`).
pub struct PostgresPersistenceResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 3 across PostgreSQL data directories and SQL schema/dump files.
pub fn run_postgres_persistence_audit(
    root: &Path,
    extra_sql_dumps: &[PathBuf],
) -> PostgresPersistenceResult {
    let mut findings = Vec::new();
    let mut pg_confs_scanned = 0u64;
    let mut pg_hbas_scanned = 0u64;
    let mut sql_files_scanned = 0u64;

    // 1. Discover `postgresql.conf`, `postgresql.auto.conf`, and `pg_hba.conf`
    let mut conf_files = Vec::new();
    let mut hba_files = Vec::new();
    for rel in ["var/lib/pgsql", "var/lib/postgresql", "etc/postgresql"] {
        let dir = join_rooted(root, rel);
        if dir.is_dir() {
            discover_pg_config_files(&dir, 6, &mut conf_files, &mut hba_files);
        }
    }
    conf_files.sort();
    conf_files.dedup();
    hba_files.sort();
    hba_files.dedup();

    for cf in &conf_files {
        if let Ok(text) = fs::read_to_string(cf) {
            pg_confs_scanned += 1;
            let rel_label = display_under_root(root, cf);
            audit_postgresql_conf(&rel_label, &text, &mut findings);
        }
    }

    for hf in &hba_files {
        if let Ok(text) = fs::read_to_string(hf) {
            pg_hbas_scanned += 1;
            let rel_label = display_under_root(root, hf);
            audit_pg_hba_conf(&rel_label, &text, &mut findings);
        }
    }

    // 2. Scan SQL dump / schema / catalog script files
    let mut sql_files: Vec<PathBuf> = extra_sql_dumps.to_vec();
    for rel in ["var/lib/pgsql", "var/lib/postgresql", "var/backups", "opt"] {
        let dir = join_rooted(root, rel);
        if dir.is_dir() {
            collect_files_with_exts(&dir, &["sql", "psql", "dump"], 6, &mut sql_files);
        }
    }
    sql_files.sort();
    sql_files.dedup();

    for sf in &sql_files {
        // Skip official `/usr/pgsql-*/share/extension` system SQL scripts if ever under `opt`; limit to <= 8 MiB
        let Ok(meta) = fs::metadata(sf) else {
            continue;
        };
        if meta.len() > 8 * 1024 * 1024 {
            continue;
        }
        if let Ok(text) = fs::read_to_string(sf) {
            sql_files_scanned += 1;
            let rel_label = display_under_root(root, sf);
            audit_sql_persistence_and_triggers(&rel_label, &text, &mut findings);
        }
    }

    let summary = JsonValue::OrderedObject(vec![
        (
            "postgresql_confs_scanned".to_string(),
            JsonValue::Uint(pg_confs_scanned),
        ),
        (
            "pg_hba_confs_scanned".to_string(),
            JsonValue::Uint(pg_hbas_scanned),
        ),
        (
            "sql_schema_and_dumps_scanned".to_string(),
            JsonValue::Uint(sql_files_scanned),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    PostgresPersistenceResult { summary, findings }
}

/// Audits `postgresql.conf` / `postgresql.auto.conf` for preload `.so` implants and command hooks.
pub fn audit_postgresql_conf(file_label: &str, content: &str, findings: &mut Vec<Finding>) {
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let clean = strip_pg_comment(raw_line).trim();
        if clean.is_empty() {
            continue;
        }

        let Some((key, val)) = parse_pg_conf_kv(clean) else {
            continue;
        };
        let key_low = key.to_ascii_lowercase();

        // 3a. Preload shared library implants
        if matches!(
            key_low.as_str(),
            "shared_preload_libraries" | "local_preload_libraries" | "session_preload_libraries"
        ) && !val.is_empty()
        {
            for item in val.split(',') {
                let lib = item.trim().trim_matches('\'').trim_matches('"').trim();
                if lib.is_empty() {
                    continue;
                }
                let base_no_so = lib.strip_suffix(".so").unwrap_or(lib);
                let has_path_sep = lib.contains('/') || lib.contains("..");
                let is_allowed = !has_path_sep && ALLOWED_PG_PRELOAD_LIBS.contains(&base_no_so);

                if !is_allowed {
                    findings.push(
                        Finding::new(
                            EngineId::PostgresPersistence,
                            "CRITICAL_PG_PRELOAD_LIBRARY_IMPLANT",
                            Severity::Critical,
                            format!("{}:{}", file_label, line_no),
                            format!(
                                "Unauthorized shared library `{}` configured in PostgreSQL `{}` ({}:{})",
                                lib, key_low, file_label, line_no
                            ),
                        )
                        .with_evidence("file", JsonValue::str(file_label))
                        .with_evidence("line", JsonValue::Uint(line_no as u64))
                        .with_evidence("parameter", JsonValue::str(&key_low))
                        .with_evidence("library", JsonValue::str(lib)),
                    );
                }
            }
        }

        if key_low == "dynamic_library_path" && !val.is_empty() {
            let suspicious_dir = val.contains("/tmp")
                || val.contains("/var/tmp")
                || val.contains("/dev/shm")
                || val.contains("/.");
            if suspicious_dir {
                findings.push(
                    Finding::new(
                        EngineId::PostgresPersistence,
                        "CRITICAL_PG_PRELOAD_LIBRARY_IMPLANT",
                        Severity::Critical,
                        format!("{}:{}", file_label, line_no),
                        format!(
                            "PostgreSQL `dynamic_library_path` includes world-writable/hidden directory `{}` ({}:{})",
                            val, file_label, line_no
                        ),
                    )
                    .with_evidence("file", JsonValue::str(file_label))
                    .with_evidence("line", JsonValue::Uint(line_no as u64))
                    .with_evidence("dynamic_library_path", JsonValue::str(&val)),
                );
            }
        }

        // 3b. OS command execution hooks (`archive_command`, `restore_command`, `ssl_passphrase_command`)
        if matches!(
            key_low.as_str(),
            "archive_command"
                | "restore_command"
                | "archive_cleanup_command"
                | "recovery_end_command"
                | "ssl_passphrase_command"
        ) && !val.is_empty()
            && val != "/bin/true"
            && val != "true"
            && val != ":"
        {
            if let Some(reason) = detect_suspicious_pg_shell_hook(&val) {
                findings.push(
                    Finding::new(
                        EngineId::PostgresPersistence,
                        "CRITICAL_PG_COMMAND_EXECUTION_HOOK",
                        Severity::Critical,
                        format!("{}:{}", file_label, line_no),
                        format!(
                            "PostgreSQL `{}` executes suspicious shell/network command ({}) in {}:{}",
                            key_low, reason, file_label, line_no
                        ),
                    )
                    .with_evidence("file", JsonValue::str(file_label))
                    .with_evidence("line", JsonValue::Uint(line_no as u64))
                    .with_evidence("parameter", JsonValue::str(&key_low))
                    .with_evidence("command", JsonValue::str(&val))
                    .with_evidence("reason", JsonValue::str(reason)),
                );
            }
        }
    }
}

/// Audits `pg_hba.conf` for external/wildcard `trust` (passwordless) backdoors.
pub fn audit_pg_hba_conf(file_label: &str, content: &str, findings: &mut Vec<Finding>) {
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let clean = strip_pg_comment(raw_line).trim();
        if clean.is_empty() {
            continue;
        }

        let cols: Vec<&str> = clean.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let conn_type = cols[0].to_ascii_lowercase();
        if !conn_type.starts_with("host") {
            continue;
        }

        // Standard `host db user address method` (5 cols) OR `host db user addr netmask method` (6 cols)
        let (addr_spec, auth_method) = if cols.len() >= 6 && is_netmask_token(cols[4]) {
            (format!("{}/{}", cols[3], cols[4]), cols[5].to_ascii_lowercase())
        } else if cols.len() >= 5 {
            (cols[3].to_string(), cols[4].to_ascii_lowercase())
        } else {
            continue;
        };

        if auth_method != "trust" {
            continue;
        }

        let addr_low = addr_spec.to_ascii_lowercase();
        let is_loopback = addr_low.starts_with("127.")
            || addr_low == "::1/128"
            || addr_low == "localhost";

        if !is_loopback {
            findings.push(
                Finding::new(
                    EngineId::PostgresPersistence,
                    "CRITICAL_PG_HBA_TRUST_BACKDOOR",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!(
                        "PostgreSQL pg_hba.conf grants passwordless `trust` authentication to non-loopback network `{}` (user=`{}`, db=`{}`)",
                        addr_spec, cols[2], cols[1]
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("line", JsonValue::Uint(line_no as u64))
                .with_evidence("connection_type", JsonValue::str(&conn_type))
                .with_evidence("database", JsonValue::str(cols[1]))
                .with_evidence("user", JsonValue::str(cols[2]))
                .with_evidence("address", JsonValue::str(&addr_spec))
                .with_evidence("auth_method", JsonValue::str("trust")),
            );
        }
    }
}

/// Scans SQL dumps/schemas for untrusted procedural languages (`plpython3u`, `plperlu`, `plsh`),
/// external `LANGUAGE C` shared-object functions, `COPY ... PROGRAM`, and auth/vault triggers.
pub fn audit_sql_persistence_and_triggers(
    file_label: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    // Process semicolon-delimited SQL statements while tracking starting line numbers
    let mut stmt_buf = String::new();
    let mut stmt_line = 1usize;

    for (idx, raw_line) in content.lines().enumerate() {
        let code = raw_line.split("--").next().unwrap_or("").trim();
        if code.is_empty() {
            continue;
        }
        if stmt_buf.is_empty() {
            stmt_line = idx + 1;
        } else {
            stmt_buf.push(' ');
        }
        stmt_buf.push_str(code);

        if code.ends_with(';') {
            inspect_single_sql_statement(file_label, stmt_line, &stmt_buf, findings);
            stmt_buf.clear();
        }
    }
    if !stmt_buf.is_empty() {
        inspect_single_sql_statement(file_label, stmt_line, &stmt_buf, findings);
    }
}

fn inspect_single_sql_statement(
    file_label: &str,
    line_no: usize,
    stmt: &str,
    findings: &mut Vec<Finding>,
) {
    let lower = stmt.to_ascii_lowercase();

    // 1. Untrusted procedural languages (`plperlu`, `plpythonu`, `plpython2u`, `plpython3u`, `pltclu`, `plsh`)
    for lang in [
        "plperlu",
        "plpythonu",
        "plpython2u",
        "plpython3u",
        "pltclu",
        "plsh",
    ] {
        if lower.contains(&format!("language {}", lang))
            || lower.contains(&format!("language '{}'", lang))
            || lower.contains(&format!("extension {}", lang))
            || lower.contains(&format!("extension if not exists {}", lang))
        {
            findings.push(
                Finding::new(
                    EngineId::PostgresPersistence,
                    "CRITICAL_PG_UNTRUSTED_LANGUAGE_OR_TRIGGER_IMPLANT",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!(
                        "Untrusted PostgreSQL OS-execution procedural language `{}` enabled/used in {}:{}",
                        lang, file_label, line_no
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("line", JsonValue::Uint(line_no as u64))
                .with_evidence("language", JsonValue::str(lang))
                .with_evidence("sql_preview", JsonValue::str(truncate_sql(stmt))),
            );
            return;
        }
    }

    // 2. External `LANGUAGE C` user-defined shared-object functions (`AS '/path/...'`)
    if (lower.contains("create function") || lower.contains("create or replace function"))
        && (lower.contains("language c") || lower.contains("language 'c'"))
        && !lower.contains("$libdir/")
    {
        findings.push(
            Finding::new(
                EngineId::PostgresPersistence,
                "CRITICAL_PG_UNTRUSTED_LANGUAGE_OR_TRIGGER_IMPLANT",
                Severity::Critical,
                format!("{}:{}", file_label, line_no),
                format!(
                    "External `LANGUAGE C` shared-object SQL function outside `$libdir` in {}:{}",
                    file_label, line_no
                ),
            )
            .with_evidence("file", JsonValue::str(file_label))
            .with_evidence("line", JsonValue::Uint(line_no as u64))
            .with_evidence("sql_preview", JsonValue::str(truncate_sql(stmt))),
        );
        return;
    }

    // 3. `COPY ... FROM PROGRAM` / `COPY ... TO PROGRAM` OS command execution
    if lower.contains("copy ") && (lower.contains(" from program ") || lower.contains(" to program "))
    {
        findings.push(
            Finding::new(
                EngineId::PostgresPersistence,
                "CRITICAL_PG_COMMAND_EXECUTION_HOOK",
                Severity::Critical,
                format!("{}:{}", file_label, line_no),
                format!(
                    "PostgreSQL `COPY ... PROGRAM` shell command execution statement in {}:{}",
                    file_label, line_no
                ),
            )
            .with_evidence("file", JsonValue::str(file_label))
            .with_evidence("line", JsonValue::Uint(line_no as u64))
            .with_evidence("sql_preview", JsonValue::str(truncate_sql(stmt))),
        );
        return;
    }

    // 4. `CREATE TRIGGER` on authentication / credential / vault tables
    if lower.contains("create trigger") || lower.contains("create constraint trigger") {
        if let Some(tbl) = SENSITIVE_AUTH_VAULT_TABLES
            .iter()
            .find(|&&t| lower.contains(&format!(" on {}", t)) || lower.contains(&format!(".{}", t)))
        {
            findings.push(
                Finding::new(
                    EngineId::PostgresPersistence,
                    "CRITICAL_PG_UNTRUSTED_LANGUAGE_OR_TRIGGER_IMPLANT",
                    Severity::Critical,
                    format!("{}:{}", file_label, line_no),
                    format!(
                        "Database trigger attached to sensitive authentication/vault table `{}` in {}:{}",
                        tbl, file_label, line_no
                    ),
                )
                .with_evidence("file", JsonValue::str(file_label))
                .with_evidence("line", JsonValue::Uint(line_no as u64))
                .with_evidence("target_table", JsonValue::str(*tbl))
                .with_evidence("sql_preview", JsonValue::str(truncate_sql(stmt))),
            );
        }
    }
}

fn detect_suspicious_pg_shell_hook(cmd: &str) -> Option<&'static str> {
    let lower = cmd.to_ascii_lowercase();
    for (needle, reason) in [
        ("/dev/tcp/", "bash /dev/tcp reverse shell"),
        ("nc ", "netcat socket command"),
        ("ncat ", "ncat socket command"),
        ("netcat ", "netcat socket command"),
        ("socat ", "socat relay"),
        ("mkfifo", "named-pipe reverse shell"),
        ("curl ", "outbound curl HTTP transfer"),
        ("wget ", "outbound wget HTTP transfer"),
        ("python", "inline Python interpreter invocation"),
        ("perl ", "inline Perl interpreter invocation"),
        ("bash -c", "inline bash -c execution"),
        ("bash -i", "interactive bash reverse shell"),
        ("sh -i", "interactive sh reverse shell"),
        ("base64", "encoded command execution"),
        ("/tmp/", "execution/staging under /tmp"),
        ("/var/tmp/", "execution/staging under /var/tmp"),
        ("/dev/shm/", "execution/staging under /dev/shm"),
    ] {
        if lower.contains(needle) {
            return Some(reason);
        }
    }
    None
}

fn parse_pg_conf_kv(line: &str) -> Option<(String, String)> {
    if let Some((k, v)) = line.split_once('=') {
        let key = k.trim().to_string();
        let val = v.trim().trim_matches('\'').trim_matches('"').trim().to_string();
        if !key.is_empty() {
            return Some((key, val));
        }
    }
    let mut parts = line.splitn(2, char::is_whitespace);
    let key = parts.next()?.trim().to_string();
    let val = parts
        .next()?
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .trim()
        .to_string();
    Some((key, val))
}

fn is_netmask_token(tok: &str) -> bool {
    tok.split('.').count() == 4 && tok.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

fn strip_pg_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_sq = false;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\'' {
            in_sq = !in_sq;
        } else if b == b'#' && !in_sq {
            return &line[..i];
        }
    }
    line
}

fn truncate_sql(s: &str) -> String {
    let t = s.trim();
    if t.chars().count() <= 180 {
        t.to_string()
    } else {
        let mut out: String = t.chars().take(180).collect();
        out.push_str("...");
        out
    }
}

fn discover_pg_config_files(
    dir: &Path,
    depth: usize,
    confs: &mut Vec<PathBuf>,
    hbas: &mut Vec<PathBuf>,
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
        let name = entry.file_name().to_string_lossy().into_owned();
        if ft.is_dir() {
            if name == "base" || name == "pg_wal" || name == "pg_xlog" {
                continue;
            }
            discover_pg_config_files(&entry.path(), depth - 1, confs, hbas);
        } else if ft.is_file() {
            if name == "postgresql.conf" || name == "postgresql.auto.conf" {
                confs.push(entry.path());
            } else if name == "pg_hba.conf" {
                hbas.push(entry.path());
            }
        }
    }
}
