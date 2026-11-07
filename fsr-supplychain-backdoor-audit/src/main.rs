//! CLI Entrypoint for `fsr-supplychain-backdoor-audit` (Phase 4).

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fsr_deep_audit::schema::Severity;
use fsr_supplychain_backdoor_audit::{
    execute_supplychain_backdoor_audit, SupplyChainAuditConfig,
};

fn print_usage() {
    let help = "\
fsr-supplychain-backdoor-audit 1.0.0
Phase-4 Read-Only Supply-Chain Backdoor & Persistence Hunter:
SOAR Connector Credential Skimmers, Playbook Obfuscation, Nginx Traffic Mirroring,
Django Auth-Bypass Middleware, PostgreSQL Preload/HBA/Trigger Implants, Systemd/PAM
(pam_unix.so ELF64 Prologue)/SSH Persistence, and FortiGate Rogue Super-Admins.

USAGE:
    fsr-supplychain-backdoor-audit [OPTIONS]

OPTIONS:
    -r, --root <DIR>            Target read-only root filesystem / mounted OVA image (default: `/`)
        --fgt-config <FILE>     Audit FortiGate configuration backup for rogue admins & stitch exfil
        --playbook <FILE>       Additional exported Playbook JSON / Jinja2 template file (repeatable)
        --sql-dump <FILE>       Additional PostgreSQL schema / pg_dump `.sql` file (repeatable)
        --include-all-phases    Run Phase-1 + Phase-2 + Phase-3 + Phase-4 (all 19 forensic engines)
        --only <LIST>           Engines: skimmer,web,pg,os,fgt,all (default: all)
    -o, --output <FILE>         Write JSON/NDJSON report to <FILE> instead of stdout
        --pretty                Pretty-print JSON output (default)
        --compact               Single-line NDJSON output for SIEM / SOAR pipelines
    -h, --help                  Display this help message
    -V, --version               Display version information

EXIT CODES:
    0   Clean (no CRITICAL/HIGH/MEDIUM findings)
    2   Supply-chain backdoor, credential skimmer, or persistence implant detected
    1   CLI / I/O error
";
    let _ = io::stdout().write_all(help.as_bytes());
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut cfg = SupplyChainAuditConfig::default();
    let mut output_path: Option<PathBuf> = None;
    let mut pretty = true;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_usage();
                return ExitCode::from(0);
            }
            "-V" | "--version" => {
                println!(
                    "fsr-supplychain-backdoor-audit {}",
                    env!("CARGO_PKG_VERSION")
                );
                return ExitCode::from(0);
            }
            "-r" | "--root" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --root requires a directory path");
                    return ExitCode::from(1);
                };
                cfg.root_path = PathBuf::from(val);
            }
            "--fgt-config" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --fgt-config requires a file path");
                    return ExitCode::from(1);
                };
                cfg.fgt_config_path = Some(PathBuf::from(val));
            }
            "--playbook" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --playbook requires a file path");
                    return ExitCode::from(1);
                };
                cfg.extra_playbook_paths.push(PathBuf::from(val));
            }
            "--sql-dump" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --sql-dump requires a file path");
                    return ExitCode::from(1);
                };
                cfg.extra_sql_dumps.push(PathBuf::from(val));
            }
            "--include-all-phases" => {
                cfg.include_all_phases = true;
            }
            "--only" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --only requires comma-separated engine names");
                    return ExitCode::from(1);
                };
                cfg.enable_connector_skimmer = false;
                cfg.enable_web_auth_backdoor = false;
                cfg.enable_postgres_persistence = false;
                cfg.enable_os_persistence = false;
                cfg.enable_fortigate_backdoor = false;
                for token in val.split(',').map(|s| s.trim()) {
                    match token {
                        "all" => {
                            cfg.enable_connector_skimmer = true;
                            cfg.enable_web_auth_backdoor = true;
                            cfg.enable_postgres_persistence = true;
                            cfg.enable_os_persistence = true;
                            cfg.enable_fortigate_backdoor = true;
                        }
                        "skimmer" | "connector" | "connector_skimmer_audit" => {
                            cfg.enable_connector_skimmer = true
                        }
                        "web" | "django" | "nginx" | "web_auth_backdoor" => {
                            cfg.enable_web_auth_backdoor = true
                        }
                        "pg" | "postgres" | "postgres_persistence" => {
                            cfg.enable_postgres_persistence = true
                        }
                        "os" | "pam" | "systemd" | "os_persistence_audit" => {
                            cfg.enable_os_persistence = true
                        }
                        "fgt" | "fortigate" | "fortigate_backdoor_audit" => {
                            cfg.enable_fortigate_backdoor = true
                        }
                        "" => {}
                        other => {
                            eprintln!("error: unknown engine `{}` in --only", other);
                            return ExitCode::from(1);
                        }
                    }
                }
            }
            "-o" | "--output" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --output requires a file path");
                    return ExitCode::from(1);
                };
                output_path = Some(PathBuf::from(val));
            }
            "--pretty" => pretty = true,
            "--compact" => pretty = false,
            unknown => {
                eprintln!("error: unrecognized argument `{}` (try --help)", unknown);
                return ExitCode::from(1);
            }
        }
        i += 1;
    }

    let report = execute_supplychain_backdoor_audit(&cfg);
    let compromised = report.findings.iter().any(|f| {
        matches!(
            f.severity,
            Severity::Critical | Severity::High | Severity::Medium
        )
    });

    let mut rendered = report.into_canonical_json().to_json_string(pretty);
    rendered.push('\n');

    if let Some(out_file) = output_path {
        if let Err(e) = fs::write(&out_file, rendered.as_bytes()) {
            eprintln!("error: failed writing `{}`: {}", out_file.display(), e);
            return ExitCode::from(1);
        }
    } else if let Err(e) = io::stdout().write_all(rendered.as_bytes()) {
        eprintln!("error: stdout write failed: {}", e);
        return ExitCode::from(1);
    }

    if compromised {
        ExitCode::from(2)
    } else {
        ExitCode::from(0)
    }
}
