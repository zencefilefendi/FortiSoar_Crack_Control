//! CLI Entrypoint for `fsr-clone-cluster-audit` (Phase 3).

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fsr_clone_cluster_audit::{execute_clone_cluster_audit, CloneClusterAuditConfig};
use fsr_deep_audit::schema::Severity;

fn print_usage() {
    let help = "\
fsr-clone-cluster-audit 1.0.0
Phase-3 Golden Image Clone Detector: PostgreSQL pg_control / EXT4 / XFS Birthmarks,
wtmp & RTC Time-Freeze Auditor, FGVM License Blob Inspector, O(N) Multi-Node Cluster
Correlator, and Active TLS 1.2 / HTTP Management Fingerprinter.

USAGE:
    fsr-clone-cluster-audit [OPTIONS]

STAGE A — SINGLE APPLIANCE / DISK IMAGE BIRTHMARK & LICENSE AUDIT:
    -r, --root <DIR>              Target root filesystem / mounted OVA image (default: `/`)
        --org <LABEL>             Organization / tenant / ASN label for this node's birthmark
        --reference-time <UNIX>   Explicit reference Unix timestamp for offline time-freeze checks
        --fgt-license <FILE>      Inspect FortiGate VM `.lic` file (repeatable)
        --fgt-config <FILE>       Inspect FortiGate VM configuration backup file
        --fgt-hw-status <FILE>    Inspect FortiGate hardware/status dump (`get hardware status` / `.vmx`)

STAGE B — MULTI-ORG / MULTI-NODE CLONE CLUSTERING & ACTIVE PROBING:
        --cluster-input <PATH>    Directory of birthmark JSON reports or Shodan/Censys/TLS NDJSON file
        --scan-targets <LIST>     Comma-separated `ip:port` management endpoints to fingerprint live
        --cluster-only            Skip local `--root` extraction; correlate only `--cluster-input` / `--scan-targets`

GENERAL OPTIONS:
        --include-all-phases      Run Phase-1 + Phase-2 + Phase-3 (all 14 forensic engines)
        --only <LIST>             Engines: birthmark,time,lic,cluster,remote,all (default: all)
    -o, --output <FILE>           Write JSON/NDJSON report to <FILE> instead of stdout
        --pretty                  Pretty-print JSON output (default)
        --compact                 Single-line NDJSON output for SIEM / cluster pipelines
    -h, --help                    Display this help message
    -V, --version                 Display version information

EXIT CODES:
    0   Clean (no CRITICAL/HIGH/MEDIUM findings)
    2   Golden Image clone cluster, pirated FGVM license, or time-freeze tampering detected
    1   CLI / I/O error
";
    let _ = io::stdout().write_all(help.as_bytes());
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut cfg = CloneClusterAuditConfig::default();
    let mut explicit_root_given = false;
    let mut explicit_cluster_only = false;
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
                println!("fsr-clone-cluster-audit {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::from(0);
            }
            "-r" | "--root" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --root requires a directory path");
                    return ExitCode::from(1);
                };
                cfg.root_path = PathBuf::from(val);
                explicit_root_given = true;
            }
            "--org" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --org requires a label");
                    return ExitCode::from(1);
                };
                cfg.org_label = Some(val.clone());
            }
            "--reference-time" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --reference-time requires a Unix epoch integer");
                    return ExitCode::from(1);
                };
                match val.parse::<i64>() {
                    Ok(ts) => cfg.reference_now_unix = Some(ts),
                    Err(_) => {
                        eprintln!("error: invalid integer `{}` for --reference-time", val);
                        return ExitCode::from(1);
                    }
                }
            }
            "--fgt-license" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --fgt-license requires a file path");
                    return ExitCode::from(1);
                };
                cfg.fgt_license_files.push(PathBuf::from(val));
            }
            "--fgt-config" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --fgt-config requires a file path");
                    return ExitCode::from(1);
                };
                cfg.fgt_config_path = Some(PathBuf::from(val));
            }
            "--fgt-hw-status" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --fgt-hw-status requires a file path");
                    return ExitCode::from(1);
                };
                cfg.fgt_hw_status_path = Some(PathBuf::from(val));
            }
            "--cluster-input" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --cluster-input requires a directory or NDJSON file path");
                    return ExitCode::from(1);
                };
                cfg.cluster_input_path = Some(PathBuf::from(val));
            }
            "--scan-targets" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("error: --scan-targets requires comma-separated ip:port targets");
                    return ExitCode::from(1);
                };
                for part in val.split(',') {
                    let t = part.trim();
                    if !t.is_empty() {
                        cfg.scan_targets.push(t.to_string());
                    }
                }
            }
            "--cluster-only" => {
                explicit_cluster_only = true;
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
                cfg.enable_birthmark = false;
                cfg.enable_time_freeze = false;
                cfg.enable_fgvm_license = false;
                cfg.enable_cluster_correlator = false;
                cfg.enable_remote_fingerprinter = false;
                for token in val.split(',').map(|s| s.trim()) {
                    match token {
                        "all" => {
                            cfg.enable_birthmark = true;
                            cfg.enable_time_freeze = true;
                            cfg.enable_fgvm_license = true;
                            cfg.enable_cluster_correlator = true;
                            cfg.enable_remote_fingerprinter = true;
                        }
                        "birthmark" | "birthmark_extractor" => cfg.enable_birthmark = true,
                        "time" | "time_freeze" | "time_freeze_audit" => {
                            cfg.enable_time_freeze = true
                        }
                        "lic" | "fgvm" | "fgvm_license_inspect" => cfg.enable_fgvm_license = true,
                        "cluster" | "cluster_correlator" => cfg.enable_cluster_correlator = true,
                        "remote" | "remote_fingerprinter" => {
                            cfg.enable_remote_fingerprinter = true
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

    // If `--cluster-input` or `--scan-targets` was requested without an explicit `--root`,
    // automatically avoid scanning the analyst host's `/` into the customer cluster.
    if explicit_cluster_only
        || (!explicit_root_given
            && (cfg.cluster_input_path.is_some() || !cfg.scan_targets.is_empty()))
    {
        cfg.audit_local_root = false;
    }

    let report = execute_clone_cluster_audit(&cfg);
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
