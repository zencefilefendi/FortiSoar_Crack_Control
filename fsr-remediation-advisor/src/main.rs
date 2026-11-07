//! Standalone CLI for `fsr-remediation-advisor`.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;

use fsr_remediation_advisor::{
    emit_remediation_plan, generate_remediation_plan, RemediationAdvisorConfig,
    RemediationOutputFormat,
};

fn print_help() {
    println!(
        "\
fsr-remediation-advisor {}
Deterministic DFIR Incident Response, Vault Credential Rotation, Non-Destructive
Network Containment, Clean Playbook Migration & Self-Integrity Advisor.

USAGE:
    fsr-remediation-advisor --bundle <FORENSIC_BUNDLE.JSON> [OPTIONS]

OPTIONS:
    -b, --bundle <FILE>                 Input `ForensicVerdictBundle` JSON envelope
    -r, --root <DIR>                    Mounted read-only appliance root directory (overrides bundle `root_path`)
        --playbook <PATH>               Additional Playbook JSON file or export directory (repeatable)
        --expected-self-sha256 <HEX64>  Expected SHA-256 of the running auditor binary on field USB media
        --check-host-preload            Inspect live `/etc/ld.so.preload` on the executing host
    -f, --format <FMT>                  Output format: `json` (default), `markdown` (`md`), or `html`
        --compact                       Emit single-line NDJSON when `--format json`
    -o, --output <FILE>                 Write remediation plan to `<FILE>` instead of stdout
    -h, --help                          Display this help message
    -V, --version                       Display version information",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut cfg = RemediationAdvisorConfig::default();
    let mut format = RemediationOutputFormat::Json;
    let mut pretty = true;
    let mut output_file: Option<PathBuf> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            "-V" | "--version" => {
                println!("fsr-remediation-advisor {}", env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            "-b" | "--bundle" | "--generate-remediation-plan" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_err("--bundle requires a ForensicVerdictBundle JSON file path");
                };
                cfg.bundle_path = Some(PathBuf::from(v));
            }
            "-r" | "--root" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_err("--root requires a directory path");
                };
                cfg.override_root_path = Some(PathBuf::from(v));
            }
            "--playbook" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_err("--playbook requires a file or directory path");
                };
                cfg.extra_playbook_paths.push(PathBuf::from(v));
            }
            "--expected-self-sha256" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_err("--expected-self-sha256 requires a 64-char hex SHA-256 string");
                };
                cfg.expected_self_sha256 = Some(v.clone());
            }
            "--check-host-preload" => {
                cfg.check_host_ld_so_preload = true;
            }
            "-f" | "--format" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_err("--format requires json, markdown, or html");
                };
                match RemediationOutputFormat::parse_label(v) {
                    Some(fmt) => format = fmt,
                    None => exit_err(&format!(
                        "unsupported --format '{}': expected json, markdown, or html",
                        v
                    )),
                }
            }
            "--compact" => {
                pretty = false;
            }
            "--pretty" => {
                pretty = true;
            }
            "-o" | "--output" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_err("--output requires a destination file path");
                };
                output_file = Some(PathBuf::from(v));
            }
            other => {
                exit_err(&format!("unrecognized option '{}'", other));
            }
        }
        i += 1;
    }

    if cfg.bundle_path.is_none() {
        exit_err("missing required `--bundle <FORENSIC_BUNDLE.JSON>` argument");
    }

    match generate_remediation_plan(&cfg) {
        Ok(plan) => {
            let rendered = emit_remediation_plan(&plan, format, pretty);
            if let Some(path) = output_file {
                if let Err(e) = fs::write(&path, rendered.as_bytes()) {
                    eprintln!(
                        "[fsr-remediation-advisor] failed writing '{}': {}",
                        path.display(),
                        e
                    );
                    process::exit(1);
                }
            } else {
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                let _ = writeln!(handle, "{}", rendered);
            }
            process::exit(0);
        }
        Err(err) => {
            eprintln!("[fsr-remediation-advisor] error: {}", err);
            process::exit(1);
        }
    }
}

fn exit_err(msg: &str) -> ! {
    eprintln!("[fsr-remediation-advisor] CLI error: {}", msg);
    eprintln!("Run `fsr-remediation-advisor --help` for usage instructions.");
    process::exit(1);
}
