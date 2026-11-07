//! Standalone CLI Entrypoint for `fsr-ova-attribution` (Phase 8).

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fsr_deep_audit::schema::Severity;
use fsr_ova_attribution::{execute_ova_attribution_suite, OvaAttributionConfig};

fn print_help() {
    println!(
        "\
fsr-ova-attribution {}
Phase-8 Zero-Mount OVA/OVF/VMDK/QCOW2 Forensics & Crack-Kit DNA Attribution Engine:
Inspects `.ova` POSIX ustar archives and `.vmdk` extents in userspace without `mount` or
`root`, verifies `.mf` SHA-1/SHA-256 manifests, carves `pg_control` / EXT4 / XFS / X.509 /
ELF64 artifacts, and attributes multi-org cracks via deterministic `CKIT-SHA256-...` DNA.

USAGE:
    fsr-ova-attribution [OPTIONS]

OPTIONS:
        --ova, --inspect-ova <FILE.ova>   Zero-mount userspace inspection of `.ova` / `.vmdk` / `.qcow2`
    -r, --root <DIR>                      Mounted or unpacked appliance root directory
        --attribute-cracker, --attribute-kit
                                          Synthesize Crack-Kit DNA (`CKIT-SHA256-...`) & correlate peers
        --org-label <NAME>                Institution / tenant label for attribution clustering
        --cluster-input <PATH>            Peer JSON/NDJSON bundles, `.ova` files, or root dirs
        --spki-pin <HEX64>                Additional trusted Fortinet SPKI SHA-256 pin (repeatable)
    -o, --output <FILE>                   Write JSON/NDJSON report to <FILE> instead of stdout
        --pretty                          Pretty-print JSON output (default)
        --compact                         Single-line NDJSON output
    -h, --help                            Display this help message
    -V, --version                         Display version information",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        return ExitCode::from(1);
    }

    let mut cfg = OvaAttributionConfig::default();
    let mut pretty = true;
    let mut output_file: Option<PathBuf> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("fsr-ova-attribution {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--ova" | "--inspect-ova" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("[fsr-ova-attribution] error: --ova requires a file path");
                    return ExitCode::from(1);
                };
                cfg.ova_path = Some(PathBuf::from(v));
            }
            "-r" | "--root" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("[fsr-ova-attribution] error: --root requires a directory path");
                    return ExitCode::from(1);
                };
                cfg.root_path = Some(PathBuf::from(v));
            }
            "--attribute-cracker" | "--attribute-kit" => {
                cfg.attribute_cracker = true;
            }
            "--org-label" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("[fsr-ova-attribution] error: --org-label requires a name");
                    return ExitCode::from(1);
                };
                cfg.org_label = Some(v.clone());
            }
            "--cluster-input" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("[fsr-ova-attribution] error: --cluster-input requires a path");
                    return ExitCode::from(1);
                };
                cfg.cluster_input_path = Some(PathBuf::from(v));
            }
            "--spki-pin" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("[fsr-ova-attribution] error: --spki-pin requires a hex string");
                    return ExitCode::from(1);
                };
                cfg.extra_fortinet_spkis.push(v.clone());
            }
            "-o" | "--output" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("[fsr-ova-attribution] error: --output requires a file path");
                    return ExitCode::from(1);
                };
                output_file = Some(PathBuf::from(v));
            }
            "--pretty" => pretty = true,
            "--compact" => pretty = false,
            other => {
                eprintln!("[fsr-ova-attribution] error: unrecognized option `{}`", other);
                return ExitCode::from(1);
            }
        }
        i += 1;
    }

    if cfg.ova_path.is_none() && cfg.root_path.is_none() {
        eprintln!("[fsr-ova-attribution] error: supply `--ova <file.ova>` and/or `--root <dir>`");
        return ExitCode::from(1);
    }

    match execute_ova_attribution_suite(&cfg, None) {
        Ok(report) => {
            let has_breach = report.findings.iter().any(|f| {
                matches!(
                    f.severity,
                    Severity::Critical | Severity::High | Severity::Medium
                )
            });
            let rendered = report.into_canonical_json().to_json_string(pretty);
            if let Some(out_path) = output_file {
                if let Err(e) = fs::write(&out_path, rendered.as_bytes()) {
                    eprintln!(
                        "[fsr-ova-attribution] error writing `{}`: {}",
                        out_path.display(),
                        e
                    );
                    return ExitCode::from(1);
                }
            } else {
                let _ = writeln!(io::stdout().lock(), "{}", rendered);
            }
            if has_breach {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => {
            eprintln!("[fsr-ova-attribution] inspection error: {}", err);
            ExitCode::from(1)
        }
    }
}
