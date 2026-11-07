use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fsr_deep_audit::schema::Severity;
use fsr_deep_audit::{execute_full_audit, EngineSelection};

struct CliOptions {
    root: PathBuf,
    output_file: Option<PathBuf>,
    pretty: bool,
    selection: EngineSelection,
}

fn main() -> ExitCode {
    let opts = match parse_cli() {
        Ok(Some(o)) => o,
        Ok(None) => return ExitCode::SUCCESS,
        Err(msg) => {
            let _ = writeln!(io::stderr(), "[fsr-deep-audit] CLI error: {}", msg);
            let _ = writeln!(io::stderr(), "Run `fsr-deep-audit --help` for usage.");
            return ExitCode::from(1);
        }
    };

    let report = execute_full_audit(&opts.root, opts.selection);
    let has_alert = report
        .findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Critical | Severity::High | Severity::Medium));

    let json_ast = report.into_canonical_json();
    let mut rendered = json_ast.to_json_string(opts.pretty);
    rendered.push('\n');

    match opts.output_file {
        Some(path) => {
            if let Err(err) = fs::write(&path, rendered.as_bytes()) {
                let _ = writeln!(
                    io::stderr(),
                    "[fsr-deep-audit] failed to write report to {}: {}",
                    path.display(),
                    err
                );
                return ExitCode::from(1);
            }
        }
        None => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            if let Err(err) = lock.write_all(rendered.as_bytes()) {
                let _ = writeln!(io::stderr(), "[fsr-deep-audit] stdout error: {}", err);
                return ExitCode::from(1);
            }
        }
    }

    if has_alert {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

fn parse_cli() -> Result<Option<CliOptions>, String> {
    let mut root = PathBuf::from("/");
    let mut output_file = None;
    let mut pretty = true;
    let mut selection = EngineSelection::default();

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("fsr-deep-audit {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "--root" | "-r" => {
                let val = args
                    .next()
                    .ok_or_else(|| "missing path argument after --root".to_string())?;
                root = PathBuf::from(val);
            }
            "--output" | "-o" => {
                let val = args
                    .next()
                    .ok_or_else(|| "missing file path after --output".to_string())?;
                output_file = Some(PathBuf::from(val));
            }
            "--compact" => pretty = false,
            "--pretty" => pretty = true,
            "--only" => {
                let val = args
                    .next()
                    .ok_or_else(|| "missing comma-separated engine list after --only".to_string())?;
                selection = parse_engine_list(&val)?;
            }
            unknown => return Err(format!("unrecognized argument `{}`", unknown)),
        }
    }

    Ok(Some(CliOptions {
        root,
        output_file,
        pretty,
        selection,
    }))
}

fn parse_engine_list(spec: &str) -> Result<EngineSelection, String> {
    let mut sel = EngineSelection {
        hw_integrity: false,
        elf_vma_diff: false,
        pyc_inspector: false,
        rpm_forensics: false,
    };

    for item in spec.split(',') {
        match item.trim() {
            "all" => return Ok(EngineSelection::default()),
            "hw" | "hw_integrity" => sel.hw_integrity = true,
            "elf" | "elf_vma_diff" => sel.elf_vma_diff = true,
            "pyc" | "pyc_inspector" => sel.pyc_inspector = true,
            "rpm" | "rpm_forensics" => sel.rpm_forensics = true,
            "" => {}
            other => {
                return Err(format!(
                    "unknown engine `{}` (valid: hw, elf, pyc, rpm, all)",
                    other
                ))
            }
        }
    }

    if !sel.hw_integrity && !sel.elf_vma_diff && !sel.pyc_inspector && !sel.rpm_forensics {
        return Err("at least one engine must be enabled in --only".to_string());
    }

    Ok(sel)
}

fn print_help() {
    println!(
        "\
fsr-deep-audit {ver}
Forensic anti-cracking, raw-syscall hardware spoof, ELF64 VMA diff, PEP 552 bytecode,
and RPM database integrity auditor for RHEL/Rocky Linux 8/9 (x86_64) FortiSOAR appliances.

USAGE:
    fsr-deep-audit [OPTIONS]

OPTIONS:
    -r, --root <DIR>       Target appliance root filesystem (default: `/`)
    -o, --output <FILE>    Write deterministic JSON report to <FILE> instead of stdout
        --pretty           Pretty-print JSON output with 2-space indentation (default)
        --compact          Emit single-line compact JSON (SIEM / NDJSON pipeline mode)
        --only <LIST>      Comma-separated engines: hw,elf,pyc,rpm,all (default: all)
    -h, --help             Display this help message
    -V, --version          Display version information

EXIT CODES:
    0   Clean (no CRITICAL/HIGH/MEDIUM tampering findings)
    2   Compromised or anomalous forensic findings detected
    1   Execution / CLI error",
        ver = env!("CARGO_PKG_VERSION")
    );
}
