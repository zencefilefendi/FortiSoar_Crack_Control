//! CLI Entrypoint for `fsr-qa-fixture-harness`.
//!
//! Usage:
//!   `fsr-qa-fixture-harness --workspace-dir /tmp/fsr_qa_benchmark`
//!   `fsr-qa-fixture-harness --workspace-dir /tmp/fsr_qa_benchmark --json`

use std::env;
use std::path::PathBuf;
use std::process;

use fsr_qa_fixture_harness::{render_benchmark_table, run_qa_benchmark_suite};

const DEFAULT_WORKSPACE_DIR: &str = "/tmp/fsr_qa_benchmark";

fn print_usage(bin_name: &str) {
    eprintln!(
        "Usage: {bin} [OPTIONS]\n\
         \n\
         Builds deterministic, inert forensic test fixtures (`clean_factory_node`,\n\
         `org_alpha_node`, `org_beta_node`), runs the 19-engine `fsr-forensic-verdict`\n\
         command center across all three scenarios, emits HTML/Markdown/JSON reports,\n\
         and self-verifies RFC 6962 Merkle proofs and read-only non-mutation seals.\n\
         \n\
         Options:\n\
         \x20 --workspace-dir <DIR>   Target isolated benchmark directory (default: {def})\n\
         \x20 --json                  Emit structured JSON benchmark report instead of ASCII table\n\
         \x20 -h, --help              Print this help message\n\
         \x20 -V, --version           Print tool version",
        bin = bin_name,
        def = DEFAULT_WORKSPACE_DIR
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let bin_name = args
        .first()
        .map(|s| s.as_str())
        .unwrap_or("fsr-qa-fixture-harness");

    let mut workspace_dir = PathBuf::from(DEFAULT_WORKSPACE_DIR);
    let mut emit_json = false;

    let mut idx = 1usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "-h" | "--help" => {
                print_usage(bin_name);
                process::exit(0);
            }
            "-V" | "--version" => {
                println!("fsr-qa-fixture-harness {}", env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            "--workspace-dir" => {
                idx += 1;
                if idx >= args.len() {
                    eprintln!("error: `--workspace-dir` requires a directory path argument");
                    print_usage(bin_name);
                    process::exit(2);
                }
                workspace_dir = PathBuf::from(&args[idx]);
            }
            arg if arg.starts_with("--workspace-dir=") => {
                let val = &arg["--workspace-dir=".len()..];
                if val.is_empty() {
                    eprintln!("error: `--workspace-dir=` cannot be empty");
                    process::exit(2);
                }
                workspace_dir = PathBuf::from(val);
            }
            "--json" => {
                emit_json = true;
            }
            other => {
                eprintln!("error: unrecognized option `{}`", other);
                print_usage(bin_name);
                process::exit(2);
            }
        }
        idx += 1;
    }

    match run_qa_benchmark_suite(&workspace_dir) {
        Ok(summary) => {
            if emit_json {
                println!("{}", summary.to_json().to_json_string(true));
            } else {
                print!("{}", render_benchmark_table(&summary));
            }
            if summary.all_invariants_passed() {
                process::exit(0);
            } else {
                process::exit(1);
            }
        }
        Err(err) => {
            eprintln!("fatal: QA benchmark suite failed: {}", err);
            process::exit(1);
        }
    }
}
