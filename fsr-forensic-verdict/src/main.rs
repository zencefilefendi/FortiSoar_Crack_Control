//! Unified Command-Line Interface for `fsr-forensic-verdict` (Phase 5 DFIR Command Center).

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

use fsr_forensic_verdict::bundle_verifier::verify_forensic_bundle_file;
use fsr_forensic_verdict::fsr_remediation_advisor::self_integrity::run_startup_self_integrity_guard;
use fsr_forensic_verdict::fsr_remediation_advisor::{
    emit_remediation_plan, generate_remediation_plan, RemediationAdvisorConfig,
    RemediationOutputFormat,
};
use fsr_forensic_verdict::portal_server::{build_quick_check_config, run_portal_server};
use fsr_forensic_verdict::report_emitter::{
    emit_forensic_report, render_denetim_kabul_tutanagi_html,
    summarize_instant_enterprise_checks, OutputFormat,
};
use fsr_forensic_verdict::{execute_forensic_verdict_command_center, ForensicVerdictConfig};

fn print_help() {
    println!(
        "\
fsr-forensic-verdict {}
Phase-5–8 Unified DFIR Command Center & Cryptographic Evidence Sealer:
Orchestrates 19 Core Host/Disk Forensic Engines (Phases 1-4) + 3 Zero-Mount OVA/Crack-Kit
Attribution Engines (Phase-8, 22 modules total), generates Read-Only Non-Mutation Attestation,
seals findings in an RFC 6962 Binary Merkle Tree, classifies Causal Technical Verdicts,
emits JSON/NDJSON/Markdown/HTML/Denetim-Tutanağı reports, runs a Zero-Dependency Local Web
Inspection Portal, and verifies bundles offline.

USAGE:
    fsr-forensic-verdict --quick-check [DIR_OR_OVA_FILE]
    fsr-forensic-verdict --serve <HOST:PORT> [--root <DIR>]
    fsr-forensic-verdict [OPTIONS]
    fsr-forensic-verdict --verify-bundle <FORENSIC_BUNDLE.JSON>
    fsr-forensic-verdict --generate-remediation-plan <FORENSIC_BUNDLE.JSON> [OPTIONS]

ZERO-FRICTION ENTERPRISE & INSTANT VERIFICATION OPTIONS:
        --quick-check [PATH]      One-command auto-detecting audit (directory, `/opt/cyops-auth`, or `.ova`)
                                  with Crack-Kit DNA attribution and automatic Denetim Tutanağı output
        --serve <HOST:PORT>       Start zero-dependency local Web Inspection Portal (e.g. `127.0.0.1:8090`)
        --serve-once              Serve a single HTTP request on `--serve` and exit cleanly

AUDIT & ORCHESTRATION OPTIONS:
    -r, --root <DIR>              Target read-only root filesystem / mounted OVA image (default: `/`)
        --baseline <FILE.json>    Version-tagged structural baseline manifest (e.g. `baselines/fortisoar-7.6.x.json`)
        --ova, --inspect-ova <FILE.ova>
                                  Zero-mount userspace POSIX ustar OVA/OVF & VMDK signature carving
        --attribute-cracker, --attribute-kit
                                  Synthesize Crack-Kit DNA (`CKIT-SHA256-...`) & attribute cracker group
        --live                    Enable active live kernel/DNS/TLS probing in Phase-2
        --org-label <NAME>        Organization / institution tag for multi-node clone correlation
        --reference-now <UNIX>    Trusted analyst UTC reference epoch seconds for clock-freeze checks
        --fgt-config <FILE>       FortiGate configuration backup file (`show full-configuration`)
        --fgt-rating <FILE>       FortiGate `diagnose debug rating` output file
        --fgt-hw-status <FILE>    FortiGate `get hardware status` output file
        --fgt-lic <FILE>          FortiGate VM `.lic` license file (repeatable)
        --spki-pin <HEX64>        Additional trusted Fortinet SPKI SHA-256 pin (repeatable)
        --cluster-input <PATH>    Directory or `.json`/`.ndjson` telemetry for clone cluster matching
        --scan-target <HOST:PORT> Active TLS/HTTP management fingerprint target (repeatable)
        --playbook <FILE>         Additional exported SOAR Playbook / Jinja2 file (repeatable)
        --sql-dump <FILE>         Additional PostgreSQL schema / `pg_dump` `.sql` file (repeatable)
        --expected-self-sha256 <HEX64> Expected `/proc/self/exe` SHA-256 for field USB self-integrity

OUTPUT, VERIFICATION & REMEDIATION OPTIONS:
    -f, --format <FMT>            Output format: `json` (default), `markdown` (`md`), `html`,
                                  or `denetim-tutanagi` (`acceptance-report`)
        --pretty                  Pretty-print JSON output (default for `--format json`)
        --compact                 Single-line NDJSON output (for `--format json` SIEM pipelines)
    -o, --output <FILE>           Write report or verification output to <FILE> instead of stdout
        --verify-bundle <FILE>    Verify `<FILE>` offline (RFC 6962 Merkle proofs + Non-Mutation digest)
        --generate-remediation-plan <FILE> Generate deterministic IR, Vault Re-Keying & Clean Migration Plan from `<FILE>`
    -h, --help                    Display this help message
    -V, --version                 Display version information

EXIT CODES:
    0   Clean audit (0 findings) OR `--verify-bundle` cryptographically authentic
    2   Compromised / cracked / backdoored appliance detected during audit
    3   `--verify-bundle` detected tampered finding, broken Merkle proof, or mutated target
    1   CLI argument or I/O error",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut cfg = ForensicVerdictConfig::default();
    let mut explicit_root = false;
    let mut format = OutputFormat::Json;
    let mut pretty = true;
    let mut output_file: Option<PathBuf> = None;
    let mut verify_bundle_path: Option<PathBuf> = None;
    let mut remediation_bundle_path: Option<PathBuf> = None;
    let mut quick_check_mode = false;
    let mut serve_addr: Option<String> = None;
    let mut serve_once = false;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            "-V" | "--version" => {
                println!("fsr-forensic-verdict {}", env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            "-r" | "--root" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--root requires a directory path");
                };
                cfg.root_path = PathBuf::from(v);
                explicit_root = true;
            }
            "--baseline" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--baseline requires a JSON manifest file path");
                };
                cfg.baseline_manifest_path = Some(PathBuf::from(v));
            }
            "--live" => {
                cfg.live_mode = true;
            }
            "--org-label" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--org-label requires a value");
                };
                cfg.org_label = Some(v.clone());
            }
            "--reference-now" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--reference-now requires a Unix timestamp");
                };
                match v.parse::<i64>() {
                    Ok(ts) => cfg.reference_now_unix = Some(ts),
                    Err(_) => exit_cli_err("invalid integer passed to --reference-now"),
                }
            }
            "--fgt-config" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--fgt-config requires a file path");
                };
                cfg.fgt_config_path = Some(PathBuf::from(v));
            }
            "--fgt-rating" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--fgt-rating requires a file path");
                };
                cfg.fgt_rating_path = Some(PathBuf::from(v));
            }
            "--fgt-hw-status" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--fgt-hw-status requires a file path");
                };
                cfg.fgt_hw_status_path = Some(PathBuf::from(v));
            }
            "--fgt-lic" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--fgt-lic requires a file path");
                };
                cfg.fgt_license_files.push(PathBuf::from(v));
            }
            "--spki-pin" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--spki-pin requires a 64-char hex string");
                };
                cfg.extra_fortinet_spkis.push(v.clone());
            }
            "--cluster-input" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--cluster-input requires a path");
                };
                cfg.cluster_input_path = Some(PathBuf::from(v));
            }
            "--scan-target" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--scan-target requires HOST:PORT");
                };
                cfg.scan_targets.push(v.clone());
            }
            "--playbook" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--playbook requires a file path");
                };
                cfg.extra_playbook_paths.push(PathBuf::from(v));
            }
            "--sql-dump" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--sql-dump requires a file path");
                };
                cfg.extra_sql_dumps.push(PathBuf::from(v));
            }
            "-f" | "--format" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--format requires `json`, `markdown`, or `html`");
                };
                match OutputFormat::parse_label(v) {
                    Some(fmt) => format = fmt,
                    None => exit_cli_err(&format!(
                        "unsupported --format '{}': expected json, markdown, or html",
                        v
                    )),
                }
            }
            "--pretty" => {
                pretty = true;
            }
            "--compact" => {
                pretty = false;
            }
            "-o" | "--output" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--output requires a file path");
                };
                output_file = Some(PathBuf::from(v));
            }
            "--verify-bundle" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--verify-bundle requires a bundle JSON file path");
                };
                verify_bundle_path = Some(PathBuf::from(v));
            }
            "--generate-remediation-plan" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--generate-remediation-plan requires a ForensicVerdictBundle JSON file path");
                };
                remediation_bundle_path = Some(PathBuf::from(v));
            }
            "--expected-self-sha256" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--expected-self-sha256 requires a 64-char hex SHA-256 string");
                };
                cfg.expected_self_sha256 = Some(v.clone());
            }
            "--ova" | "--inspect-ova" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--ova / --inspect-ova requires an .ova or .vmdk file path");
                };
                cfg.ova_path = Some(PathBuf::from(v));
            }
            "--attribute-cracker" | "--attribute-kit" => {
                cfg.attribute_cracker = true;
            }
            "--quick-check" => {
                quick_check_mode = true;
                cfg.attribute_cracker = true;
                let next_is_target = args
                    .get(i + 1)
                    .is_some_and(|next_arg| !next_arg.starts_with('-'));
                if next_is_target {
                    i += 1;
                    let target = PathBuf::from(&args[i]);
                    let qc = build_quick_check_config(&target);
                    cfg.root_path = qc.root_path;
                    cfg.audit_root_filesystem = qc.audit_root_filesystem;
                    cfg.ova_path = qc.ova_path;
                    explicit_root = true;
                } else if Path::new("/opt/cyops-auth").is_dir() {
                    cfg.root_path = PathBuf::from("/");
                }
            }
            "--serve" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    exit_cli_err("--serve requires a HOST:PORT address (e.g. 127.0.0.1:8090)");
                };
                serve_addr = Some(v.clone());
            }
            "--serve-once" => {
                serve_once = true;
            }
            unknown => {
                exit_cli_err(&format!("unrecognized argument: {}", unknown));
            }
        }
        i += 1;
    }

    // Mode D: Zero-Dependency Local Web Inspection Portal (`--serve <HOST:PORT>`)
    if let Some(bind_addr) = serve_addr {
        eprintln!(
            "[fsr-forensic-verdict] Kurumsal Crack Doğrulama Portalı başlatıldı: http://{}",
            bind_addr
        );
        if let Err(err) = run_portal_server(&bind_addr, &cfg.root_path, serve_once) {
            eprintln!("[fsr-forensic-verdict] portal server error: {}", err);
            process::exit(1);
        }
        process::exit(0);
    }

    // Mode C: Generate Deterministic Incident Response, Vault Re-Keying & Clean Migration Plan
    if let Some(bundle_path) = remediation_bundle_path {
        let rem_fmt = match format {
            OutputFormat::Json => RemediationOutputFormat::Json,
            OutputFormat::Markdown => RemediationOutputFormat::Markdown,
            OutputFormat::Html | OutputFormat::DenetimTutanagi => RemediationOutputFormat::Html,
        };
        let rem_cfg = RemediationAdvisorConfig {
            bundle_path: Some(bundle_path),
            bundle_raw_json: None,
            override_root_path: if explicit_root {
                Some(cfg.root_path.clone())
            } else {
                None
            },
            extra_playbook_paths: cfg.extra_playbook_paths.clone(),
            expected_self_sha256: cfg.expected_self_sha256.clone(),
            check_host_ld_so_preload: cfg.live_mode,
        };
        match generate_remediation_plan(&rem_cfg) {
            Ok(plan) => {
                let rendered = emit_remediation_plan(&plan, rem_fmt, pretty);
                write_output_or_exit(&rendered, output_file.as_deref());
                process::exit(0);
            }
            Err(err) => {
                eprintln!("[fsr-forensic-verdict] remediation plan error: {}", err);
                process::exit(1);
            }
        }
    }

    // When `--ova` / `--inspect-ova` is invoked standalone without an explicit `--root`,
    // inspect strictly the `.ova` archive in userspace without scanning host `/`.
    if cfg.ova_path.is_some() && !explicit_root {
        cfg.audit_root_filesystem = false;
    }

    // Startup Air-Gapped Field Self-Integrity Armor (`/proc/self/exe` SHA-256 + `LD_PRELOAD` / `LD_LIBRARY_PATH`):
    // Immediately alerts on `stderr` and enters Safe Hardened Mode if the host attempts to hook the auditor.
    let check_host_preload = verify_bundle_path.is_none()
        && cfg.audit_root_filesystem
        && (cfg.live_mode || cfg.root_path == Path::new("/"));
    let _startup_self_guard = run_startup_self_integrity_guard(
        "fsr-forensic-verdict",
        cfg.expected_self_sha256.as_deref(),
        check_host_preload,
    );

    // Mode B: Offline Evidence Bundle Verification (`--verify-bundle <FILE>`)
    if let Some(bundle_path) = verify_bundle_path {
        let verification = verify_forensic_bundle_file(&bundle_path);
        let payload = verification.to_json().to_json_string(pretty);
        write_output_or_exit(&payload, output_file.as_deref());
        if verification.bundle_authentic {
            process::exit(0);
        } else {
            process::exit(3);
        }
    }

    // Mode A: Full 5-Phase (19–22 Engine) Forensic Audit + Sealing + Report Emission
    let bundle = execute_forensic_verdict_command_center(&cfg);
    let rendered = emit_forensic_report(&bundle, format, pretty);
    write_output_or_exit(&rendered, output_file.as_deref());

    if quick_check_mode {
        let tutanak_path = PathBuf::from("/tmp/fortisoar_denetim_tutanagi.html");
        let tutanak_html = render_denetim_kabul_tutanagi_html(&bundle);
        if fs::write(&tutanak_path, tutanak_html.as_bytes()).is_ok() {
            eprintln!(
                "  [Resmi Kurumsal Denetim ve Bütünlük Tutanağı Kaydedildi]: {}",
                tutanak_path.display()
            );
        }
    }

    let (das_status, lic_status, vault_status) = summarize_instant_enterprise_checks(&bundle);
    let banner_hdr = if bundle.verdict_summary.critical_count > 0
        || bundle.verdict_summary.high_count > 0
    {
        "[✖ KRİTİK UYARI: LİSANSSIZ / KIRILMIŞ (CRACKLİ) VEYA ARKA KAPILI SİSTEM TESPİT EDİLDİ]"
    } else if bundle.verdict_summary.medium_count > 0 {
        "[! UYARI: ŞÜPHELİ ANOMALİ TESPİT EDİLDİ]"
    } else {
        "[✔ DOĞRULANDI: ORİJİNAL FABRİKA BÜTÜNLÜĞÜ — CRACK VEYA ARKA KAPI BULUNMADI]"
    };
    eprintln!("================================================================================");
    eprintln!("  KURUMSAL SİBER GÜVENLİK DENETİMİ — ANLIK CRACK / BÜTÜNLÜK KARTI");
    eprintln!("  {}", banner_hdr);
    eprintln!(
        "  Hedef: {} | Risk Skoru: {}/100 | Bulgular: {} (Kritik: {}, Yüksek: {})",
        bundle.context.root_path,
        bundle.verdict_summary.composite_risk_score,
        bundle.verdict_summary.total_findings,
        bundle.verdict_summary.critical_count,
        bundle.verdict_summary.high_count
    );
    eprintln!("  • cyops-auth / /server/csdassrv.py     : {}", das_status);
    eprintln!("  • FortiGate / FortiSOAR Lisans & Klon   : {}", lic_status);
    eprintln!("  • Tedarik Zinciri & Kasa (Vault)        : {}", vault_status);
    eprintln!(
        "  • RFC 6962 Merkle Kökü: {} (target_mutated: {})",
        bundle.merkle_envelope.merkle_root_hex, bundle.non_mutation_attestation.target_mutated
    );
    eprintln!("================================================================================");

    if bundle.non_mutation_attestation.target_mutated {
        process::exit(3);
    }
    if bundle.verdict_summary.critical_count > 0
        || bundle.verdict_summary.high_count > 0
        || bundle.verdict_summary.medium_count > 0
    {
        process::exit(2);
    }
    process::exit(0);
}

fn write_output_or_exit(rendered: &str, output_file: Option<&std::path::Path>) {
    if let Some(path) = output_file {
        if let Err(e) = fs::write(path, rendered.as_bytes()) {
            eprintln!(
                "[fsr-forensic-verdict] error writing output to '{}': {}",
                path.display(),
                e
            );
            process::exit(1);
        }
    } else {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        if let Err(e) = writeln!(handle, "{}", rendered) {
            eprintln!("[fsr-forensic-verdict] stdout write error: {}", e);
            process::exit(1);
        }
    }
}

fn exit_cli_err(msg: &str) -> ! {
    eprintln!("[fsr-forensic-verdict] CLI error: {}", msg);
    eprintln!("Run `fsr-forensic-verdict --help` for usage instructions.");
    process::exit(1);
}
