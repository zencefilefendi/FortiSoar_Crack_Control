use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fsr_deep_audit::schema::Severity;
use fsr_net_crypto_audit::{execute_net_crypto_audit, NetCryptoAuditConfig};

struct CliArgs {
    config: NetCryptoAuditConfig,
    output_file: Option<PathBuf>,
    pretty: bool,
}

fn main() -> ExitCode {
    let cli = match parse_cli() {
        Ok(Some(c)) => c,
        Ok(None) => return ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(io::stderr(), "[fsr-net-crypto-audit] CLI error: {}", err);
            let _ = writeln!(io::stderr(), "Run `fsr-net-crypto-audit --help` for usage.");
            return ExitCode::from(1);
        }
    };

    let report = execute_net_crypto_audit(&cli.config);
    let has_alert = report
        .findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Critical | Severity::High | Severity::Medium));

    let mut rendered = report.into_canonical_json().to_json_string(cli.pretty);
    rendered.push('\n');

    match cli.output_file {
        Some(path) => {
            if let Err(e) = fs::write(&path, rendered.as_bytes()) {
                let _ = writeln!(
                    io::stderr(),
                    "[fsr-net-crypto-audit] failed writing {}: {}",
                    path.display(),
                    e
                );
                return ExitCode::from(1);
            }
        }
        None => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            if let Err(e) = lock.write_all(rendered.as_bytes()) {
                let _ = writeln!(io::stderr(), "[fsr-net-crypto-audit] stdout error: {}", e);
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

fn parse_cli() -> Result<Option<CliArgs>, String> {
    let mut cfg = NetCryptoAuditConfig::default();
    let mut output_file = None;
    let mut pretty = true;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("fsr-net-crypto-audit {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "-r" | "--root" => {
                let v = args
                    .next()
                    .ok_or_else(|| "missing directory path after --root".to_string())?;
                cfg.root_path = PathBuf::from(v);
            }
            "--live" => cfg.live_mode = true,
            "--fgt-config" => {
                let v = args
                    .next()
                    .ok_or_else(|| "missing file path after --fgt-config".to_string())?;
                cfg.fgt_config_path = Some(PathBuf::from(v));
            }
            "--fgt-rating" => {
                let v = args
                    .next()
                    .ok_or_else(|| "missing file path after --fgt-rating".to_string())?;
                cfg.fgt_rating_path = Some(PathBuf::from(v));
            }
            "--fortinet-spki" => {
                let v = args
                    .next()
                    .ok_or_else(|| "missing 64-hex SHA-256 digest after --fortinet-spki".to_string())?;
                if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("invalid --fortinet-spki (expected 64 hex characters)".to_string());
                }
                cfg.extra_fortinet_spkis.push(v);
            }
            "--include-phase1" => cfg.include_phase1_engines = true,
            "--only" => {
                let v = args
                    .next()
                    .ok_or_else(|| "missing comma-separated engine list after --only".to_string())?;
                apply_engine_filter(&mut cfg, &v)?;
            }
            "-o" | "--output" => {
                let v = args
                    .next()
                    .ok_or_else(|| "missing file path after --output".to_string())?;
                output_file = Some(PathBuf::from(v));
            }
            "--pretty" => pretty = true,
            "--compact" => pretty = false,
            other => return Err(format!("unrecognized option `{}`", other)),
        }
    }

    Ok(Some(CliArgs {
        config: cfg,
        output_file,
        pretty,
    }))
}

fn apply_engine_filter(cfg: &mut NetCryptoAuditConfig, spec: &str) -> Result<(), String> {
    cfg.enable_net_hijack = false;
    cfg.enable_ca_trust = false;
    cfg.enable_ssl_bypass = false;
    cfg.enable_fdn_probe = false;
    cfg.enable_fgt_cfg = false;

    for token in spec.split(',') {
        match token.trim() {
            "all" => {
                cfg.enable_net_hijack = true;
                cfg.enable_ca_trust = true;
                cfg.enable_ssl_bypass = true;
                cfg.enable_fdn_probe = true;
                cfg.enable_fgt_cfg = true;
                return Ok(());
            }
            "net" | "net_hijack" => cfg.enable_net_hijack = true,
            "ca" | "ca_trust" | "ca_trust_audit" => cfg.enable_ca_trust = true,
            "ssl" | "ssl_bypass" | "ssl_bypass_check" => cfg.enable_ssl_bypass = true,
            "fdn" | "fdn_live_probe" => cfg.enable_fdn_probe = true,
            "fgt" | "fortigate_cfg_audit" => cfg.enable_fgt_cfg = true,
            "" => {}
            unknown => {
                return Err(format!(
                    "unknown engine `{}` (valid: net, ca, ssl, fdn, fgt, all)",
                    unknown
                ))
            }
        }
    }

    if !cfg.enable_net_hijack
        && !cfg.enable_ca_trust
        && !cfg.enable_ssl_bypass
        && !cfg.enable_fdn_probe
        && !cfg.enable_fgt_cfg
    {
        return Err("at least one engine must be specified in --only".to_string());
    }
    Ok(())
}

fn print_help() {
    println!(
        "\
fsr-net-crypto-audit {ver}
Phase-2 Network Redirection, Netfilter/eBPF Socket Hook, X.509 CA Trust Store,
libssl Verification Bypass, Active FDN Split-Horizon DNS/TLS, and FortiGate FDS Auditor.

USAGE:
    fsr-net-crypto-audit [OPTIONS]

OPTIONS:
    -r, --root <DIR>            Target root filesystem / mounted forensic image (default: `/`)
        --live                  Enable active FDN UDP DNS (1.1.1.1/8.8.8.8) + TCP:443 TLS probing
                                and live Netfilter / __NR_bpf(321) kernel enumeration
        --fgt-config <FILE>     Audit FortiGate VM configuration backup file
        --fgt-rating <FILE>     Audit FortiGate `diagnose debug rating` capture file
        --fortinet-spki <HEX>   Additional authorized Fortinet CA SPKI SHA-256 hex fingerprint
        --include-phase1        Also run Phase-1 (`hw`, `elf`, `pyc`, `rpm`) in unified report
        --only <LIST>           Engines to run: net,ca,ssl,fdn,fgt,all (default: all)
    -o, --output <FILE>         Write JSON/NDJSON report to <FILE> instead of stdout
        --pretty                Pretty-print JSON output (default)
        --compact               Single-line NDJSON output for SIEM/SOAR pipelines
    -h, --help                  Display this help message
    -V, --version               Display version information

EXIT CODES:
    0   Clean (no CRITICAL/HIGH/MEDIUM findings)
    2   Tampering, FDS emulator, or cryptographic anomaly detected
    1   CLI / I/O error",
        ver = env!("CARGO_PKG_VERSION")
    );
}
