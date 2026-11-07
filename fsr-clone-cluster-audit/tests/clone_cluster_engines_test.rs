//! Comprehensive End-to-End & Binary Parser Tests for `fsr-clone-cluster-audit` (Phase 3).

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;

use fsr_clone_cluster_audit::birthmark_extractor::{
    parse_ext4_superblock, parse_pg_control_bytes, parse_xfs_superblock, PG_CONTROL_FILE_SIZE,
};
use fsr_clone_cluster_audit::cluster_correlator::correlate_cluster_nodes;
use fsr_clone_cluster_audit::fgvm_license_inspect::analyze_fgvm_serial;
use fsr_clone_cluster_audit::remote_fingerprinter::{
    parse_raw_http_response, run_remote_fingerprinter_with_transport, HttpEndpointResponse,
    RemoteFingerprintTransport,
};
use fsr_clone_cluster_audit::time_freeze_audit::{
    parse_wtmp_bytes, LASTLOG_RECORD_SIZE_X86_64, WTMP_RECORD_SIZE_X86_64, WTMP_TV_SEC_OFFSET,
};
use fsr_clone_cluster_audit::{execute_clone_cluster_audit, CloneClusterAuditConfig};
use fsr_deep_audit::crypto::crc32c;
use fsr_net_crypto_audit::asn1_x509::extract_pem_certificates;
use fsr_net_crypto_audit::fdn_live_probe::TlsServerHandshakeInfo;

/// Builds a structurally valid 8192-byte PostgreSQL 15 `pg_control` binary (`x86_64` LE)
/// with exact Castagnoli CRC-32C at `offsetof(ControlFileData, crc) == 288`.
fn build_pg_control_8192(sys_id: u64, control_ts: i64, corrupt_crc: bool) -> Vec<u8> {
    let mut buf = vec![0u8; PG_CONTROL_FILE_SIZE];
    buf[0..8].copy_from_slice(&sys_id.to_le_bytes());
    buf[8..12].copy_from_slice(&1300u32.to_le_bytes()); // PG 13-16 pg_control_version
    buf[12..16].copy_from_slice(&202209061u32.to_le_bytes()); // PG 15 catalog_version_no
    buf[16..20].copy_from_slice(&1u32.to_le_bytes()); // DB_SHUTDOWNED
    buf[24..32].copy_from_slice(&control_ts.to_le_bytes()); // pg_time_t time
    buf[32..40].copy_from_slice(&0x0000_0001_0200_0098u64.to_le_bytes()); // checkPoint LSN

    let mut crc = crc32c(&buf[..288]);
    if corrupt_crc {
        crc ^= 0xDEAD_BEEF;
    }
    buf[288..292].copy_from_slice(&crc.to_le_bytes());
    buf
}

/// Builds a 4096-byte raw EXT4 partition header with valid `0xEF53` superblock at offset `1024`.
fn build_ext4_partition_header(uuid: [u8; 16], mkfs_ts: u32, wtime_ts: u32, label: &str) -> Vec<u8> {
    let mut img = vec![0u8; 4096];
    let sb = &mut img[1024..];
    sb[0x2C..0x30].copy_from_slice(&wtime_ts.to_le_bytes()); // s_mtime
    sb[0x30..0x34].copy_from_slice(&wtime_ts.to_le_bytes()); // s_wtime
    sb[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes()); // s_magic
    sb[0x68..0x78].copy_from_slice(&uuid);
    let lbl = label.as_bytes();
    sb[0x78..0x78 + lbl.len().min(16)].copy_from_slice(&lbl[..lbl.len().min(16)]);
    sb[0x88..0x89].copy_from_slice(b"/");
    sb[0x108..0x10C].copy_from_slice(&mkfs_ts.to_le_bytes()); // s_mkfs_time
    img
}

/// Builds a 4096-byte raw XFS v5 partition header (`"XFSB"` big-endian at offset `0`).
fn build_xfs_v5_partition_header(uuid: [u8; 16], meta_uuid: [u8; 16], label: &str) -> Vec<u8> {
    let mut img = vec![0u8; 4096];
    img[0..4].copy_from_slice(&0x5846_5342u32.to_be_bytes()); // "XFSB"
    img[4..8].copy_from_slice(&4096u32.to_be_bytes()); // sb_blocksize = 4096
    img[0x20..0x30].copy_from_slice(&uuid); // sb_uuid
    img[0x64..0x66].copy_from_slice(&0xB4A5u16.to_be_bytes()); // XFS v5 (low nibble = 5)
    let lbl = label.as_bytes();
    img[0x6C..0x6C + lbl.len().min(12)].copy_from_slice(&lbl[..lbl.len().min(12)]);
    img[0x140..0x150].copy_from_slice(&meta_uuid); // sb_meta_uuid
    img
}

/// Builds a single 384-byte `x86_64` Linux `utmp`/`wtmp` record.
fn build_wtmp_record(ut_type: i16, pid: i32, user: &str, tv_sec: u32) -> [u8; WTMP_RECORD_SIZE_X86_64] {
    let mut rec = [0u8; WTMP_RECORD_SIZE_X86_64];
    rec[0..2].copy_from_slice(&ut_type.to_le_bytes());
    rec[4..8].copy_from_slice(&pid.to_le_bytes());
    let ub = user.as_bytes();
    rec[44..44 + ub.len().min(31)].copy_from_slice(&ub[..ub.len().min(31)]);
    rec[WTMP_TV_SEC_OFFSET..WTMP_TV_SEC_OFFSET + 4].copy_from_slice(&tv_sec.to_le_bytes());
    rec
}

fn generate_openssl_cert_der(dir: &Path, name: &str, subject: &str) -> Vec<u8> {
    let key_path = dir.join(format!("{}.key", name));
    let crt_path = dir.join(format!("{}.crt", name));
    let st = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key_path.to_str().unwrap(),
            "-out",
            crt_path.to_str().unwrap(),
            "-days",
            "365",
            "-subj",
            subject,
        ])
        .output()
        .expect("openssl must be available");
    assert!(st.status.success(), "openssl cert generation failed");
    let pem = fs::read_to_string(&crt_path).unwrap();
    extract_pem_certificates(&pem).pop().unwrap()
}

#[test]
fn test_binary_pg_control_ext4_xfs_wtmp_and_fgvm_serial_grammar() {
    // 1. PostgreSQL `pg_control` valid & corrupted CRC32C verification
    let valid_pg = build_pg_control_8192(7_318_349_394_477_075_001, 1_785_000_000, false);
    let parsed_pg = parse_pg_control_bytes("/var/lib/pgsql/15/data/global/pg_control", &valid_pg)
        .expect("valid pg_control");
    assert_eq!(parsed_pg.system_identifier, 7_318_349_394_477_075_001);
    assert_eq!(parsed_pg.pg_control_version, 1300);
    assert!(parsed_pg.crc32c_valid);
    assert_eq!(parsed_pg.crc32c_offset, 288);

    let bad_pg = build_pg_control_8192(7_318_349_394_477_075_001, 1_785_000_000, true);
    let parsed_bad = parse_pg_control_bytes("/var/lib/pgsql/15/data/global/pg_control", &bad_pg)
        .expect("bad crc pg_control still parses header");
    assert!(!parsed_bad.crc32c_valid);

    // 2. EXT4 & XFS v5 Superblock binary parsers
    let ext4_uuid = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x47, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01,
    ];
    let ext4_raw = build_ext4_partition_header(ext4_uuid, 1_700_000_000, 1_780_000_000, "fsr-root");
    let sb_ext4 = parse_ext4_superblock("/dev/sda2", &ext4_raw).expect("valid EXT4 superblock");
    assert_eq!(sb_ext4.fs_type, "ext4");
    assert_eq!(sb_ext4.uuid, "11223344-5566-4788-99aa-bbccddeeff01");
    assert_eq!(sb_ext4.mkfs_time_unix, Some(1_700_000_000));
    assert_eq!(sb_ext4.volume_label, "fsr-root");

    let xfs_uuid = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x40, 0x11, 0x82, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
        0x89,
    ];
    let xfs_meta = [
        0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x43, 0x21, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07,
    ];
    let xfs_raw = build_xfs_v5_partition_header(xfs_uuid, xfs_meta, "cyops-db");
    let sb_xfs = parse_xfs_superblock("/dev/mapper/rl-opt", &xfs_raw).expect("valid XFS v5");
    assert_eq!(sb_xfs.fs_type, "xfs_v5");
    assert_eq!(sb_xfs.uuid, "aabbccdd-eeff-4011-8223-344556677889");
    assert_eq!(
        sb_xfs.meta_uuid.as_deref(),
        Some("99887766-5544-4321-8001-020304050607")
    );

    // 3. Binary `wtmp` parser with explicit `OLD_TIME (4)` -> `NEW_TIME (3)` clock rewind
    let mut wtmp_bytes = Vec::new();
    wtmp_bytes.extend_from_slice(&build_wtmp_record(7, 1200, "csadmin", 1_780_010_000));
    wtmp_bytes.extend_from_slice(&build_wtmp_record(4, 0, "runlevel", 1_780_050_000)); // OLD_TIME
    wtmp_bytes.extend_from_slice(&build_wtmp_record(3, 0, "runlevel", 1_778_000_000)); // NEW_TIME (-23 days!)
    let wtmp_res = parse_wtmp_bytes(&wtmp_bytes);
    assert_eq!(wtmp_res.records_parsed, 3);
    assert_eq!(wtmp_res.latest_timestamp_unix, Some(1_780_050_000));
    assert_eq!(wtmp_res.backward_jumps.len(), 1);
    assert!(wtmp_res.backward_jumps[0].explicit_time_change_record);

    // 4. FGVM Serial Grammar: Authentic vs Eval vs Keygen
    let legit = analyze_fgvm_serial("FGVM020000184926", "test");
    assert!(
        legit.format_valid,
        "legitimate factory FGVM02 serial must pass without false positive: {:?}",
        legit.keygen_or_pirated_reason
    );

    let eval = analyze_fgvm_serial("FGVMEV0000000000", "test");
    assert!(eval.model_spec.unwrap().is_eval_trial);

    let keygen1 = analyze_fgvm_serial("FGVMUL1234567890", "test");
    assert!(!keygen1.format_valid);

    let keygen2 = analyze_fgvm_serial("FGVM08DEADBEEF01", "test");
    assert!(!keygen2.format_valid);
}

#[test]
fn test_full_golden_image_clone_cluster_time_freeze_fgvm_and_remote_probing() {
    let work: PathBuf = std::env::temp_dir().join(format!(
        "fsr_phase3_cluster_e2e_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).unwrap();

    // Shared Golden Image birthmark constants (used by cloned Customer A & Customer B)
    let cloned_pg_id: u64 = 7_199_283_746_551_902_114;
    let cloned_ext4_uuid: [u8; 16] = [
        0xde, 0xad, 0xc0, 0xde, 0x12, 0x34, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22,
        0x33,
    ];
    let shared_vault_master_secret = "FernetMasterVaultKey_GoldenImage_Pirated_2026_Secret!!";
    let shared_ssh_pub =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl root@fortisoar-ova\n";

    // Helper to populate a FortiSOAR appliance root tree
    let populate_soar_node = |node_root: &Path,
                              hostname: &str,
                              machine_id: &str,
                              pg_id: u64,
                              pg_ts: i64,
                              ext4_u: [u8; 16],
                              vault_key: &str,
                              password_salt: &str,
                              ssh_pub: &str| {
        fs::create_dir_all(node_root.join("etc/ssh")).unwrap();
        fs::create_dir_all(node_root.join("var/lib/pgsql/15/data/global")).unwrap();
        fs::create_dir_all(node_root.join("dev")).unwrap();
        fs::create_dir_all(node_root.join("opt/cyops-core/conf")).unwrap();

        fs::write(node_root.join("etc/hostname"), format!("{}\n", hostname)).unwrap();
        fs::write(node_root.join("etc/machine-id"), format!("{}\n", machine_id)).unwrap();
        fs::write(node_root.join("etc/ssh/ssh_host_ed25519_key.pub"), ssh_pub).unwrap();
        fs::write(
            node_root.join("var/lib/pgsql/15/data/global/pg_control"),
            build_pg_control_8192(pg_id, pg_ts, false),
        )
        .unwrap();
        fs::write(
            node_root.join("dev/sda1"),
            build_ext4_partition_header(ext4_u, 1_710_000_000, pg_ts as u32, "root"),
        )
        .unwrap();
        fs::write(
            node_root.join("opt/cyops-core/conf/settings.py"),
            format!(
                "# FortiSOAR production config\nSECRET_KEY = '{}'\nPASSWORD_SALT = '{}'\n",
                vault_key, password_salt
            ),
        )
        .unwrap();
    };

    // ------------------------------------------------------------------------
    // 1. Create Cloned Node A (`bank-alpha`), Cloned Node B (`telco-beta`, also time-frozen!),
    //    and Clean Independent Node C (`clean-gamma`)
    // ------------------------------------------------------------------------
    let root_a = work.join("node_a_bank");
    let root_b = work.join("node_b_telco");
    let root_c = work.join("node_c_clean");

    populate_soar_node(
        &root_a,
        "soar-prod.bank-alpha.internal",
        "8f14e45fceea167a5a36dedd4bea2543",
        cloned_pg_id,
        1_785_000_000,
        cloned_ext4_uuid,
        shared_vault_master_secret,
        "ClonedSalt_9988776655443322",
        shared_ssh_pub,
    );

    populate_soar_node(
        &root_b,
        "soar-hq.telco-beta.internal",
        "8f14e45fceea167a5a36dedd4bea2543",
        cloned_pg_id,
        1_789_000_000, // DB checkpoint at 1_789_000_000
        cloned_ext4_uuid,
        shared_vault_master_secret,
        "ClonedSalt_9988776655443322",
        shared_ssh_pub,
    );

    // Inject Time-Freeze & License Abuse artifacts onto Node B (`telco-beta`):
    // - Binary `/var/log/wtmp` & `/var/log/lastlog` ahead of frozen clock (`1_750_000_000`),
    // - `libfaketime` in `/etc/systemd/system/uwsgi.service`,
    // - Masked `/etc/systemd/system/chronyd.service` (0-byte mask file),
    // - Cracked FGVM01 `.lic` running on 16 vCPUs + `FGVMEV` trial serial in FortiOS config!
    fs::create_dir_all(root_b.join("var/log")).unwrap();
    let mut wtmp_b = Vec::new();
    wtmp_b.extend_from_slice(&build_wtmp_record(7, 2001, "root", 1_788_500_000));
    fs::write(root_b.join("var/log/wtmp"), &wtmp_b).unwrap();

    let mut lastlog_b = vec![0u8; LASTLOG_RECORD_SIZE_X86_64 * 2];
    lastlog_b[0..4].copy_from_slice(&1_788_600_000u32.to_le_bytes()); // UID 0 lastlog
    fs::write(root_b.join("var/log/lastlog"), &lastlog_b).unwrap();

    fs::create_dir_all(root_b.join("etc/systemd/system")).unwrap();
    fs::write(
        root_b.join("etc/systemd/system/uwsgi.service"),
        "[Service]\nEnvironment=\"LD_PRELOAD=/usr/lib64/libfaketime.so.1\"\nEnvironment=\"FAKETIME=@2025-06-15 00:00:00\"\n",
    )
    .unwrap();
    fs::write(root_b.join("etc/systemd/system/chronyd.service"), b"").unwrap(); // 0-byte systemd mask

    let forged_lic_path = work.join("forged_fgvm01.lic");
    fs::write(
        &forged_lic_path,
        "-----BEGIN FGT VM LICENSE-----\nU0VSSUFMTk89RkdWTTAxMDAwMDI5Mzg0NwpDUFVTPTEKUkFNPTIwNDgK\n-----END FGT VM LICENSE-----\n",
    )
    .unwrap();

    let fgt_cfg_path = work.join("fgt_prod_trial_and_keygen.conf");
    fs::write(
        &fgt_cfg_path,
        "#config-version=FGVMEV-7.4.3-FW-build2573\n\
         # Serial-Number: FGVMEV0000000000\n\
         # Secondary-Keygen: FGVMUL1234567890\n\
         config vpn ipsec phase1-interface\n\
             edit \"hq-tunnel\"\n\
             next\n\
         end\n\
         config router bgp\n\
             set as 65001\n\
         end\n\
         CPU(s): 16\n\
         Total RAM: 32768 MB\n",
    )
    .unwrap();

    // Populate Clean Node C with completely unique birthmarks
    populate_soar_node(
        &root_c,
        "soar-clean.gamma-corp.internal",
        "1234567890abcdef1234567890abcdef",
        9_876_543_210_111_222_333,
        1_785_000_000,
        [0x55; 16],
        "UniqueRandomPerApplianceSecret_GammaCorp_Only_884422!!",
        "GammaUniqueSalt_1928374655647382",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB root@gamma\n",
    );

    // ------------------------------------------------------------------------
    // 2. Run Stage A on Node A, Node B (with frozen clock), and Node C; save reports to cluster dir
    // ------------------------------------------------------------------------
    let cluster_dir = work.join("collected_reports");
    fs::create_dir_all(&cluster_dir).unwrap();

    let rep_a = execute_clone_cluster_audit(&CloneClusterAuditConfig {
        root_path: root_a.clone(),
        org_label: Some("AS64501-BankAlpha".to_string()),
        ..Default::default()
    });
    let json_a = rep_a.into_canonical_json().to_json_string(true);
    // CRITICAL SECURITY ASSERTION: Raw plaintext secret must NEVER appear in the JSON report!
    assert!(
        !json_a.contains(shared_vault_master_secret),
        "plaintext vault secret must NEVER leak into birthmark report"
    );
    fs::write(cluster_dir.join("bank_alpha.json"), &json_a).unwrap();

    let rep_b = execute_clone_cluster_audit(&CloneClusterAuditConfig {
        root_path: root_b.clone(),
        org_label: Some("AS64502-TelcoBeta".to_string()),
        reference_now_unix: Some(1_750_000_000), // Clock frozen ~1.2 years behind DB & wtmp!
        fgt_license_files: vec![forged_lic_path],
        fgt_config_path: Some(fgt_cfg_path),
        ..Default::default()
    });
    let codes_b: Vec<&str> = rep_b.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(codes_b.contains(&"CRITICAL_TIME_MANIPULATION_LICENSE_ABUSE"));
    assert!(codes_b.contains(&"CRITICAL_FGVM_UNSIGNED_OR_FORGED_LIC"));
    assert!(codes_b.contains(&"CRITICAL_FGVM_EVAL_TRIAL_IN_PRODUCTION"));
    assert!(codes_b.contains(&"CRITICAL_FGVM_PIRATED_OR_KEYGEN_SERIAL"));
    assert!(codes_b.contains(&"CRITICAL_FGVM_HARDWARE_LIMIT_BYPASS"));

    let json_b = rep_b.into_canonical_json().to_json_string(true);
    fs::write(cluster_dir.join("telco_beta.json"), &json_b).unwrap();

    let rep_c = execute_clone_cluster_audit(&CloneClusterAuditConfig {
        root_path: root_c.clone(),
        org_label: Some("AS64503-GammaClean".to_string()),
        ..Default::default()
    });
    assert!(
        rep_c.findings.is_empty(),
        "clean appliance C must emit zero findings, got: {:?}",
        rep_c.findings
    );
    fs::write(
        cluster_dir.join("gamma_clean.json"),
        rep_c.into_canonical_json().to_json_string(true),
    )
    .unwrap();

    // ------------------------------------------------------------------------
    // 3. Test Engine 5 (`remote_fingerprinter`) + Engine 4 (`cluster_correlator`) together
    // ------------------------------------------------------------------------
    let cert_dir = work.join("certs");
    fs::create_dir_all(&cert_dir).unwrap();
    let cloned_fgvm_cert_der = generate_openssl_cert_der(
        &cert_dir,
        "cloned_fgvm",
        "/C=US/O=Fortinet/OU=FortiGate/CN=FGVM040000551128",
    );

    // Verify raw HTTP parser detects FortiOS `Server: xxxxxxxx-xxxxx` & FortiSOAR `/api/3/info`
    let fgt_http = parse_raw_http_response(
        b"HTTP/1.1 200 OK\r\nServer: xxxxxxxx-xxxxx\r\nSet-Cookie: APSCOOKIE_123=0%260\r\n\r\n<html>/remote/login</html>",
    );
    assert_eq!(fgt_http.detected_platform, "fortigate_fortios_httpsd");

    let soar_http = parse_raw_http_response(
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/json\r\n\r\n{\"version\":\"7.6.0\",\"instance_uuid\":\"9f8e7d6c-5b4a-4321-8765-1029384756ab\"}",
    );
    assert_eq!(soar_http.detected_platform, "fortisoar_nginx_cyops");
    assert_eq!(
        soar_http.soar_instance_uuid.as_deref(),
        Some("9f8e7d6c-5b4a-4321-8765-1029384756ab")
    );

    struct TwoClonedFgtTransport {
        cert_der: Vec<u8>,
    }
    impl RemoteFingerprintTransport for TwoClonedFgtTransport {
        fn resolve_target(&self, host_port: &str) -> Result<(SocketAddr, String), String> {
            let sa: SocketAddr = host_port.parse().map_err(|e| format!("{}", e))?;
            Ok((sa, sa.ip().to_string()))
        }
        fn fetch_tls12_handshake(
            &self,
            _addr: SocketAddr,
            _sni_host: &str,
        ) -> Result<TlsServerHandshakeInfo, String> {
            Ok(TlsServerHandshakeInfo {
                negotiated_version: 0x0303,
                cipher_suite: 0xc02f,
                der_certificates: vec![self.cert_der.clone()],
            })
        }
        fn fetch_http_probe(
            &self,
            _addr: SocketAddr,
            _host_header: &str,
            _path: &str,
        ) -> Result<HttpEndpointResponse, String> {
            Ok(parse_raw_http_response(
                b"HTTP/1.1 400 Bad Request\r\nServer: xxxxxxxx-xxxxx\r\n\r\n",
            ))
        }
    }

    let remote_res = run_remote_fingerprinter_with_transport(
        &[
            "203.0.113.10:10443".to_string(),
            "198.51.100.77:10443".to_string(),
        ],
        &TwoClonedFgtTransport {
            cert_der: cloned_fgvm_cert_der,
        },
    );
    assert_eq!(remote_res.collected_nodes.len(), 2);

    // Feed remote nodes directly into `correlate_cluster_nodes`
    let remote_corr = correlate_cluster_nodes(&remote_res.collected_nodes, &[]);
    let remote_codes: Vec<&str> = remote_corr.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(
        remote_codes.contains(&"CRITICAL_DUPLICATE_FGVM_SERIAL_CLONE"),
        "expected duplicate FGVM040000551128 & SPKI clone finding across 203.0.113.10 and 198.51.100.77"
    );

    // Also write a Shodan/TLS NDJSON stream into `cluster_dir` and run full Stage B `--cluster-input`
    let shodan_ndjson = format!(
        "{{\"ip_str\":\"192.0.2.55\",\"port\":443,\"org\":\"AS64590-RetailA\",\"fgvm_serial\":\"FGVM080000776655\",\"spki_sha256\":\"{}\"}}\n\
         {{\"ip_str\":\"198.51.100.99\",\"port\":443,\"org\":\"AS64591-RetailB\",\"fgvm_serial\":\"FGVM080000776655\",\"spki_sha256\":\"{}\"}}\n",
        "ab".repeat(32),
        "ab".repeat(32)
    );
    fs::write(cluster_dir.join("shodan_fgvm_scan.ndjson"), shodan_ndjson).unwrap();

    let cluster_report = execute_clone_cluster_audit(&CloneClusterAuditConfig {
        audit_local_root: false,
        cluster_input_path: Some(cluster_dir),
        ..Default::default()
    });
    let cluster_codes: Vec<&str> = cluster_report
        .findings
        .iter()
        .map(|f| f.code.as_str())
        .collect();

    assert!(cluster_codes.contains(&"CRITICAL_CLONED_GOLDEN_IMAGE_PG_CLUSTER"));
    assert!(cluster_codes.contains(&"CRITICAL_SHARED_SOAR_VAULT_MASTER_KEY"));
    assert!(cluster_codes.contains(&"CRITICAL_DUPLICATE_FGVM_SERIAL_CLONE"));
    assert!(cluster_codes.contains(&"HIGH_CLONED_VM_FILESYSTEM_UUID"));

    let final_json = cluster_report.clone().into_canonical_json().to_json_string(true);
    let final_ndjson = cluster_report.into_canonical_json().to_json_string(false);
    assert!(!final_ndjson.contains('\n'));
    assert!(
        !final_json.contains("soar-clean.gamma-corp.internal"),
        "clean non-cloned appliance must NEVER be implicated in clone cluster findings"
    );

    // Validate full schema compatibility with Phase 1 & Phase 2 via Python `json.loads`
    let mut py = Command::new("python3")
        .arg("-c")
        .arg(
            "import json, sys; d = json.loads(sys.stdin.read()); \
             assert d['schema_version'] == '1.0.0'; \
             assert d['tool']['name'] == 'fsr-clone-cluster-audit'; \
             assert d['verdict']['status'] == 'COMPROMISED_OR_CRACKED'; \
             assert set(d['engines'].keys()) == {'birthmark_extractor','time_freeze_audit','fgvm_license_inspect','remote_fingerprinter','cluster_correlator'}",
        )
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        py.stdin
            .as_mut()
            .unwrap()
            .write_all(final_json.as_bytes())
            .unwrap();
    }
    assert!(py.wait().unwrap().success());

    let _ = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let _ = fs::remove_dir_all(&work);
}
