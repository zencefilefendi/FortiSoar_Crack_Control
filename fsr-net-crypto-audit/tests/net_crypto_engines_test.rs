use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;

use fsr_deep_audit::crypto::sha256_hex;
use fsr_net_crypto_audit::asn1_x509::{extract_pem_certificates, parse_x509_der};
use fsr_net_crypto_audit::fdn_live_probe::{
    build_dns_query_packet, build_tls12_client_hello, parse_dns_response_packet,
    parse_tls_handshake_messages, run_fdn_probe_with_transport, DnsParsedResponse,
    FdnProbeTransport, TlsServerHandshakeInfo, DNS_QTYPE_A,
};
use fsr_net_crypto_audit::{execute_net_crypto_audit, NetCryptoAuditConfig};

/// Generates a real X.509v3 PEM certificate using the system `openssl` binary.
fn generate_openssl_cert_pem(dir: &std::path::Path, prefix: &str, subj: &str, is_ca: bool) -> String {
    let key_path = dir.join(format!("{}.key", prefix));
    let crt_path = dir.join(format!("{}.crt", prefix));
    let bc = if is_ca {
        "basicConstraints=critical,CA:TRUE"
    } else {
        "basicConstraints=CA:FALSE"
    };

    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "365",
            "-subj",
            subj,
            "-addext",
            bc,
            "-addext",
            "subjectAltName=DNS:fake-emulator.local",
            "-keyout",
        ])
        .arg(&key_path)
        .arg("-out")
        .arg(&crt_path)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("openssl CLI required for X.509 test generation");
    assert!(status.success(), "openssl req -x509 failed");

    fs::read_to_string(&crt_path).unwrap()
}

/// Computes the exact reference SPKI SHA-256 digest via `openssl x509 -pubkey` + `openssl pkey -pubin -outform der`.
fn openssl_reference_spki_sha256(crt_path: &std::path::Path) -> String {
    let pub_pem = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(crt_path)
        .args(["-pubkey", "-noout"])
        .output()
        .unwrap();
    assert!(pub_pem.status.success());

    let mut child = Command::new("openssl")
        .args(["pkey", "-pubin", "-outform", "der"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&pub_pem.stdout)
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    sha256_hex(&out.stdout)
}

/// Builds a synthetic x86_64 ELF64 `.so` exporting 3 OpenSSL verification symbols at distinct `.text` offsets.
fn build_elf64_openssl_lib(
    sym1: (&str, &[u8]),
    sym2: (&str, &[u8]),
    sym3: (&str, &[u8]),
) -> Vec<u8> {
    let mut buf = vec![0u8; 0x2000];

    // Place `.text` at 0x0400 with 64-byte spacing per function
    let text_off = 0x0400usize;
    buf[text_off..text_off + sym1.1.len()].copy_from_slice(sym1.1);
    buf[text_off + 64..text_off + 64 + sym2.1.len()].copy_from_slice(sym2.1);
    buf[text_off + 128..text_off + 128 + sym3.1.len()].copy_from_slice(sym3.1);

    // `.dynstr` at 0x0600
    let dynstr_off = 0x0600usize;
    let mut dynstr = vec![0u8];
    let n1 = dynstr.len();
    dynstr.extend_from_slice(sym1.0.as_bytes());
    dynstr.push(0);
    let n2 = dynstr.len();
    dynstr.extend_from_slice(sym2.0.as_bytes());
    dynstr.push(0);
    let n3 = dynstr.len();
    dynstr.extend_from_slice(sym3.0.as_bytes());
    dynstr.push(0);
    buf[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(&dynstr);

    // `.dynsym` at 0x0700 (4 * 24 bytes: NULL + 3 exported functions in section #1 `.text`)
    let dynsym_off = 0x0700usize;
    for (idx, (name_off, fn_va)) in [
        (n1, text_off as u64),
        (n2, (text_off + 64) as u64),
        (n3, (text_off + 128) as u64),
    ]
    .into_iter()
    .enumerate()
    {
        let base = dynsym_off + (idx + 1) * 24;
        buf[base..base + 4].copy_from_slice(&(name_off as u32).to_le_bytes());
        buf[base + 4] = 0x12; // STB_GLOBAL | STT_FUNC
        buf[base + 6..base + 8].copy_from_slice(&1u16.to_le_bytes()); // st_shndx = 1 (.text)
        buf[base + 8..base + 16].copy_from_slice(&fn_va.to_le_bytes());
        buf[base + 16..base + 24].copy_from_slice(&48u64.to_le_bytes()); // st_size = 48
    }

    // `.shstrtab` at 0x0900
    let shstr_off = 0x0900usize;
    let shstr = b"\0.text\0.dynstr\0.dynsym\0.shstrtab\0";
    buf[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

    // 1 `PT_LOAD` `Elf64_Phdr` at 0x0040 covering `0x0..0x1000`
    let phoff = 0x0040usize;
    buf[phoff..phoff + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    buf[phoff + 4..phoff + 8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    buf[phoff + 32..phoff + 40].copy_from_slice(&0x1000u64.to_le_bytes());
    buf[phoff + 40..phoff + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    buf[phoff + 48..phoff + 56].copy_from_slice(&0x1000u64.to_le_bytes());

    // Section Headers (`5 * 64` bytes) at 0x1000
    let shoff = 0x1000usize;
    write_sh(&mut buf[shoff + 64..shoff + 128], 1, 1, 6, text_off as u64, 192, 0, 0);
    write_sh(
        &mut buf[shoff + 128..shoff + 192],
        7,
        3,
        2,
        dynstr_off as u64,
        dynstr.len() as u64,
        0,
        0,
    );
    write_sh(
        &mut buf[shoff + 192..shoff + 256],
        15,
        11,
        2,
        dynsym_off as u64,
        96,
        2,
        24,
    );
    write_sh(
        &mut buf[shoff + 256..shoff + 320],
        23,
        3,
        0,
        shstr_off as u64,
        shstr.len() as u64,
        0,
        0,
    );

    // `Elf64_Ehdr`
    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    buf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
    buf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    buf[52..54].copy_from_slice(&64u16.to_le_bytes());
    buf[54..56].copy_from_slice(&56u16.to_le_bytes());
    buf[56..58].copy_from_slice(&1u16.to_le_bytes());
    buf[58..60].copy_from_slice(&64u16.to_le_bytes());
    buf[60..62].copy_from_slice(&5u16.to_le_bytes());
    buf[62..64].copy_from_slice(&4u16.to_le_bytes());
    buf
}

#[allow(clippy::too_many_arguments)]
fn write_sh(
    dst: &mut [u8],
    name: u32,
    shtype: u32,
    flags: u64,
    off: u64,
    sz: u64,
    link: u32,
    entsize: u64,
) {
    dst[0..4].copy_from_slice(&name.to_le_bytes());
    dst[4..8].copy_from_slice(&shtype.to_le_bytes());
    dst[8..16].copy_from_slice(&flags.to_le_bytes());
    dst[16..24].copy_from_slice(&off.to_le_bytes());
    dst[24..32].copy_from_slice(&off.to_le_bytes());
    dst[32..40].copy_from_slice(&sz.to_le_bytes());
    dst[40..44].copy_from_slice(&link.to_le_bytes());
    dst[56..64].copy_from_slice(&entsize.to_le_bytes());
}

#[test]
fn test_raw_dns_packet_and_tls12_certificate_framing() {
    // 1. Verify raw RFC 1035 DNS Query + compressed DNS Response parser
    let txid = 0x9a42u16;
    let query = build_dns_query_packet(txid, "update.fortiguard.net", DNS_QTYPE_A)
        .expect("valid DNS query");
    assert_eq!(&query[0..2], &txid.to_be_bytes());

    // Build synthetic DNS response echoing Question + 1 compressed Answer (`0xc0 0x0c` -> 173.243.138.90)
    let mut resp = query.clone();
    resp[2] = 0x81; // QR=1, RD=1
    resp[3] = 0x80; // RA=1, NOERROR
    resp[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    resp.extend_from_slice(&[0xc0, 0x0c]); // Name pointer to offset 12
    resp.extend_from_slice(&DNS_QTYPE_A.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // IN
    resp.extend_from_slice(&300u32.to_be_bytes()); // TTL = 300s
    resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
    resp.extend_from_slice(&[173, 243, 138, 90]);

    let parsed = parse_dns_response_packet(&resp, txid).expect("valid DNS response");
    assert_eq!(parsed.rcode, 0);
    assert_eq!(
        parsed.ips,
        vec![IpAddr::V4(Ipv4Addr::new(173, 243, 138, 90))]
    );

    // 2. Verify TLS 1.2 ClientHello + ServerHello/Certificate stream parser
    let ch = build_tls12_client_hello("update.fortiguard.net", [0x11; 32]);
    assert_eq!(ch[0], 0x16); // TLS Handshake record
    assert_eq!(ch[5], 0x01); // HandshakeType::ClientHello

    let tmp_dir = std::env::temp_dir().join(format!("fsr_tls_unit_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir).unwrap();
    let pem = generate_openssl_cert_pem(
        &tmp_dir,
        "rogue_leaf",
        "/C=US/O=FortinetFakeEmulator/CN=update.fortiguard.net",
        false,
    );
    let ref_spki = openssl_reference_spki_sha256(&tmp_dir.join("rogue_leaf.crt"));
    let der = extract_pem_certificates(&pem).pop().unwrap();
    let cert_info = parse_x509_der(&der).expect("X.509 DER parse must succeed");
    assert_eq!(
        cert_info.spki_sha256, ref_spki,
        "pure-Rust SPKI SHA-256 must match OpenSSL reference byte-for-byte"
    );

    // Frame ServerHello (msg_type=2) + Certificate (msg_type=11) into TLS 1.2 records
    let mut sh_body = Vec::new();
    sh_body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    sh_body.extend_from_slice(&[0x22; 32]); // server_random
    sh_body.push(0); // session_id len = 0
    sh_body.extend_from_slice(&[0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    sh_body.push(0); // compression null

    let mut hs_bytes = Vec::new();
    hs_bytes.push(2); // ServerHello
    hs_bytes.extend_from_slice(&[0, 0, sh_body.len() as u8]);
    hs_bytes.extend_from_slice(&sh_body);

    let clen = der.len();
    let list_len = clen + 3;
    let msg_len = list_len + 3;
    hs_bytes.push(11); // Certificate
    hs_bytes.push(((msg_len >> 16) & 0xff) as u8);
    hs_bytes.push(((msg_len >> 8) & 0xff) as u8);
    hs_bytes.push((msg_len & 0xff) as u8);
    hs_bytes.push(((list_len >> 16) & 0xff) as u8);
    hs_bytes.push(((list_len >> 8) & 0xff) as u8);
    hs_bytes.push((list_len & 0xff) as u8);
    hs_bytes.push(((clen >> 16) & 0xff) as u8);
    hs_bytes.push(((clen >> 8) & 0xff) as u8);
    hs_bytes.push((clen & 0xff) as u8);
    hs_bytes.extend_from_slice(&der);

    let mut tls_stream = Vec::new();
    tls_stream.push(0x16);
    tls_stream.extend_from_slice(&[0x03, 0x03]);
    tls_stream.extend_from_slice(&(hs_bytes.len() as u16).to_be_bytes());
    tls_stream.extend_from_slice(&hs_bytes);

    let parsed_hs = parse_tls_handshake_messages(&tls_stream).expect("valid TLS handshake");
    assert_eq!(parsed_hs.negotiated_version, 0x0303);
    assert_eq!(parsed_hs.cipher_suite, 0xc02f);
    assert_eq!(parsed_hs.der_certificates.len(), 1);

    // Run Engine 4 simulated split-horizon transport
    struct PoisonedFdnMock {
        rogue_der: Vec<u8>,
    }
    impl FdnProbeTransport for PoisonedFdnMock {
        fn resolve_via_system_libc(&self, _domain: &str) -> Result<Vec<IpAddr>, String> {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 100, 50))])
        }
        fn query_external_udp_dns(
            &self,
            _resolver_addr: SocketAddr,
            _domain: &str,
            qtype: u16,
        ) -> Result<DnsParsedResponse, String> {
            let ips = if qtype == DNS_QTYPE_A {
                vec![IpAddr::V4(Ipv4Addr::new(173, 243, 138, 90))]
            } else {
                Vec::new()
            };
            Ok(DnsParsedResponse {
                rcode: 0,
                ips,
                cnames: Vec::new(),
            })
        }
        fn fetch_tls_server_handshake(
            &self,
            _target: SocketAddr,
            _sni_domain: &str,
        ) -> Result<TlsServerHandshakeInfo, String> {
            Ok(TlsServerHandshakeInfo {
                negotiated_version: 0x0303,
                cipher_suite: 0xc02f,
                der_certificates: vec![self.rogue_der.clone()],
            })
        }
    }

    let probe_res = run_fdn_probe_with_transport(&PoisonedFdnMock { rogue_der: der }, &[]);
    let codes: Vec<&str> = probe_res.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(codes.contains(&"CRITICAL_FDN_DNS_POISONING"));
    assert!(codes.contains(&"CRITICAL_FDN_ROGUE_TLS_SERVER_CERT"));

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_phase2_full_offline_forensic_suite_all_engines() {
    let root: PathBuf = std::env::temp_dir().join(format!(
        "fsr_net_crypto_e2e_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    // ------------------------------------------------------------------------
    // 1. Engine 1 Fixtures: /etc/hosts, dnsmasq, /proc/net/route, iptables, eBPF
    // ------------------------------------------------------------------------
    fs::create_dir_all(root.join("etc/dnsmasq.d")).unwrap();
    fs::write(
        root.join("etc/hosts"),
        "127.0.0.1 localhost\n10.20.30.40 update.fortiguard.net service.fortiguard.net\n",
    )
    .unwrap();
    fs::write(
        root.join("etc/dnsmasq.d/fds_spoof.conf"),
        "address=/forticloud.com/192.168.88.10\n",
    )
    .unwrap();

    // `/proc/net/route`: `173.243.128.0` in x86_64 LE hex is `0080F3AD`, `/19` mask `255.255.224.0` is `00E0FFFF`
    fs::create_dir_all(root.join("proc/9090/fdinfo")).unwrap();
    fs::create_dir_all(root.join("proc/net")).unwrap();
    fs::write(
        root.join("proc/net/route"),
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
         tun0\t0080F3AD\t010010AC\t0003\t0\t0\t10\t00E0FFFF\t0\t0\t0\n",
    )
    .unwrap();

    fs::create_dir_all(root.join("etc/iproute2")).unwrap();
    fs::write(
        root.join("etc/iproute2/rt_tables"),
        "255\tlocal\n254\tmain\n200\tfds_reroute\n",
    )
    .unwrap();

    fs::create_dir_all(root.join("etc/sysconfig")).unwrap();
    fs::write(
        root.join("etc/sysconfig/iptables"),
        "*nat\n-A OUTPUT -d 208.91.112.0/21 -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:8443\nCOMMIT\n",
    )
    .unwrap();

    // Active `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` (18) in `/proc/9090/fdinfo/5` + `/sys/fs/bpf` pin
    fs::write(root.join("proc/9090/comm"), "fds-ebpf-loader\n").unwrap();
    fs::write(
        root.join("proc/9090/fdinfo/5"),
        "pos:\t0\nflags:\t02000002\nprog_type:\t18\nprog_jited:\t1\nprog_tag:\tdeadbeefcafebabe\nprog_id:\t77\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("sys/fs/bpf")).unwrap();
    fs::write(root.join("sys/fs/bpf/cgroup_connect4_hijack"), b"\x00").unwrap();

    // ------------------------------------------------------------------------
    // 2. Engine 2 Fixtures: Accredited WebPKI Root + Rogue certifi Root + Impersonated Fortinet CA
    // ------------------------------------------------------------------------
    let cert_gen_dir = root.join("tmp_cert_gen");
    fs::create_dir_all(&cert_gen_dir).unwrap();

    let digicert_pem = generate_openssl_cert_pem(
        &cert_gen_dir,
        "digicert",
        "/C=US/O=DigiCert Inc/CN=DigiCert Global Root G2",
        true,
    );
    let rogue_root_pem = generate_openssl_cert_pem(
        &cert_gen_dir,
        "rogue_root",
        "/C=XX/O=UndergroundCracker/CN=Local FDS Emulator Root CA",
        true,
    );
    let fake_fortinet_ca_pem = generate_openssl_cert_pem(
        &cert_gen_dir,
        "fake_forti",
        "/C=US/ST=California/L=Sunnyvale/O=Fortinet/OU=Certificate Authority/CN=fortinet-ca2",
        true,
    );
    let _ = fs::remove_dir_all(&cert_gen_dir);

    let anchors_dir = root.join("etc/pki/ca-trust/source/anchors");
    fs::create_dir_all(&anchors_dir).unwrap();
    fs::write(anchors_dir.join("fortinet-ca2-fake.crt"), &fake_fortinet_ca_pem).unwrap();

    let sys_bundle_dir = root.join("etc/pki/tls/certs");
    fs::create_dir_all(&sys_bundle_dir).unwrap();
    fs::write(sys_bundle_dir.join("ca-bundle.crt"), &digicert_pem).unwrap();

    let py_certifi_dir =
        root.join("opt/cyops-core/lib/python3.11/site-packages/certifi");
    fs::create_dir_all(&py_certifi_dir).unwrap();
    fs::write(
        py_certifi_dir.join("cacert.pem"),
        format!("{}\n{}\n", digicert_pem, rogue_root_pem),
    )
    .unwrap();

    // ------------------------------------------------------------------------
    // 3. Engine 3 Fixtures: Patched `/usr/lib64/libssl.so.3` & `/usr/lib64/libcrypto.so.3`
    // ------------------------------------------------------------------------
    let lib64_dir = root.join("usr/lib64");
    fs::create_dir_all(&lib64_dir).unwrap();
    // `SSL_get_verify_result`: Intel CET `endbr64` (`f3 0f 1e fa`) + `mov eax, 0; ret` (`b8 00 00 00 00 c3`)
    // `X509_verify_cert`: `mov eax, 1; ret` (`b8 01 00 00 00 c3`)
    // `EVP_VerifyFinal`: legitimate function prologue (`f3 0f 1e fa 41 57 41 56 55 53 48 83 ec 28`)
    let libssl_bytes = build_elf64_openssl_lib(
        (
            "SSL_get_verify_result",
            &[0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3],
        ),
        (
            "X509_verify_cert",
            &[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3],
        ),
        (
            "EVP_VerifyFinal",
            &[0xf3, 0x0f, 0x1e, 0xfa, 0x41, 0x57, 0x41, 0x56, 0x55, 0x53, 0x48, 0x83, 0xec, 0x28],
        ),
    );
    fs::write(lib64_dir.join("libssl.so.3"), &libssl_bytes).unwrap();

    // ------------------------------------------------------------------------
    // 4. Engine 5 Fixtures: FortiGate Config Backup + `diagnose debug rating`
    // ------------------------------------------------------------------------
    let fgt_cfg_path = root.join("fgt_cracked.conf");
    let fgt_cfg = format!(
        "config system fortiguard\n\
             set fortiguard-anycast disable\n\
             set protocol udp\n\
             set port 8888\n\
             set sdns-server-ip \"192.168.100.50\"\n\
         end\n\
         config system central-management\n\
             set type fortimanager\n\
             set fmg \"192.168.100.50\"\n\
             set include-default-servers disable\n\
             config server-list\n\
                 edit 1\n\
                     set server-type update rating\n\
                     set server-address 192.168.100.50\n\
                 next\n\
             end\n\
         end\n\
         config vpn certificate ca\n\
             edit \"CA_Cert_1\"\n\
                 set ca \"{}\"\n\
                 set range global\n\
                 set source user\n\
             next\n\
         end\n",
        fake_fortinet_ca_pem.trim()
    );
    fs::write(&fgt_cfg_path, fgt_cfg).unwrap();

    let fgt_rating_path = root.join("diagnose_debug_rating.txt");
    let fgt_rating = "\
Locale       : english
Service      : Web-filter
Status       : Enable
License      : Contract
Anycast      : Disable

-=- Server List (Sat Nov  7 17:00:00 2026) -=-

IP               Weight    RTT   Flags   TZ    FortiGuard-requests  Curr Lost  Total Lost
192.168.100.50   10        1     I       0     1942                 0          0
173.243.140.16   50        34    D       -8    0                    0          0
";
    fs::write(&fgt_rating_path, fgt_rating).unwrap();

    // ------------------------------------------------------------------------
    // 5. Run Full Phase-2 Audit & Assert All Expected Findings + Clean Controls
    // ------------------------------------------------------------------------
    let cfg = NetCryptoAuditConfig {
        root_path: root.clone(),
        live_mode: false,
        fgt_config_path: Some(fgt_cfg_path),
        fgt_rating_path: Some(fgt_rating_path),
        ..Default::default()
    };

    let report = execute_net_crypto_audit(&cfg);
    let codes: Vec<&str> = report.findings.iter().map(|f| f.code.as_str()).collect();

    // Engine 1 assertions
    assert!(codes.contains(&"CRITICAL_STATIC_DNS_FORTIGUARD_HIJACK"));
    assert!(codes.contains(&"CRITICAL_LOCAL_DNS_DAEMON_HIJACK"));
    assert!(codes.contains(&"CRITICAL_ROUTE_HIJACK_FORTINET_ASN"));
    assert!(codes.contains(&"HIGH_CUSTOM_POLICY_ROUTING_TABLE"));
    assert!(codes.contains(&"CRITICAL_NETFILTER_DNAT_OR_FWMARK_HIJACK"));
    assert!(codes.contains(&"CRITICAL_EBPF_NET_HIJACK"));

    // Engine 2 assertions
    assert!(codes.contains(&"CRITICAL_IMPERSONATED_FORTINET_CA"));
    assert!(codes.contains(&"CRITICAL_PYTHON_CERTIFI_ROGUE_ROOT_CA"));
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.summary.contains("DigiCert Global Root G2")),
        "accredited DigiCert WebPKI root must not trigger false positive"
    );

    // Engine 3 assertions
    let ssl_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.code == "CRITICAL_SSL_VERIFY_PROLOGUE_BYPASS")
        .collect();
    assert_eq!(
        ssl_findings.len(),
        2,
        "expected SSL_get_verify_result and X509_verify_cert patched, EVP_VerifyFinal clean"
    );

    // Engine 5 assertions
    assert!(codes.contains(&"CRITICAL_FGT_ANYCAST_DISABLED_OVERRIDE"));
    assert!(codes.contains(&"CRITICAL_FGT_ROGUE_SDNS_SERVER"));
    assert!(codes.contains(&"CRITICAL_FGT_CENTRAL_MGMT_FDS_EMULATOR"));
    assert!(codes.contains(&"CRITICAL_FGT_INJECTED_ROGUE_CA_CERT"));
    assert!(codes.contains(&"CRITICAL_FGT_RATING_ROGUE_FDS_SERVER"));

    // Validate Phase-1 / Phase-2 schema compatibility via Python `json.loads`
    let json_pretty = report.clone().into_canonical_json().to_json_string(true);
    let json_ndjson = report.into_canonical_json().to_json_string(false);
    assert!(!json_ndjson.contains('\n'), "compact NDJSON mode must be single-line");

    let mut py = Command::new("python3")
        .arg("-c")
        .arg(
            "import json, sys; d = json.loads(sys.stdin.read()); \
             assert d['schema_version'] == '1.0.0'; \
             assert d['tool']['name'] == 'fsr-net-crypto-audit'; \
             assert d['verdict']['status'] == 'COMPROMISED_OR_CRACKED'; \
             assert set(d['engines'].keys()) == {'net_hijack','ca_trust_audit','ssl_bypass_check','fdn_live_probe','fortigate_cfg_audit'}",
        )
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        py.stdin
            .as_mut()
            .unwrap()
            .write_all(json_pretty.as_bytes())
            .unwrap();
    }
    assert!(py.wait().unwrap().success());

    let _ = fs::remove_dir_all(&root);
}
