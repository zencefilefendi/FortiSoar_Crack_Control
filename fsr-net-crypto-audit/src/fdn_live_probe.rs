//! Engine 4: Active Cryptographic FDN Probe & Split-Horizon DNS Comparator (`--live`).
//!
//! Resolves `update.fortiguard.net`, `service.fortiguard.net`, and `globalupdate.fortinet.net`
//! via both `libc::getaddrinfo` (OS resolver) and raw RFC 1035 UDP DNS A/AAAA queries to
//! `1.1.1.1:53` / `8.8.8.8:53`, flags RFC1918/loopback/foreign-ASN split-horizon tampering as
//! `CRITICAL_FDN_DNS_POISONING`, and connects to TCP:443 with a byte-level TLS 1.2 `ClientHello`
//! to parse `ServerHello` + `Certificate` and verify authentic Fortinet X.509 ownership.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fsr_deep_audit::schema::{EngineId, Finding, JsonValue, Severity};

use crate::asn1_x509::{parse_x509_der, X509CertInfo};
use crate::ca_trust_audit::is_authorized_fortinet_spki;
use crate::ip_asn::{classify_ip, IpOwnershipClass};

pub const FDN_PROBE_DOMAINS: &[&str] = &[
    "update.fortiguard.net",
    "service.fortiguard.net",
    "globalupdate.fortinet.net",
];

pub const PUBLIC_DNS_VALIDATORS: &[&str] = &["1.1.1.1:53", "8.8.8.8:53"];

pub const DNS_QTYPE_A: u16 = 1;
pub const DNS_QTYPE_AAAA: u16 = 28;
const DNS_QCLASS_IN: u16 = 1;

/// Parsed RFC 1035 DNS Response.
#[derive(Debug, Clone)]
pub struct DnsParsedResponse {
    pub rcode: u8,
    pub ips: Vec<IpAddr>,
    pub cnames: Vec<String>,
}

/// Parsed TLS 1.2 `ServerHello` + `Certificate` handshake metadata.
#[derive(Debug, Clone)]
pub struct TlsServerHandshakeInfo {
    pub negotiated_version: u16,
    pub cipher_suite: u16,
    pub der_certificates: Vec<Vec<u8>>,
}

/// Transport abstraction allowing live network probing in `--live` mode and deterministic offline tests.
pub trait FdnProbeTransport {
    fn resolve_via_system_libc(&self, domain: &str) -> Result<Vec<IpAddr>, String>;
    fn query_external_udp_dns(
        &self,
        resolver_addr: SocketAddr,
        domain: &str,
        qtype: u16,
    ) -> Result<DnsParsedResponse, String>;
    fn fetch_tls_server_handshake(
        &self,
        target: SocketAddr,
        sni_domain: &str,
    ) -> Result<TlsServerHandshakeInfo, String>;
}

/// Production socket transport using `getaddrinfo`, `UdpSocket`, and `TcpStream`.
pub struct LiveSocketFdnTransport {
    pub timeout: Duration,
}

impl Default for LiveSocketFdnTransport {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(4),
        }
    }
}

impl FdnProbeTransport for LiveSocketFdnTransport {
    fn resolve_via_system_libc(&self, domain: &str) -> Result<Vec<IpAddr>, String> {
        let addrs = (domain, 443u16)
            .to_socket_addrs()
            .map_err(|e| format!("getaddrinfo failed: {}", e))?;
        let mut ips = Vec::new();
        for sa in addrs {
            if !ips.contains(&sa.ip()) {
                ips.push(sa.ip());
            }
        }
        Ok(ips)
    }

    fn query_external_udp_dns(
        &self,
        resolver_addr: SocketAddr,
        domain: &str,
        qtype: u16,
    ) -> Result<DnsParsedResponse, String> {
        let txid = derive_txid(domain, qtype);
        let pkt = build_dns_query_packet(txid, domain, qtype)?;

        let bind_addr = if resolver_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("UDP bind failed: {}", e))?;
        let _ = sock.set_read_timeout(Some(self.timeout));
        let _ = sock.set_write_timeout(Some(self.timeout));

        sock.send_to(&pkt, resolver_addr)
            .map_err(|e| format!("UDP send_to {} failed: {}", resolver_addr, e))?;

        let mut recv_buf = [0u8; 2048];
        let (n, _peer) = sock
            .recv_from(&mut recv_buf)
            .map_err(|e| format!("UDP recv_from {} timed out/failed: {}", resolver_addr, e))?;

        parse_dns_response_packet(&recv_buf[..n], txid)
    }

    fn fetch_tls_server_handshake(
        &self,
        target: SocketAddr,
        sni_domain: &str,
    ) -> Result<TlsServerHandshakeInfo, String> {
        let mut stream = TcpStream::connect_timeout(&target, self.timeout)
            .map_err(|e| format!("TCP connect {} failed: {}", target, e))?;
        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

        let random = derive_client_random(sni_domain);
        let client_hello = build_tls12_client_hello(sni_domain, random);
        stream
            .write_all(&client_hello)
            .map_err(|e| format!("TLS ClientHello write failed: {}", e))?;

        let mut raw_records = Vec::with_capacity(8192);
        let mut chunk = [0u8; 4096];

        // Read TLS records until we observe `ServerHelloDone` (14) or `Certificate` (11) completes, up to 64 KiB
        while raw_records.len() < 65_536 {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    raw_records.extend_from_slice(&chunk[..n]);
                    if let Ok(parsed) = parse_tls_handshake_messages(&raw_records) {
                        if !parsed.der_certificates.is_empty() {
                            return Ok(parsed);
                        }
                    }
                    // Stop if peer sent a TLS Alert record (ContentType = 21)
                    if raw_records.first() == Some(&21) {
                        return Err("TLS server aborted handshake with Alert record".to_string());
                    }
                }
                Err(_) => break,
            }
        }

        parse_tls_handshake_messages(&raw_records)
    }
}

/// Output of Engine 4 (`fdn_live_probe`).
pub struct FdnLiveProbeResult {
    pub summary: JsonValue,
    pub findings: Vec<Finding>,
}

/// Runs Engine 4 when `--live` is enabled; otherwise records passive/skipped status cleanly.
pub fn run_fdn_live_probe_audit(
    live_mode: bool,
    extra_fortinet_spkis: &[String],
) -> FdnLiveProbeResult {
    if !live_mode {
        return FdnLiveProbeResult {
            summary: JsonValue::OrderedObject(vec![
                ("live_mode_enabled".to_string(), JsonValue::Bool(false)),
                (
                    "status".to_string(),
                    JsonValue::str("skipped_offline_mode (pass --live to enable active FDN DNS/TLS probing)"),
                ),
            ]),
            findings: Vec::new(),
        };
    }

    run_fdn_probe_with_transport(&LiveSocketFdnTransport::default(), extra_fortinet_spkis)
}

/// Runs active split-horizon DNS comparison and TLS:443 certificate verification across FDN endpoints.
pub fn run_fdn_probe_with_transport<T: FdnProbeTransport>(
    transport: &T,
    extra_fortinet_spkis: &[String],
) -> FdnLiveProbeResult {
    let mut findings = Vec::new();
    let mut endpoint_reports = Vec::new();

    for &domain in FDN_PROBE_DOMAINS {
        let sys_ips = transport.resolve_via_system_libc(domain).unwrap_or_default();

        let mut ext_ips: Vec<IpAddr> = Vec::new();
        let mut ext_errors: Vec<String> = Vec::new();

        for &validator_str in PUBLIC_DNS_VALIDATORS {
            let Ok(validator_sa) = validator_str.parse::<SocketAddr>() else {
                continue;
            };
            for qtype in [DNS_QTYPE_A, DNS_QTYPE_AAAA] {
                match transport.query_external_udp_dns(validator_sa, domain, qtype) {
                    Ok(resp) => {
                        for ip in resp.ips {
                            if !ext_ips.contains(&ip) {
                                ext_ips.push(ip);
                            }
                        }
                    }
                    Err(e) => ext_errors.push(e),
                }
            }
            if !ext_ips.is_empty() {
                break;
            }
        }

        // 1. Evaluate System Resolver IPs for RFC1918 / Loopback / Foreign ASN & Split-Horizon Divergence
        evaluate_dns_split_horizon(domain, &sys_ips, &ext_ips, &mut findings);

        // 2. Active TCP:443 TLS ServerHello + X.509 Certificate Verification
        let probe_ip = sys_ips.first().or_else(|| ext_ips.first()).copied();
        let mut tls_report_val = JsonValue::Null;

        if let Some(target_ip) = probe_ip {
            let target_sa = SocketAddr::new(target_ip, 443);
            match transport.fetch_tls_server_handshake(target_sa, domain) {
                Ok(hs) => {
                    tls_report_val = verify_fdn_tls_certificate_chain(
                        domain,
                        target_ip,
                        &hs,
                        extra_fortinet_spkis,
                        &mut findings,
                    );
                }
                Err(err) => {
                    tls_report_val = JsonValue::OrderedObject(vec![
                        ("target".to_string(), JsonValue::str(target_sa.to_string())),
                        ("handshake_error".to_string(), JsonValue::str(err)),
                    ]);
                }
            }
        }

        endpoint_reports.push(JsonValue::OrderedObject(vec![
            ("domain".to_string(), JsonValue::str(domain)),
            (
                "system_resolver_ips".to_string(),
                JsonValue::Array(
                    sys_ips
                        .iter()
                        .map(|ip| JsonValue::str(format!("{} ({})", ip, classify_ip(*ip).as_str())))
                        .collect(),
                ),
            ),
            (
                "external_dns_ips".to_string(),
                JsonValue::Array(
                    ext_ips
                        .iter()
                        .map(|ip| JsonValue::str(format!("{} ({})", ip, classify_ip(*ip).as_str())))
                        .collect(),
                ),
            ),
            ("tls_443_inspection".to_string(), tls_report_val),
        ]));
    }

    let summary = JsonValue::OrderedObject(vec![
        ("live_mode_enabled".to_string(), JsonValue::Bool(true)),
        (
            "probed_domains_count".to_string(),
            JsonValue::Uint(FDN_PROBE_DOMAINS.len() as u64),
        ),
        (
            "endpoints".to_string(),
            JsonValue::Array(endpoint_reports),
        ),
        (
            "findings_emitted".to_string(),
            JsonValue::Uint(findings.len() as u64),
        ),
    ]);

    FdnLiveProbeResult { summary, findings }
}

fn evaluate_dns_split_horizon(
    domain: &str,
    sys_ips: &[IpAddr],
    ext_ips: &[IpAddr],
    findings: &mut Vec<Finding>,
) {
    for &ip in sys_ips {
        let cls = classify_ip(ip);
        if cls.is_local_or_private() {
            findings.push(
                Finding::new(
                    EngineId::FdnLiveProbe,
                    "CRITICAL_FDN_DNS_POISONING",
                    Severity::Critical,
                    domain,
                    format!(
                        "System resolver (`getaddrinfo`) mapped FortiGuard endpoint `{}` to non-public {} address {} (local FDS license emulator)",
                        domain,
                        cls.as_str(),
                        ip
                    ),
                )
                .with_evidence("domain", JsonValue::str(domain))
                .with_evidence("poisoned_ip", JsonValue::str(ip.to_string()))
                .with_evidence("ip_ownership", JsonValue::str(cls.as_str()))
                .with_evidence(
                    "external_validator_ips",
                    JsonValue::Array(ext_ips.iter().map(|i| JsonValue::str(i.to_string())).collect()),
                ),
            );
        } else if cls == IpOwnershipClass::ExternalNonFortinet {
            findings.push(
                Finding::new(
                    EngineId::FdnLiveProbe,
                    "CRITICAL_FDN_DNS_POISONING",
                    Severity::Critical,
                    domain,
                    format!(
                        "System resolver mapped `{}` to foreign non-Fortinet IP {} outside AS40934",
                        domain, ip
                    ),
                )
                .with_evidence("domain", JsonValue::str(domain))
                .with_evidence("resolved_ip", JsonValue::str(ip.to_string()))
                .with_evidence("ip_ownership", JsonValue::str(cls.as_str())),
            );
        }
    }

    // Split-horizon ASN / network mismatch check when both resolvers returned answers
    if !sys_ips.is_empty() && !ext_ips.is_empty() {
        let sys_has_fortinet = sys_ips
            .iter()
            .any(|&i| classify_ip(i) == IpOwnershipClass::FortinetAs40934);
        let ext_has_fortinet = ext_ips
            .iter()
            .any(|&i| classify_ip(i) == IpOwnershipClass::FortinetAs40934);

        let shares_any_slash16 = sys_ips.iter().any(|s| {
            ext_ips.iter().any(|e| match (s, e) {
                (IpAddr::V4(a), IpAddr::V4(b)) => a.octets()[0..2] == b.octets()[0..2],
                (IpAddr::V6(a), IpAddr::V6(b)) => a.segments()[0..2] == b.segments()[0..2],
                _ => false,
            })
        });

        if ext_has_fortinet && !sys_has_fortinet && !shares_any_slash16 {
            findings.push(
                Finding::new(
                    EngineId::FdnLiveProbe,
                    "CRITICAL_FDN_DNS_POISONING",
                    Severity::Critical,
                    domain,
                    format!(
                        "Split-horizon DNS divergence for `{}`: OS resolver returned {:?} whereas raw UDP DNS (1.1.1.1/8.8.8.8) returned official Fortinet AS40934 {:?}",
                        domain, sys_ips, ext_ips
                    ),
                )
                .with_evidence(
                    "system_ips",
                    JsonValue::Array(sys_ips.iter().map(|i| JsonValue::str(i.to_string())).collect()),
                )
                .with_evidence(
                    "external_ips",
                    JsonValue::Array(ext_ips.iter().map(|i| JsonValue::str(i.to_string())).collect()),
                ),
            );
        }
    }
}

fn verify_fdn_tls_certificate_chain(
    domain: &str,
    target_ip: IpAddr,
    hs: &TlsServerHandshakeInfo,
    extra_fortinet_spkis: &[String],
    findings: &mut Vec<Finding>,
) -> JsonValue {
    let parsed_chain: Vec<X509CertInfo> = hs
        .der_certificates
        .iter()
        .filter_map(|d| parse_x509_der(d).ok())
        .collect();

    let Some(leaf) = parsed_chain.first() else {
        findings.push(
            Finding::new(
                EngineId::FdnLiveProbe,
                "CRITICAL_FDN_TLS_INVALID_CERT_CHAIN",
                Severity::Critical,
                format!("{} ({}:443)", domain, target_ip),
                format!(
                    "TLS server at {}:443 for `{}` returned no valid X.509 DER certificate",
                    target_ip, domain
                ),
            ),
        );
        return JsonValue::str("invalid_or_empty_certificate_chain");
    };

    let hostname_ok = leaf.matches_hostname(domain);
    let subject_org_fortinet = leaf
        .subject_org
        .as_deref()
        .map(|o| o.to_ascii_lowercase().contains("fortinet"))
        .unwrap_or(false);
    let issuer_fortinet_or_webpki = leaf
        .issuer_org
        .as_deref()
        .map(|o| {
            let l = o.to_ascii_lowercase();
            l.contains("fortinet")
                || l.contains("digicert")
                || l.contains("sectigo")
                || l.contains("globalsign")
                || l.contains("entrust")
                || l.contains("amazon")
                || l.contains("cloudflare")
                || l.contains("let's encrypt")
        })
        .unwrap_or(false);

    let chain_has_impersonated_fortinet_ca = parsed_chain.iter().skip(1).any(|ca| {
        ca.is_self_signed
            && ca.mentions_fortinet_identity()
            && !is_authorized_fortinet_spki(&ca.spki_sha256, extra_fortinet_spkis)
    });

    if leaf.is_self_signed
        || (!hostname_ok && !subject_org_fortinet)
        || !issuer_fortinet_or_webpki
        || chain_has_impersonated_fortinet_ca
    {
        findings.push(
            Finding::new(
                EngineId::FdnLiveProbe,
                "CRITICAL_FDN_ROGUE_TLS_SERVER_CERT",
                Severity::Critical,
                format!("{} ({}:443)", domain, target_ip),
                format!(
                    "TLS endpoint {}:443 for `{}` presented untrusted/forged certificate `{}` issued by `{}` (self_signed={}, hostname_match={})",
                    target_ip, domain, leaf.subject_dn, leaf.issuer_dn, leaf.is_self_signed, hostname_ok
                ),
            )
            .with_evidence("domain", JsonValue::str(domain))
            .with_evidence("server_ip", JsonValue::str(target_ip.to_string()))
            .with_evidence("leaf_subject", JsonValue::str(&leaf.subject_dn))
            .with_evidence("leaf_issuer", JsonValue::str(&leaf.issuer_dn))
            .with_evidence("leaf_spki_sha256", JsonValue::str(&leaf.spki_sha256))
            .with_evidence("leaf_self_signed", JsonValue::Bool(leaf.is_self_signed))
            .with_evidence("hostname_matched", JsonValue::Bool(hostname_ok)),
        );
    }

    JsonValue::OrderedObject(vec![
        ("server_ip".to_string(), JsonValue::str(target_ip.to_string())),
        (
            "tls_version".to_string(),
            JsonValue::str(format!("0x{:04x}", hs.negotiated_version)),
        ),
        (
            "cipher_suite".to_string(),
            JsonValue::str(format!("0x{:04x}", hs.cipher_suite)),
        ),
        ("leaf_subject".to_string(), JsonValue::str(&leaf.subject_dn)),
        ("leaf_issuer".to_string(), JsonValue::str(&leaf.issuer_dn)),
        (
            "leaf_spki_sha256".to_string(),
            JsonValue::str(&leaf.spki_sha256),
        ),
        (
            "hostname_matched".to_string(),
            JsonValue::Bool(hostname_ok),
        ),
    ])
}

// ============================================================================
// Pure-Rust RFC 1035 Raw UDP DNS Packet Builder & Parser
// ============================================================================

/// Constructs an RFC 1035 binary UDP DNS Query packet (`RD=1`, `QDCOUNT=1`).
pub fn build_dns_query_packet(txid: u16, fqdn: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let clean = fqdn.trim().trim_end_matches('.');
    if clean.is_empty() || clean.len() > 253 {
        return Err("invalid DNS query hostname length".to_string());
    }

    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&0x0120u16.to_be_bytes()); // Standard query, RD=1, AD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    for label in clean.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid DNS label `{}`", label));
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00); // Root label terminator

    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&DNS_QCLASS_IN.to_be_bytes());
    Ok(pkt)
}

/// Parses an RFC 1035 binary UDP DNS Response packet, decompressing `0xC0` name pointers.
pub fn parse_dns_response_packet(
    pkt: &[u8],
    expected_txid: u16,
) -> Result<DnsParsedResponse, String> {
    if pkt.len() < 12 {
        return Err("DNS response shorter than 12-byte header".to_string());
    }
    let rx_txid = u16::from_be_bytes([pkt[0], pkt[1]]);
    if rx_txid != expected_txid {
        return Err(format!(
            "DNS TXID mismatch (expected 0x{:04x}, got 0x{:04x})",
            expected_txid, rx_txid
        ));
    }

    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    if (flags & 0x8000) == 0 {
        return Err("DNS packet does not have QR=1 response bit set".to_string());
    }
    let rcode = (flags & 0x000f) as u8;
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        let (_qname, next_pos) = read_dns_name(pkt, pos)?;
        if next_pos + 4 > pkt.len() {
            return Err("truncated DNS Question section".to_string());
        }
        pos = next_pos + 4;
    }

    let mut ips = Vec::new();
    let mut cnames = Vec::new();

    for _ in 0..ancount {
        let (_rr_name, after_name) = read_dns_name(pkt, pos)?;
        if after_name + 10 > pkt.len() {
            return Err("truncated DNS Answer RR header".to_string());
        }
        let rtype = u16::from_be_bytes([pkt[after_name], pkt[after_name + 1]]);
        let rdlength = u16::from_be_bytes([pkt[after_name + 8], pkt[after_name + 9]]) as usize;
        let rdata_start = after_name + 10;
        let rdata_end = rdata_start.saturating_add(rdlength);
        if rdata_end > pkt.len() {
            return Err("truncated DNS Answer RDATA".to_string());
        }
        let rdata = &pkt[rdata_start..rdata_end];

        match rtype {
            DNS_QTYPE_A if rdlength == 4 => {
                ips.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
            }
            DNS_QTYPE_AAAA if rdlength == 16 => {
                let oct: [u8; 16] = rdata.try_into().unwrap();
                ips.push(IpAddr::V6(Ipv6Addr::from(oct)));
            }
            5 => {
                // CNAME
                if let Ok((cname, _)) = read_dns_name(pkt, rdata_start) {
                    cnames.push(cname);
                }
            }
            _ => {}
        }

        pos = rdata_end;
    }

    Ok(DnsParsedResponse { rcode, ips, cnames })
}

fn read_dns_name(pkt: &[u8], start_offset: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut cur = start_offset;
    let mut end_after_first_jump: Option<usize> = None;
    let mut hops = 0usize;

    loop {
        if hops > 32 {
            return Err("DNS compression pointer loop detected".to_string());
        }
        let &len_byte = pkt
            .get(cur)
            .ok_or_else(|| "DNS name out of packet bounds".to_string())?;

        if len_byte == 0 {
            let final_pos = end_after_first_jump.unwrap_or(cur + 1);
            return Ok((labels.join("."), final_pos));
        }

        if (len_byte & 0xc0) == 0xc0 {
            let &b2 = pkt
                .get(cur + 1)
                .ok_or_else(|| "truncated DNS compression pointer".to_string())?;
            if end_after_first_jump.is_none() {
                end_after_first_jump = Some(cur + 2);
            }
            cur = (((len_byte & 0x3f) as usize) << 8) | (b2 as usize);
            hops += 1;
            continue;
        }

        if (len_byte & 0xc0) != 0 {
            return Err("invalid reserved DNS label flag bits".to_string());
        }

        let l = len_byte as usize;
        let slice = pkt
            .get(cur + 1..cur + 1 + l)
            .ok_or_else(|| "truncated DNS label bytes".to_string())?;
        labels.push(String::from_utf8_lossy(slice).into_owned());
        cur += 1 + l;
    }
}

// ============================================================================
// Pure-Rust TLS 1.2 `ClientHello` Builder & `ServerHello`/`Certificate` Parser
// ============================================================================

/// Builds a TLS 1.2 `ClientHello` record with SNI so the remote endpoint returns
/// an unencrypted `ServerHello` + `Certificate` chain over TCP:443.
pub fn build_tls12_client_hello(server_name: &str, client_random: [u8; 32]) -> Vec<u8> {
    let sni_bytes = server_name.as_bytes();
    let mut extensions = Vec::new();

    // Extension 0x0000: server_name (SNI)
    if !sni_bytes.is_empty() {
        let sni_list_len = (3 + sni_bytes.len()) as u16;
        let ext_len = sni_list_len + 2;
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&ext_len.to_be_bytes());
        extensions.extend_from_slice(&sni_list_len.to_be_bytes());
        extensions.push(0x00); // host_name (0)
        extensions.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        extensions.extend_from_slice(sni_bytes);
    }

    // Extension 0x000a: supported_groups (x25519, secp256r1, secp384r1)
    extensions.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
    ]);
    // Extension 0x000b: ec_point_formats (uncompressed)
    extensions.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    // Extension 0x000d: signature_algorithms
    extensions.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x0c, 0x00, 0x0a, 0x08, 0x04, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x06,
        0x01,
    ]);

    let cipher_suites: &[u8] = &[
        0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0x00, 0x9c, // TLS_RSA_WITH_AES_128_GCM_SHA256
        0x00, 0x9d, // TLS_RSA_WITH_AES_256_GCM_SHA384
        0x00, 0x3d, // TLS_RSA_WITH_AES_256_CBC_SHA256
        0x00, 0x3c, // TLS_RSA_WITH_AES_128_CBC_SHA256
    ];

    let mut body = Vec::with_capacity(128);
    body.extend_from_slice(&[0x03, 0x03]); // ClientVersion: TLS 1.2
    body.extend_from_slice(&client_random);
    body.push(0x00); // SessionID length = 0
    body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    body.extend_from_slice(cipher_suites);
    body.extend_from_slice(&[0x01, 0x00]); // CompressionMethods: null
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let hs_len = body.len();
    let mut handshake = Vec::with_capacity(4 + hs_len);
    handshake.push(0x01); // HandshakeType::client_hello (1)
    handshake.push(((hs_len >> 16) & 0xff) as u8);
    handshake.push(((hs_len >> 8) & 0xff) as u8);
    handshake.push((hs_len & 0xff) as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(0x16); // ContentType::handshake (22)
    record.extend_from_slice(&[0x03, 0x01]); // Record layer compatibility version TLS 1.0
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Reassembles TLS Handshake records (`ContentType = 22`) and parses `ServerHello` (2) + `Certificate` (11).
pub fn parse_tls_handshake_messages(stream: &[u8]) -> Result<TlsServerHandshakeInfo, String> {
    let mut hs_payload = Vec::new();
    let mut pos = 0usize;

    while pos + 5 <= stream.len() {
        let content_type = stream[pos];
        let rec_len = u16::from_be_bytes([stream[pos + 3], stream[pos + 4]]) as usize;
        if pos + 5 + rec_len > stream.len() {
            break;
        }
        if content_type == 0x16 {
            hs_payload.extend_from_slice(&stream[pos + 5..pos + 5 + rec_len]);
        }
        pos += 5 + rec_len;
    }

    if hs_payload.is_empty() {
        return Err("incomplete or missing TLS Handshake records".to_string());
    }

    let mut negotiated_version = 0u16;
    let mut cipher_suite = 0u16;
    let mut der_certificates = Vec::new();

    let mut hpos = 0usize;
    while hpos + 4 <= hs_payload.len() {
        let msg_type = hs_payload[hpos];
        let msg_len = ((hs_payload[hpos + 1] as usize) << 16)
            | ((hs_payload[hpos + 2] as usize) << 8)
            | (hs_payload[hpos + 3] as usize);
        if hpos + 4 + msg_len > hs_payload.len() {
            break;
        }
        let body = &hs_payload[hpos + 4..hpos + 4 + msg_len];
        hpos += 4 + msg_len;

        match msg_type {
            2 if body.len() >= 38 => {
                // ServerHello: [version: 2B, random: 32B, sid_len: 1B, sid: var, cipher_suite: 2B, ...]
                negotiated_version = u16::from_be_bytes([body[0], body[1]]);
                let sid_len = body[34] as usize;
                if let Some(cs) = body.get(35 + sid_len..35 + sid_len + 2) {
                    cipher_suite = u16::from_be_bytes([cs[0], cs[1]]);
                }
            }
            11 if body.len() >= 3 => {
                // Certificate: [certs_list_len: 3B, ([cert_len: 3B, der_bytes...])* ]
                let list_len = ((body[0] as usize) << 16)
                    | ((body[1] as usize) << 8)
                    | (body[2] as usize);
                let list_end = (3 + list_len).min(body.len());
                let mut cpos = 3usize;
                while cpos + 3 <= list_end {
                    let clen = ((body[cpos] as usize) << 16)
                        | ((body[cpos + 1] as usize) << 8)
                        | (body[cpos + 2] as usize);
                    cpos += 3;
                    if cpos + clen > list_end {
                        break;
                    }
                    der_certificates.push(body[cpos..cpos + clen].to_vec());
                    cpos += clen;
                }
            }
            _ => {}
        }
    }

    if der_certificates.is_empty() {
        return Err("TLS Certificate handshake message (type 11) not received yet".to_string());
    }

    Ok(TlsServerHandshakeInfo {
        negotiated_version,
        cipher_suite,
        der_certificates,
    })
}

fn derive_txid(domain: &str, qtype: u16) -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0x4653);
    let fold = domain
        .bytes()
        .fold(0u16, |acc, b| acc.rotate_left(3) ^ (b as u16));
    nanos ^ fold ^ qtype ^ (std::process::id() as u16)
}

fn derive_client_random(domain: &str) -> [u8; 32] {
    let mut r = [0u8; 32];
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    r[0..16].copy_from_slice(&ts.to_be_bytes());
    for (i, b) in domain.bytes().take(16).enumerate() {
        r[16 + i] = b ^ 0x5a;
    }
    r
}
