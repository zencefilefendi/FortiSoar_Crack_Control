//! Pure-Rust RFC 4648 Base64, PEM Bundle, and RFC 5280 ASN.1 DER X.509v3 Parser.
//!
//! Operates directly on byte slices with zero external crates, computing exact
//! `SubjectPublicKeyInfo` (SPKI) SHA-256 fingerprints, Distinguished Names,
//! validity timestamps, `BasicConstraints (CA:TRUE)`, and `SubjectAltName` entries.

use std::net::{Ipv4Addr, Ipv6Addr};

use fsr_deep_audit::crypto::{hex_encode, sha256_hex};

/// Parsed X.509 Certificate forensic metadata.
#[derive(Debug, Clone)]
pub struct X509CertInfo {
    pub version: u8,
    pub serial_hex: String,
    pub subject_dn: String,
    pub issuer_dn: String,
    pub subject_cn: Option<String>,
    pub subject_org: Option<String>,
    pub issuer_cn: Option<String>,
    pub issuer_org: Option<String>,
    pub not_before: String,
    pub not_before_unix: Option<i64>,
    pub not_after: String,
    pub not_after_unix: Option<i64>,
    pub basic_constraints_ca: bool,
    pub is_self_signed: bool,
    pub san_dns_names: Vec<String>,
    pub san_ip_addrs: Vec<String>,
    pub spki_sha256: String,
    pub cert_sha256: String,
}

impl X509CertInfo {
    /// Checks if `Subject` or `Issuer` mentions Fortinet/FortiGuard/FortiSOAR/FGVM branding.
    pub fn mentions_fortinet_identity(&self) -> bool {
        let combined = format!("{} {}", self.subject_dn, self.issuer_dn).to_ascii_lowercase();
        const BRANDS: &[&str] = &[
            "fortinet",
            "fortiguard",
            "fortisoar",
            "fgvm",
            "fortigate",
            "forticloud",
            "fortimanager",
        ];
        BRANDS.iter().any(|kw| combined.contains(kw))
    }

    /// Checks whether a certificate matches a target DNS hostname via SAN `dNSName` or fallback `CN`.
    pub fn matches_hostname(&self, hostname: &str) -> bool {
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        if !self.san_dns_names.is_empty() {
            return self
                .san_dns_names
                .iter()
                .any(|pattern| wildcard_dns_match(&pattern.to_ascii_lowercase(), &host));
        }
        if let Some(cn) = &self.subject_cn {
            return wildcard_dns_match(&cn.to_ascii_lowercase(), &host);
        }
        false
    }
}

fn wildcard_dns_match(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().trim_end_matches('.');
    if p == host {
        return true;
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        if let Some((_first_label, rest)) = host.split_once('.') {
            return rest == suffix;
        }
    }
    false
}

/// Zero-copy ASN.1 DER Tag-Length-Value slice.
#[derive(Debug, Clone, Copy)]
pub struct DerTlv<'a> {
    pub tag: u8,
    pub raw_tlv: &'a [u8],
    pub value: &'a [u8],
}

/// Parses a single ASN.1 DER TLV element from the front of `input`, returning `(tlv, remaining)`.
pub fn parse_der_tlv(input: &[u8]) -> Result<(DerTlv<'_>, &[u8]), String> {
    if input.len() < 2 {
        return Err("ASN.1 DER truncated before length byte".to_string());
    }

    let tag = input[0];
    let mut idx = 1usize;

    // Handle multi-octet tag numbers (`(tag & 0x1f) == 0x1f`)
    if (tag & 0x1f) == 0x1f {
        while idx < input.len() {
            let b = input[idx];
            idx += 1;
            if (b & 0x80) == 0 {
                break;
            }
            if idx > 6 {
                return Err("ASN.1 tag number overflow".to_string());
            }
        }
    }

    let Some(&len_byte) = input.get(idx) else {
        return Err("ASN.1 DER missing length byte".to_string());
    };
    idx += 1;

    let value_len: usize = if (len_byte & 0x80) == 0 {
        len_byte as usize
    } else {
        let num_octets = (len_byte & 0x7f) as usize;
        if num_octets == 0 || num_octets > 4 {
            return Err(format!(
                "unsupported ASN.1 DER length octet count {}",
                num_octets
            ));
        }
        if idx + num_octets > input.len() {
            return Err("ASN.1 DER truncated inside multi-byte length".to_string());
        }
        let mut acc = 0usize;
        for &b in &input[idx..idx + num_octets] {
            acc = (acc << 8) | (b as usize);
        }
        idx += num_octets;
        acc
    };

    let end = idx
        .checked_add(value_len)
        .ok_or_else(|| "ASN.1 DER value length overflow".to_string())?;
    if end > input.len() {
        return Err(format!(
            "ASN.1 DER element extends past buffer ({} > {})",
            end,
            input.len()
        ));
    }

    let tlv = DerTlv {
        tag,
        raw_tlv: &input[..end],
        value: &input[idx..end],
    };
    Ok((tlv, &input[end..]))
}

/// Extracts all PEM-encoded certificate blocks (`BEGIN CERTIFICATE` / `BEGIN TRUSTED CERTIFICATE`) into raw DER vectors.
pub fn extract_pem_certificates(pem_text: &str) -> Vec<Vec<u8>> {
    let mut certs = Vec::new();
    let mut inside_cert = false;
    let mut b64_buf = String::new();

    for line in pem_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN ") && trimmed.contains("CERTIFICATE-----") {
            inside_cert = true;
            b64_buf.clear();
        } else if trimmed.starts_with("-----END ") && trimmed.contains("CERTIFICATE-----") {
            if inside_cert {
                if let Ok(der) = base64_decode(&b64_buf) {
                    if !der.is_empty() {
                        certs.push(der);
                    }
                }
            }
            inside_cert = false;
            b64_buf.clear();
        } else if inside_cert {
            b64_buf.push_str(trimmed);
        }
    }

    certs
}

/// Pure-Rust RFC 4648 Base64 decoder ignoring whitespace.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    let mut quad = [0u8; 4];
    let mut q_len = 0usize;
    let mut pad_count = 0usize;

    for b in input.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                pad_count += 1;
                0
            }
            _ => return Err(format!("invalid Base64 character 0x{:02x}", b)),
        };

        quad[q_len] = val;
        q_len += 1;

        if q_len == 4 {
            let b0 = (quad[0] << 2) | (quad[1] >> 4);
            let b1 = (quad[1] << 4) | (quad[2] >> 2);
            let b2 = (quad[2] << 6) | quad[3];

            out.push(b0);
            if pad_count < 2 {
                out.push(b1);
            }
            if pad_count == 0 {
                out.push(b2);
            }

            q_len = 0;
            pad_count = 0;
        }
    }

    Ok(out)
}

/// Parses a DER-encoded X.509 Certificate per RFC 5280 §4.1.
pub fn parse_x509_der(der: &[u8]) -> Result<X509CertInfo, String> {
    let (cert_seq, _trailing) = parse_der_tlv(der)?;
    if cert_seq.tag != 0x30 {
        return Err(format!(
            "outer X.509 structure is not SEQUENCE (tag 0x{:02x})",
            cert_seq.tag
        ));
    }
    let cert_sha256 = sha256_hex(cert_seq.raw_tlv);

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (tbs_seq, _sig_rest) = parse_der_tlv(cert_seq.value)?;
    if tbs_seq.tag != 0x30 {
        return Err("TBSCertificate is not SEQUENCE".to_string());
    }

    let mut cur = tbs_seq.value;
    let (first_elem, after_first) = parse_der_tlv(cur)?;

    // Optional [0] EXPLICIT Version (default v1 = 0 -> human version 1)
    let version: u8 = if first_elem.tag == 0xa0 {
        cur = after_first;
        let (ver_int, _) = parse_der_tlv(first_elem.value)?;
        ver_int.value.first().copied().unwrap_or(0).saturating_add(1)
    } else {
        1
    };

    // serialNumber INTEGER (0x02)
    let (serial_tlv, cur) = parse_der_tlv(cur)?;
    if serial_tlv.tag != 0x02 {
        return Err("expected INTEGER for X.509 serialNumber".to_string());
    }
    let serial_trimmed = if serial_tlv.value.len() > 1 && serial_tlv.value[0] == 0x00 {
        &serial_tlv.value[1..]
    } else {
        serial_tlv.value
    };
    let serial_hex = hex_encode(serial_trimmed);

    // signature AlgorithmIdentifier SEQUENCE (0x30)
    let (_sig_alg, cur) = parse_der_tlv(cur)?;

    // issuer Name SEQUENCE (0x30)
    let (issuer_tlv, cur) = parse_der_tlv(cur)?;
    if issuer_tlv.tag != 0x30 {
        return Err("expected SEQUENCE for X.509 issuer".to_string());
    }
    let (issuer_dn, issuer_cn, issuer_org) = parse_x509_name(issuer_tlv.value);

    // validity SEQUENCE { notBefore, notAfter }
    let (validity_tlv, cur) = parse_der_tlv(cur)?;
    if validity_tlv.tag != 0x30 {
        return Err("expected SEQUENCE for X.509 validity".to_string());
    }
    let (nb_tlv, val_rest) = parse_der_tlv(validity_tlv.value)?;
    let (na_tlv, _) = parse_der_tlv(val_rest)?;
    let (not_before, not_before_unix) = parse_asn1_time(nb_tlv);
    let (not_after, not_after_unix) = parse_asn1_time(na_tlv);

    // subject Name SEQUENCE (0x30)
    let (subject_tlv, cur) = parse_der_tlv(cur)?;
    if subject_tlv.tag != 0x30 {
        return Err("expected SEQUENCE for X.509 subject".to_string());
    }
    let (subject_dn, subject_cn, subject_org) = parse_x509_name(subject_tlv.value);

    let is_self_signed = issuer_tlv.raw_tlv == subject_tlv.raw_tlv;

    // subjectPublicKeyInfo SEQUENCE (0x30) -> exact raw DER TLV hashed for SPKI SHA-256!
    let (spki_tlv, mut opt_tail) = parse_der_tlv(cur)?;
    if spki_tlv.tag != 0x30 {
        return Err("expected SEQUENCE for SubjectPublicKeyInfo".to_string());
    }
    let spki_sha256 = sha256_hex(spki_tlv.raw_tlv);

    // Optional issuerUniqueID [1], subjectUniqueID [2], extensions [3] EXPLICIT (0xa3)
    let mut basic_constraints_ca = false;
    let mut san_dns_names = Vec::new();
    let mut san_ip_addrs = Vec::new();

    while !opt_tail.is_empty() {
        let Ok((opt_elem, next_tail)) = parse_der_tlv(opt_tail) else {
            break;
        };
        opt_tail = next_tail;

        if opt_elem.tag == 0xa3 {
            parse_x509_extensions(
                opt_elem.value,
                &mut basic_constraints_ca,
                &mut san_dns_names,
                &mut san_ip_addrs,
            );
        }
    }

    // X.509 v1 self-signed root anchors predate BasicConstraints; treat v1 self-signed as CA only if v1
    if version == 1 && is_self_signed {
        basic_constraints_ca = true;
    }

    Ok(X509CertInfo {
        version,
        serial_hex,
        subject_dn,
        issuer_dn,
        subject_cn,
        subject_org,
        issuer_cn,
        issuer_org,
        not_before,
        not_before_unix,
        not_after,
        not_after_unix,
        basic_constraints_ca,
        is_self_signed,
        san_dns_names,
        san_ip_addrs,
        spki_sha256,
        cert_sha256,
    })
}

fn parse_x509_name(mut rdn_seq: &[u8]) -> (String, Option<String>, Option<String>) {
    let mut parts = Vec::new();
    let mut cn = None;
    let mut org = None;

    while !rdn_seq.is_empty() {
        let Ok((rdn_set, rest_seq)) = parse_der_tlv(rdn_seq) else {
            break;
        };
        rdn_seq = rest_seq;
        if rdn_set.tag != 0x31 {
            continue;
        }

        let mut set_cur = rdn_set.value;
        while !set_cur.is_empty() {
            let Ok((ava_seq, rest_set)) = parse_der_tlv(set_cur) else {
                break;
            };
            set_cur = rest_set;
            if ava_seq.tag != 0x30 {
                continue;
            }
            let Ok((oid_tlv, val_rest)) = parse_der_tlv(ava_seq.value) else {
                continue;
            };
            let Ok((val_tlv, _)) = parse_der_tlv(val_rest) else {
                continue;
            };
            if oid_tlv.tag != 0x06 {
                continue;
            }

            let attr_label = oid_to_rdn_label(oid_tlv.value);
            let attr_val = decode_asn1_string(val_tlv);

            if attr_label == "CN" && cn.is_none() {
                cn = Some(attr_val.clone());
            } else if attr_label == "O" && org.is_none() {
                org = Some(attr_val.clone());
            }
            parts.push(format!("{}={}", attr_label, attr_val));
        }
    }

    (parts.join(", "), cn, org)
}

fn oid_to_rdn_label(oid_bytes: &[u8]) -> String {
    match oid_bytes {
        [0x55, 0x04, 0x03] => "CN".to_string(),
        [0x55, 0x04, 0x06] => "C".to_string(),
        [0x55, 0x04, 0x07] => "L".to_string(),
        [0x55, 0x04, 0x08] => "ST".to_string(),
        [0x55, 0x04, 0x0a] => "O".to_string(),
        [0x55, 0x04, 0x0b] => "OU".to_string(),
        [0x55, 0x04, 0x05] => "serialNumber".to_string(),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "emailAddress".to_string(),
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC".to_string(),
        other => decode_oid_dotted(other),
    }
}

pub fn decode_oid_dotted(oid: &[u8]) -> String {
    if oid.is_empty() {
        return String::new();
    }
    let first = oid[0] as u64;
    let arc0 = (first / 40).min(2);
    let arc1 = first - arc0 * 40;
    let mut out = format!("{}.{}", arc0, arc1);

    let mut acc = 0u64;
    for &b in &oid[1..] {
        acc = (acc << 7) | ((b & 0x7f) as u64);
        if (b & 0x80) == 0 {
            out.push('.');
            out.push_str(&acc.to_string());
            acc = 0;
        }
    }
    out
}

fn decode_asn1_string(tlv: DerTlv<'_>) -> String {
    // Tag 0x1e = BMPString (big-endian UTF-16)
    if tlv.tag == 0x1e && (tlv.value.len() & 1) == 0 {
        let pair_count = tlv.value.len() / 2;
        let u16s: Vec<u16> = (0..pair_count)
            .map(|i| u16::from_be_bytes([tlv.value[i * 2], tlv.value[i * 2 + 1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    String::from_utf8_lossy(tlv.value).into_owned()
}

fn parse_asn1_time(tlv: DerTlv<'_>) -> (String, Option<i64>) {
    let raw = String::from_utf8_lossy(tlv.value);
    let s = raw.trim();

    let digits = s.trim_end_matches('Z');
    let parsed_ymdhms: Option<(i32, u32, u32, u32, u32, u32)> = if tlv.tag == 0x17
        && digits.len() >= 12
    {
        // UTCTime: YYMMDDHHMMSSZ (RFC 5280: YY >= 50 => 19YY, else 20YY)
        let yy: i32 = digits[0..2].parse().ok().unwrap_or(0);
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        Some((
            year,
            digits[2..4].parse().unwrap_or(1),
            digits[4..6].parse().unwrap_or(1),
            digits[6..8].parse().unwrap_or(0),
            digits[8..10].parse().unwrap_or(0),
            digits[10..12].parse().unwrap_or(0),
        ))
    } else if tlv.tag == 0x18 && digits.len() >= 14 {
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        Some((
            digits[0..4].parse().unwrap_or(1970),
            digits[4..6].parse().unwrap_or(1),
            digits[6..8].parse().unwrap_or(1),
            digits[8..10].parse().unwrap_or(0),
            digits[10..12].parse().unwrap_or(0),
            digits[12..14].parse().unwrap_or(0),
        ))
    } else {
        None
    };

    if let Some((y, mo, d, h, mi, se)) = parsed_ymdhms {
        let iso = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, se);
        let unix = civil_to_unix_utc(y, mo, d, h, mi, se);
        (iso, unix)
    } else {
        (s.to_string(), None)
    }
}

/// Howard Hinnant civil-from-days proleptic Gregorian UTC timestamp formula.
fn civil_to_unix_utc(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let y = (year as i64) - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i64;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + (day as i64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(
        days * 86_400
            + (hour as i64) * 3600
            + (min as i64) * 60
            + (sec as i64),
    )
}

fn parse_x509_extensions(
    ext_wrapper: &[u8],
    is_ca: &mut bool,
    san_dns: &mut Vec<String>,
    san_ips: &mut Vec<String>,
) {
    let Ok((ext_seq, _)) = parse_der_tlv(ext_wrapper) else {
        return;
    };
    if ext_seq.tag != 0x30 {
        return;
    }

    let mut cur = ext_seq.value;
    while !cur.is_empty() {
        let Ok((ext_item, rest)) = parse_der_tlv(cur) else {
            break;
        };
        cur = rest;
        if ext_item.tag != 0x30 {
            continue;
        }

        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
        let Ok((oid_tlv, after_oid)) = parse_der_tlv(ext_item.value) else {
            continue;
        };
        let Ok((next_tlv, after_next)) = parse_der_tlv(after_oid) else {
            continue;
        };
        let oct_tlv = if next_tlv.tag == 0x01 {
            let Ok((v, _)) = parse_der_tlv(after_next) else {
                continue;
            };
            v
        } else {
            next_tlv
        };

        if oid_tlv.tag != 0x06 || oct_tlv.tag != 0x04 {
            continue;
        }

        match oid_tlv.value {
            // id-ce-basicConstraints (2.5.29.19)
            [0x55, 0x1d, 0x13] => {
                if let Ok((bc_seq, _)) = parse_der_tlv(oct_tlv.value) {
                    if bc_seq.tag == 0x30 && !bc_seq.value.is_empty() {
                        if let Ok((first, _)) = parse_der_tlv(bc_seq.value) {
                            if first.tag == 0x01 && !first.value.is_empty() && first.value[0] != 0 {
                                *is_ca = true;
                            }
                        }
                    }
                }
            }
            // id-ce-subjectAltName (2.5.29.17)
            [0x55, 0x1d, 0x11] => {
                if let Ok((san_seq, _)) = parse_der_tlv(oct_tlv.value) {
                    if san_seq.tag == 0x30 {
                        let mut scur = san_seq.value;
                        while !scur.is_empty() {
                            let Ok((gn, srest)) = parse_der_tlv(scur) else {
                                break;
                            };
                            scur = srest;
                            match gn.tag {
                                0x82 => {
                                    // [2] dNSName (IA5String)
                                    let d = String::from_utf8_lossy(gn.value).trim().to_string();
                                    if !d.is_empty() {
                                        san_dns.push(d);
                                    }
                                }
                                0x87 => {
                                    // [7] iPAddress
                                    if gn.value.len() == 4 {
                                        let ip = Ipv4Addr::new(
                                            gn.value[0],
                                            gn.value[1],
                                            gn.value[2],
                                            gn.value[3],
                                        );
                                        san_ips.push(ip.to_string());
                                    } else if gn.value.len() == 16 {
                                        let oct: [u8; 16] = gn.value.try_into().unwrap();
                                        san_ips.push(Ipv6Addr::from(oct).to_string());
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}
