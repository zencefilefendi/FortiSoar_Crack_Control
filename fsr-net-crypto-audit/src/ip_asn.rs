//! Fortinet AS40934 prefix intelligence, CIDR bitwise matching, and IP scope classification.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Official Fortinet / FortiGuard (AS40934) IPv4 CIDR allocations (`(base_u32, prefix_len, label)`).
pub const FORTINET_AS40934_V4: &[(u32, u8, &str)] = &[
    (0xad_f3_80_00, 19, "173.243.128.0/19 (AS40934 FortiGuard Primary)"),
    (0x60_2d_20_00, 19, "96.45.32.0/19 (AS40934 FortiGuard/FortiCloud)"),
    (0xd0_5b_70_00, 21, "208.91.112.0/21 (AS40934 Fortinet Core/FDN)"),
    (0xc2_45_ac_00, 22, "194.69.172.0/22 (AS40934 FortiGuard EMEA)"),
    (0x95_05_e8_00, 21, "149.5.232.0/21 (AS40934 Fortinet Global)"),
    (0x9a_34_00_00, 16, "154.52.0.0/16 (AS40934 Fortinet/FortiSASE)"),
    (0xd8_9c_d1_00, 24, "216.156.209.0/24 (AS40934 FortiGuard)"),
    (0xd1_42_51_00, 24, "209.66.81.0/24 (AS40934 FortiGuard)"),
    (0x42_75_38_00, 24, "66.117.56.0/24 (AS40934 Fortinet)"),
    (0x79_6f_ec_00, 23, "121.111.236.0/23 (AS40934 FortiGuard APAC)"),
    (0x41_d2_5f_80, 25, "65.210.95.128/25 (AS40934 FortiGuard)"),
    (0x0c_22_61_00, 24, "12.34.97.0/24 (AS40934 Fortinet)"),
];

/// High-level network ownership / routing scope of an IPv4 or IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpOwnershipClass {
    Loopback,
    Rfc1918Private,
    CgnatShared,
    LinkLocal,
    UniqueLocalV6,
    UnspecifiedOrReserved,
    FortinetAs40934,
    ExternalNonFortinet,
}

impl IpOwnershipClass {
    pub fn as_str(self) -> &'static str {
        match self {
            IpOwnershipClass::Loopback => "LOOPBACK",
            IpOwnershipClass::Rfc1918Private => "RFC1918_PRIVATE",
            IpOwnershipClass::CgnatShared => "CGNAT_100_64",
            IpOwnershipClass::LinkLocal => "LINK_LOCAL",
            IpOwnershipClass::UniqueLocalV6 => "IPV6_ULA_PRIVATE",
            IpOwnershipClass::UnspecifiedOrReserved => "UNSPECIFIED_OR_RESERVED",
            IpOwnershipClass::FortinetAs40934 => "FORTINET_AS40934",
            IpOwnershipClass::ExternalNonFortinet => "PUBLIC_NON_FORTINET_ASN",
        }
    }

    /// Returns true if the address is non-routable on the public internet (local/private hijack).
    pub fn is_local_or_private(self) -> bool {
        matches!(
            self,
            IpOwnershipClass::Loopback
                | IpOwnershipClass::Rfc1918Private
                | IpOwnershipClass::CgnatShared
                | IpOwnershipClass::LinkLocal
                | IpOwnershipClass::UniqueLocalV6
                | IpOwnershipClass::UnspecifiedOrReserved
        )
    }
}

/// Classifies any IPv4 or IPv6 address against RFC special ranges and Fortinet AS40934 blocks.
pub fn classify_ip(ip: IpAddr) -> IpOwnershipClass {
    match ip {
        IpAddr::V4(v4) => classify_ipv4(v4),
        IpAddr::V6(v6) => classify_ipv6(v6),
    }
}

pub fn classify_ipv4(ip: Ipv4Addr) -> IpOwnershipClass {
    let oct = ip.octets();
    let u = u32::from_be_bytes(oct);

    if oct[0] == 127 {
        return IpOwnershipClass::Loopback;
    }
    if oct[0] == 10
        || (oct[0] == 172 && (16..=31).contains(&oct[1]))
        || (oct[0] == 192 && oct[1] == 168)
    {
        return IpOwnershipClass::Rfc1918Private;
    }
    if oct[0] == 100 && (64..=127).contains(&oct[1]) {
        return IpOwnershipClass::CgnatShared;
    }
    if oct[0] == 169 && oct[1] == 254 {
        return IpOwnershipClass::LinkLocal;
    }
    if oct[0] == 0
        || oct[0] >= 224
        || (oct[0] == 192 && oct[1] == 0 && oct[2] == 2)
        || (oct[0] == 198 && oct[1] == 51 && oct[2] == 100)
        || (oct[0] == 203 && oct[1] == 0 && oct[2] == 113)
    {
        return IpOwnershipClass::UnspecifiedOrReserved;
    }

    for &(base, plen, _) in FORTINET_AS40934_V4 {
        if ipv4_in_subnet(u, base, plen) {
            return IpOwnershipClass::FortinetAs40934;
        }
    }

    IpOwnershipClass::ExternalNonFortinet
}

pub fn classify_ipv6(ip: Ipv6Addr) -> IpOwnershipClass {
    if ip.is_loopback() {
        return IpOwnershipClass::Loopback;
    }
    if ip.is_unspecified() {
        return IpOwnershipClass::UnspecifiedOrReserved;
    }
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return classify_ipv4(mapped);
    }

    let seg = ip.segments();
    if (seg[0] & 0xfe00) == 0xfc00 {
        return IpOwnershipClass::UniqueLocalV6;
    }
    if (seg[0] & 0xffc0) == 0xfe80 {
        return IpOwnershipClass::LinkLocal;
    }
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return IpOwnershipClass::UnspecifiedOrReserved;
    }

    // Fortinet AS40934 IPv6 allocations:
    // 2620:101:9000::/40, 2001:df2:8300::/48, 2a03:c940::/32
    if (seg[0] == 0x2620 && seg[1] == 0x0101 && (seg[2] & 0xff00) == 0x9000)
        || (seg[0] == 0x2001 && seg[1] == 0x0df2 && seg[2] == 0x8300)
        || (seg[0] == 0x2a03 && seg[1] == 0xc940)
    {
        return IpOwnershipClass::FortinetAs40934;
    }

    IpOwnershipClass::ExternalNonFortinet
}

#[inline]
pub fn prefix_mask_u32(plen: u8) -> u32 {
    if plen == 0 {
        0
    } else if plen >= 32 {
        u32::MAX
    } else {
        !0u32 << (32 - plen)
    }
}

#[inline]
pub fn ipv4_in_subnet(addr: u32, net: u32, plen: u8) -> bool {
    let mask = prefix_mask_u32(plen);
    (addr & mask) == (net & mask)
}

/// Checks whether two non-default IPv4 CIDRs overlap (`plen_a > 0 && plen_b > 0`).
#[inline]
pub fn ipv4_cidrs_overlap(net_a: u32, plen_a: u8, net_b: u32, plen_b: u8) -> bool {
    if plen_a == 0 || plen_b == 0 {
        return false;
    }
    let min_plen = plen_a.min(plen_b);
    let mask = prefix_mask_u32(min_plen);
    (net_a & mask) == (net_b & mask)
}

/// Checks if a non-default IPv4 CIDR (`plen >= 8`) overlaps any official Fortinet AS40934 prefix.
pub fn cidr_overlaps_fortinet_as40934(ip: Ipv4Addr, plen: u8) -> Option<&'static str> {
    if plen < 8 {
        return None;
    }
    let addr = u32::from_be_bytes(ip.octets());
    for &(f_net, f_plen, label) in FORTINET_AS40934_V4 {
        if ipv4_cidrs_overlap(addr, plen, f_net, f_plen) {
            return Some(label);
        }
    }
    None
}

/// Parses `"a.b.c.d/len"` or `"a.b.c.d"` (as `/32`).
pub fn parse_ipv4_cidr(token: &str) -> Option<(Ipv4Addr, u8)> {
    let trimmed = token.trim().trim_matches(|c| c == '"' || c == '\'' || c == ',');
    if let Some((ip_s, plen_s)) = trimmed.split_once('/') {
        let ip: Ipv4Addr = ip_s.parse().ok()?;
        let plen: u8 = plen_s.parse().ok()?;
        if plen <= 32 {
            Some((ip, plen))
        } else {
            None
        }
    } else {
        let ip: Ipv4Addr = trimmed.parse().ok()?;
        Some((ip, 32))
    }
}

/// Returns true if a hostname targets Fortinet, FortiGuard, FortiCloud, or FortiSOAR infrastructure.
pub fn is_fortinet_domain(domain: &str) -> bool {
    let d = domain
        .trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();

    d == "fortinet.com"
        || d.ends_with(".fortinet.com")
        || d == "fortinet.net"
        || d.ends_with(".fortinet.net")
        || d == "fortiguard.net"
        || d.ends_with(".fortiguard.net")
        || d == "fortiguard.com"
        || d.ends_with(".fortiguard.com")
        || d == "forticloud.com"
        || d.ends_with(".forticloud.com")
}
