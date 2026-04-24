use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::lookup_host;

use crate::error::{Result, VendettaError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressPolicy {
    PublicInternet,
    AllowAllForTests,
}

pub async fn resolve_target(host: &str, port: u16, policy: EgressPolicy) -> Result<Vec<SocketAddr>> {
    let resolved: Vec<SocketAddr> = lookup_host((host, port)).await?.collect();
    if resolved.is_empty() {
        return Err(VendettaError::Egress(format!(
            "{host}:{port} resolved to no addresses"
        )));
    }

    if policy == EgressPolicy::AllowAllForTests {
        return Ok(resolved);
    }

    let allowed: Vec<SocketAddr> = resolved
        .into_iter()
        .filter(|address| is_public_internet_ip(address.ip()))
        .collect();

    if allowed.is_empty() {
        return Err(VendettaError::Egress(format!(
            "{host}:{port} resolved only to non-public addresses"
        )));
    }

    Ok(allowed)
}

pub fn is_public_internet_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    let first = octets[0];
    let second = octets[1];

    if address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address == Ipv4Addr::BROADCAST
    {
        return false;
    }

    if first == 0 || first >= 240 {
        return false;
    }

    if first == 100 && (64..=127).contains(&second) {
        return false;
    }

    if first == 192 && second == 0 {
        return false;
    }

    if first == 192 && second == 0 && octets[2] == 2 {
        return false;
    }

    if first == 198 && (second == 18 || second == 19) {
        return false;
    }

    if first == 198 && second == 51 && octets[2] == 100 {
        return false;
    }

    if first == 203 && second == 0 && octets[2] == 113 {
        return false;
    }

    true
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    let first = segments[0];

    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return false;
    }

    if (first & 0xfe00) == 0xfc00 {
        return false;
    }

    if (first & 0xffc0) == 0xfe80 {
        return false;
    }

    if first == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::is_public_internet_ip;

    #[test]
    fn allows_public_ipv4_and_ipv6() {
        assert!(is_public_internet_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(is_public_internet_ip(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
        ))));
    }

    #[test]
    fn rejects_non_public_ipv4() {
        for address in [
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        ] {
            assert!(!is_public_internet_ip(IpAddr::V4(address)));
        }
    }

    #[test]
    fn rejects_non_public_ipv6() {
        for address in [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
        ] {
            assert!(!is_public_internet_ip(IpAddr::V6(address)));
        }
    }
}
