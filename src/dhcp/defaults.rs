//! Shared subnet policy for DHCP configuration suggestions.
use std::net::Ipv4Addr;

/// Select the largest contiguous usable range excluding the server address.
/// This is a configuration suggestion, not proof that hosts are unused on the LAN.
pub fn suggest_pool(cidr: ipnet::Ipv4Net) -> Result<(Ipv4Addr, Ipv4Addr), String> {
    if cidr.prefix_len() >= 31 {
        return Err(format!(
            "cannot derive a DHCP pool for /{}: no usable client range",
            cidr.prefix_len()
        ));
    }
    let network = u32::from(cidr.network());
    let broadcast = u32::from(cidr.broadcast());
    let router = u32::from(cidr.addr());
    if router <= network || router >= broadcast {
        return Err("configured interface address is not a usable DHCP router address".to_string());
    }

    let lower = (network + 1, router.saturating_sub(1));
    let upper = (router + 1, broadcast - 1);
    let lower_len = if lower.0 <= lower.1 {
        lower.1 - lower.0 + 1
    } else {
        0
    };
    let upper_len = if upper.0 <= upper.1 {
        upper.1 - upper.0 + 1
    } else {
        0
    };
    let (start, end) = if upper_len > lower_len { upper } else { lower };
    if start > end {
        return Err("configured subnet has no usable DHCP client addresses".to_string());
    }

    Ok((start.into(), end.into()))
}

#[cfg(test)]
mod tests;
