use std::net::Ipv4Addr;

use anyhow::{bail, Result};

pub const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
pub const DHCP_FIXED_HEADER_LEN: usize = 236;
pub const DHCP_MIN_PACKET_LEN: usize = 300;
pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;
pub const ETHERNET_HTYPE: u8 = 1;
pub const ETHERNET_HLEN: u8 = 6;
pub const OPTION_SUBNET_MASK: u8 = 1;
pub const OPTION_ROUTERS: u8 = 3;
pub const OPTION_DNS_SERVERS: u8 = 6;
pub const OPTION_REQUESTED_IP: u8 = 50;
pub const OPTION_LEASE_TIME: u8 = 51;
pub const OPTION_MESSAGE_TYPE: u8 = 53;
pub const OPTION_SERVER_IDENTIFIER: u8 = 54;
pub const OPTION_PARAMETER_REQUEST_LIST: u8 = 55;
pub const OPTION_RENEWAL_TIME: u8 = 58;
pub const OPTION_REBINDING_TIME: u8 = 59;
pub const OPTION_CLIENT_IDENTIFIER: u8 = 61;
pub const OPTION_END: u8 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl DhcpMessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            4 => Some(Self::Decline),
            5 => Some(Self::Ack),
            6 => Some(Self::Nak),
            7 => Some(Self::Release),
            8 => Some(Self::Inform),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpOption<'a> {
    pub code: u8,
    pub value: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpPacket<'a> {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub options: Vec<DhcpOption<'a>>,
}

impl<'a> DhcpPacket<'a> {
    /// Decode the fixed DHCP header and options, rejecting truncated packets or an invalid magic cookie.
    pub fn parse(input: &'a [u8]) -> Result<Self> {
        if input.len() < DHCP_FIXED_HEADER_LEN + DHCP_MAGIC_COOKIE.len() {
            bail!("DHCP packet is too short");
        }

        if input[236..240] != DHCP_MAGIC_COOKIE {
            bail!("invalid DHCP magic cookie");
        }

        let mut chaddr = [0_u8; 16];
        chaddr.copy_from_slice(&input[28..44]);

        Ok(Self {
            op: input[0],
            htype: input[1],
            hlen: input[2],
            hops: input[3],
            xid: u32::from_be_bytes(input[4..8].try_into()?),
            secs: u16::from_be_bytes(input[8..10].try_into()?),
            flags: u16::from_be_bytes(input[10..12].try_into()?),
            ciaddr: Ipv4Addr::new(input[12], input[13], input[14], input[15]),
            yiaddr: Ipv4Addr::new(input[16], input[17], input[18], input[19]),
            siaddr: Ipv4Addr::new(input[20], input[21], input[22], input[23]),
            giaddr: Ipv4Addr::new(input[24], input[25], input[26], input[27]),
            chaddr,
            options: parse_options(&input[240..])?,
        })
    }

    /// Read at most one option of the expected length; reject duplicates and malformed lengths.
    pub fn singleton_option(&self, code: u8, expected_len: usize) -> Result<Option<&'a [u8]>> {
        let mut matching = self.options.iter().filter(|option| option.code == code);
        let Some(option) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() {
            bail!("DHCP option {code} appears more than once");
        }
        if option.value.len() != expected_len {
            bail!(
                "DHCP option {code} has length {}, expected {expected_len}",
                option.value.len()
            );
        }
        Ok(Some(option.value))
    }

    pub fn strict_message_type(&self) -> Result<Option<DhcpMessageType>> {
        let Some(value) = self.singleton_option(OPTION_MESSAGE_TYPE, 1)? else {
            return Ok(None);
        };
        DhcpMessageType::from_u8(value[0])
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("invalid DHCP message type {}", value[0]))
    }

    pub fn strict_ipv4_option(&self, code: u8) -> Result<Option<Ipv4Addr>> {
        Ok(self
            .singleton_option(code, 4)?
            .map(|value| Ipv4Addr::new(value[0], value[1], value[2], value[3])))
    }

    pub fn strict_u32_option(&self, code: u8) -> Result<Option<u32>> {
        self.singleton_option(code, 4)?
            .map(|value| value.try_into().map(u32::from_be_bytes).map_err(Into::into))
            .transpose()
    }

    pub fn strict_subnet_mask(&self) -> Result<Option<Ipv4Addr>> {
        self.strict_ipv4_option(OPTION_SUBNET_MASK)
    }

    pub fn strict_routers(&self) -> Result<Option<Vec<Ipv4Addr>>> {
        self.strict_ipv4_list_option(OPTION_ROUTERS)
    }

    pub fn strict_dns_servers(&self) -> Result<Option<Vec<Ipv4Addr>>> {
        self.strict_ipv4_list_option(OPTION_DNS_SERVERS)
    }

    pub fn strict_lease_time(&self) -> Result<Option<u32>> {
        self.strict_u32_option(OPTION_LEASE_TIME)
    }

    pub fn strict_server_identifier(&self) -> Result<Option<Ipv4Addr>> {
        self.strict_ipv4_option(OPTION_SERVER_IDENTIFIER)
    }

    pub fn strict_renewal_time(&self) -> Result<Option<u32>> {
        self.strict_u32_option(OPTION_RENEWAL_TIME)
    }

    pub fn strict_rebinding_time(&self) -> Result<Option<u32>> {
        self.strict_u32_option(OPTION_REBINDING_TIME)
    }

    /// Decode a unique nonempty list of IPv4 addresses; reject malformed or duplicate options.
    pub fn strict_ipv4_list_option(&self, code: u8) -> Result<Option<Vec<Ipv4Addr>>> {
        let mut matching = self.options.iter().filter(|option| option.code == code);
        let Some(option) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() {
            bail!("DHCP option {code} appears more than once");
        }
        if option.value.is_empty() || option.value.len() % 4 != 0 {
            bail!("DHCP option {code} is not a non-empty IPv4 address list");
        }
        Ok(Some(
            option
                .value
                .chunks_exact(4)
                .map(|value| Ipv4Addr::new(value[0], value[1], value[2], value[3]))
                .collect(),
        ))
    }

    pub fn message_type(&self) -> Option<DhcpMessageType> {
        self.options
            .iter()
            .find(|option| option.code == 53 && option.value.len() == 1)
            .and_then(|option| DhcpMessageType::from_u8(option.value[0]))
    }

    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.ipv4_option(50)
    }

    pub fn server_identifier(&self) -> Option<Ipv4Addr> {
        self.ipv4_option(54)
    }

    fn ipv4_option(&self, code: u8) -> Option<Ipv4Addr> {
        self.options
            .iter()
            .find(|option| option.code == code && option.value.len() == 4)
            .map(|option| {
                Ipv4Addr::new(
                    option.value[0],
                    option.value[1],
                    option.value[2],
                    option.value[3],
                )
            })
    }
}

/// Append an option after checking that its value fits the DHCP length field.
pub fn push_option(output: &mut Vec<u8>, code: u8, value: &[u8]) -> Result<()> {
    if code == 0 || code == OPTION_END {
        bail!("DHCP option code {code} is reserved");
    }
    let len = u8::try_from(value.len())
        .map_err(|_| anyhow::anyhow!("DHCP option {code} value exceeds 255 bytes"))?;
    output.push(code);
    output.push(len);
    output.extend_from_slice(value);
    Ok(())
}

pub fn finish_options(output: &mut Vec<u8>) {
    output.push(OPTION_END);
    output.resize(output.len().max(DHCP_MIN_PACKET_LEN), 0);
}

/// Decode DHCP option fields, honoring padding and END and rejecting truncated values.
pub fn parse_options(input: &[u8]) -> Result<Vec<DhcpOption<'_>>> {
    let mut options = Vec::new();
    let mut cursor = 0;

    while cursor < input.len() {
        let code = input[cursor];
        cursor += 1;

        match code {
            0 => continue,
            255 => break,
            _ => {
                if cursor >= input.len() {
                    bail!("DHCP option {code} is missing length byte");
                }

                let len = input[cursor] as usize;
                cursor += 1;

                if cursor + len > input.len() {
                    bail!("DHCP option {code} exceeds packet length");
                }

                options.push(DhcpOption {
                    code,
                    value: &input[cursor..cursor + len],
                });
                cursor += len;
            }
        }
    }

    Ok(options)
}

#[cfg(test)]
mod tests;
