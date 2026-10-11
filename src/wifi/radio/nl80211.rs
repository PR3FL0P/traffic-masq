//! Read-only nl80211 probes. Each probe owns a socket, so cancellation cannot
//! leave a dump in progress on a connection used by a subsequent probe.

use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use wl_nl80211::{
    packet_core::{
        NetlinkMessage, NetlinkPayload, Nla, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST,
    },
    packet_generic::GenlMessage,
    Ieee80211HtCaps, Nl80211Attr, Nl80211BandInfo, Nl80211BandType, Nl80211Command,
    Nl80211FrequencyInfo, Nl80211IfMode, Nl80211Message,
};

use super::{
    RadioError, RegulatoryDomain, WifiBandCapabilities, WifiCapabilitiesProvider, WifiChannel,
    WifiPhyCapabilities,
};
use crate::{config::WifiBand, netlink::wireless_phy};

// These attributes are preserved as Other by wl-nl80211 0.8.0. Values come
// from include/uapi/linux/nl80211.h; no dependency on the host's headers.
const REG_ALPHA2: u16 = 33;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct Nl80211CapabilitiesProvider;

fn probe_error(message: impl Into<String>) -> RadioError {
    RadioError::ProbeFailed {
        message: message.into(),
    }
}

fn decode_error(message: impl Into<String>) -> RadioError {
    RadioError::Parse {
        message: message.into(),
    }
}

// JoinHandle's default drop detaches the task. Abort explicitly on success,
// failure, timeout and cancellation so the socket is never leaked.
struct ProbeConnection(tokio::task::JoinHandle<()>);

impl Drop for ProbeConnection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn dump(
    command: Nl80211Command,
    attributes: Vec<Nl80211Attr>,
) -> Result<Vec<Vec<Nl80211Attr>>, RadioError> {
    tokio::time::timeout(PROBE_TIMEOUT, async {
        let (mut connection, mut handle, mut notifications) = wl_nl80211::new_connection()
            .map_err(|error| probe_error(format!("open nl80211 socket: {error}")))?;
        // The terminal message carries dump interruption/error information.
        connection.set_forward_done(true);
        let _connection = ProbeConnection(tokio::spawn(connection));
        let mut request = NetlinkMessage::from(GenlMessage::from_payload(Nl80211Message {
            cmd: command,
            attributes,
        }));
        request.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
        let mut responses = handle
            .request(request)
            .await
            .map_err(|error| probe_error(format!("nl80211 {command:?}: {error}")))?;
        let mut result = DumpAccumulator::default();
        loop {
            let response = tokio::select! {
                response = responses.next() => response,
                unexpected = notifications.next() => {
                    return Err(probe_error(format!("unsolicited nl80211 message or socket overrun: {unexpected:?}")));
                }
            };
            let Some(response) = response else { break };
            let response = response.map_err(|error| decode_error(format!("nl80211 {command:?}: {error}")))?;
            result.push(response)?;
        }
        // Overrun notifications have no request sequence number. They must
        // also be checked if completion wins the select above.
        if let Ok(unexpected) = notifications.try_recv() {
            return Err(probe_error(format!("unsolicited nl80211 message or socket overrun: {unexpected:?}")));
        }
        result.finish()
    })
    .await
    .map_err(|_| probe_error(format!("nl80211 {command:?} probe timed out")))?
}

#[derive(Default)]
struct DumpAccumulator {
    messages: Vec<Vec<Nl80211Attr>>,
    complete: bool,
}

impl DumpAccumulator {
    fn push(
        &mut self,
        response: NetlinkMessage<GenlMessage<Nl80211Message>>,
    ) -> Result<(), RadioError> {
        if response.header.flags & NLM_F_DUMP_INTR != 0 {
            return Err(probe_error("nl80211 dump interrupted; retry the probe"));
        }
        if self.complete {
            return Err(probe_error("nl80211 reply after dump completion"));
        }
        match response.payload {
            NetlinkPayload::InnerMessage(message) => self.messages.push(message.payload.attributes),
            NetlinkPayload::Done(done) => {
                if done.code != 0 {
                    return Err(probe_error(format!("nl80211 dump failed: {}", done.code)));
                }
                self.complete = true;
            }
            NetlinkPayload::Error(error) if error.code.is_some() => {
                return Err(probe_error(format!("nl80211: {error}")))
            }
            NetlinkPayload::Error(_) => {} // acknowledgement
            other => return Err(probe_error(format!("unexpected nl80211 reply: {other:?}"))),
        }
        Ok(())
    }

    fn finish(self) -> Result<Vec<Vec<Nl80211Attr>>, RadioError> {
        if !self.complete {
            return Err(probe_error("nl80211 dump ended without completion"));
        }
        Ok(self.messages)
    }
}

#[async_trait]
impl WifiCapabilitiesProvider for Nl80211CapabilitiesProvider {
    async fn phy(&self, interface: &str) -> Result<WifiPhyCapabilities, RadioError> {
        let phy = wireless_phy(interface).ok_or_else(|| RadioError::NotWireless {
            interface: interface.into(),
        })?;
        // PHY names can be changed; the numeric index is a separate sysfs fact.
        let index_path = std::path::Path::new("/sys/class/net")
            .join(interface)
            .join("phy80211/index");
        let index = tokio::fs::read_to_string(&index_path)
            .await
            .map_err(|error| probe_error(format!("read {}: {error}", index_path.display())))?
            .trim()
            .parse::<u32>()
            .map_err(|error| decode_error(format!("invalid index for {phy}: {error}")))?;
        let messages = dump(
            Nl80211Command::GetWiphy,
            vec![Nl80211Attr::Wiphy(index), Nl80211Attr::SplitWiphyDump],
        )
        .await?;
        parse_phy_dump(&phy, index, &messages)
    }

    async fn regulatory_domain(&self) -> Result<RegulatoryDomain, RadioError> {
        // Like modern iw reg get, dump both global and device-specific domains.
        // An unsupported dump is an error, never an invented global-only domain.
        parse_reg_dump(&dump(Nl80211Command::GetReg, vec![]).await?)
    }
}

fn parse_phy_dump(
    phy: &str,
    index: u32,
    messages: &[Vec<Nl80211Attr>],
) -> Result<WifiPhyCapabilities, RadioError> {
    let mut result = WifiPhyCapabilities {
        phy: phy.into(),
        phy_index: Some(index),
        supports_ap: false,
        bands: Default::default(),
    };
    let mut saw_modes = false;
    for attributes in messages {
        let indexes: Vec<_> = attributes
            .iter()
            .filter_map(|attr| match attr {
                Nl80211Attr::Wiphy(value) => Some(*value),
                _ => None,
            })
            .collect();
        if indexes != [index] {
            return Err(decode_error(format!(
                "{phy}: missing or mismatched PHY index in split dump"
            )));
        }
        for attr in attributes {
            match attr {
                Nl80211Attr::WiphyName(name) if name != phy => {
                    return Err(decode_error(format!(
                        "{phy}: PHY name changed during capability probe"
                    )));
                }
                Nl80211Attr::SupportedIftypes(modes) => {
                    saw_modes = true;
                    result.supports_ap |= modes.contains(&Nl80211IfMode::Ap);
                }
                Nl80211Attr::WiphyBands(bands) => {
                    for band in bands {
                        let kind = match band.kind {
                            Nl80211BandType::Band2GHz => WifiBand::Ghz2,
                            Nl80211BandType::Band5GHz => WifiBand::Ghz5,
                            _ => continue,
                        };
                        let entry = result.bands.entry(kind).or_default();
                        for info in &band.info {
                            match info {
                                Nl80211BandInfo::HtCapa(caps) => {
                                    entry.ht40 |= caps.contains(Ieee80211HtCaps::SupWidth2040)
                                }
                                // All VHT PHYs support 80 MHz; wider-width bits are optional.
                                Nl80211BandInfo::VhtCap(_) => entry.vht80 = true,
                                Nl80211BandInfo::Freqs(frequencies) => {
                                    for frequency in frequencies {
                                        merge_frequency(entry, kind, &frequency.info)?;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if !saw_modes
        || result.bands.is_empty()
        || result.bands.values().any(|band| band.channels.is_empty())
    {
        return Err(decode_error(format!(
            "{phy}: incomplete interface modes or 2.4/5 GHz frequency information"
        )));
    }
    Ok(result)
}

fn merge_frequency(
    band: &mut WifiBandCapabilities,
    kind: WifiBand,
    attributes: &[Nl80211FrequencyInfo],
) -> Result<(), RadioError> {
    let frequencies: Vec<_> = attributes
        .iter()
        .filter_map(|attr| match attr {
            Nl80211FrequencyInfo::Freq(value) => Some(*value),
            _ => None,
        })
        .collect();
    let [frequency] = frequencies.as_slice() else {
        return Err(decode_error("missing or duplicate frequency in PHY dump"));
    };
    // Match the project's existing supported frequency windows. A driver may
    // advertise additional channels; omit those without rejecting its usable
    // 2.4/5 GHz channels or introducing new configuration support implicitly.
    if !matches!(
        (kind, *frequency),
        (WifiBand::Ghz2, 2400..=2500) | (WifiBand::Ghz5, 4900..=5900)
    ) {
        return Ok(());
    }
    let channel = match (kind, *frequency) {
        (WifiBand::Ghz2, 2484) => 14,
        (WifiBand::Ghz2, 2412..=2472) if (frequency - 2407).is_multiple_of(5) => {
            ((frequency - 2407) / 5) as u8
        }
        (WifiBand::Ghz5, 4910..=4980) if (frequency - 4000).is_multiple_of(5) => {
            ((frequency - 4000) / 5) as u8
        }
        (WifiBand::Ghz5, 5005..=5900) if (frequency - 5000).is_multiple_of(5) => {
            ((frequency - 5000) / 5) as u8
        }
        _ => {
            return Err(decode_error(format!(
                "unsupported {kind} frequency {frequency} MHz"
            )))
        }
    };
    let entry = band.channels.entry(channel).or_insert_with(|| WifiChannel {
        frequency_mhz: *frequency,
        channel,
        ..Default::default()
    });
    if entry.frequency_mhz != *frequency {
        return Err(decode_error("conflicting frequencies for one channel"));
    }
    // OR restrictions across fragments/duplicates: later messages cannot erase them.
    for attr in attributes {
        match attr {
            Nl80211FrequencyInfo::Disabled | Nl80211FrequencyInfo::No20Mhz => entry.disabled = true,
            Nl80211FrequencyInfo::NoIr | Nl80211FrequencyInfo::NoIbss => entry.no_ir = true,
            Nl80211FrequencyInfo::Radar => entry.radar = true,
            Nl80211FrequencyInfo::NoHt40Plus => entry.no_ht40_plus = true,
            Nl80211FrequencyInfo::NoHt40Minus => entry.no_ht40_minus = true,
            Nl80211FrequencyInfo::No80Mhz => entry.no_80mhz = true,
            Nl80211FrequencyInfo::Offset(value) if *value != 0 => {
                return Err(decode_error("fractional MHz frequency is unsupported"))
            }
            Nl80211FrequencyInfo::Other(value) => {
                return Err(decode_error(format!(
                    "unknown frequency attribute {}; cannot verify channel restrictions",
                    value.kind()
                )))
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_reg_dump(messages: &[Vec<Nl80211Attr>]) -> Result<RegulatoryDomain, RadioError> {
    let mut result = RegulatoryDomain::default();
    for attributes in messages {
        let mut country = None;
        let mut index = None;
        let mut self_managed = false;
        for attr in attributes {
            match attr {
                Nl80211Attr::Wiphy(_) if index.is_some() => {
                    return Err(decode_error("duplicate regulatory PHY index"));
                }
                Nl80211Attr::Wiphy(value) => index = Some(*value),
                Nl80211Attr::WiphySelfManagedReg => self_managed = true,
                Nl80211Attr::Other(value) if value.kind() == REG_ALPHA2 => {
                    let mut bytes = vec![0; value.value_len()];
                    value.emit_value(&mut bytes);
                    let code = bytes.strip_suffix(&[0]).unwrap_or(&bytes);
                    if code.len() != 2
                        || !(code.iter().all(u8::is_ascii_uppercase)
                            || matches!(code, b"00" | b"98" | b"99"))
                    {
                        return Err(decode_error("invalid regulatory country code"));
                    }
                    if country
                        .replace(
                            String::from_utf8(code.to_vec())
                                .map_err(|error| decode_error(error.to_string()))?,
                        )
                        .is_some()
                    {
                        return Err(decode_error("duplicate regulatory country code"));
                    }
                }
                _ => {}
            }
        }
        let country =
            country.ok_or_else(|| decode_error("regulatory response has no country code"))?;
        if let Some(index) = index {
            if result
                .per_phy
                .insert(index, (country, self_managed))
                .is_some()
            {
                return Err(decode_error("duplicate regulatory PHY domain"));
            }
        } else {
            if self_managed {
                return Err(decode_error("self-managed domain has no PHY index"));
            }
            if result.global_country.replace(country).is_some() {
                return Err(decode_error("duplicate global regulatory domain"));
            }
        }
    }
    if result.global_country.is_none() {
        return Err(decode_error("regulatory dump has no global domain"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
