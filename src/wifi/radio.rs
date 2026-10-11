use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::{vht80_center_channel, WifiBand, WifiChannelWidth};
use crate::netlink::wireless_phy;
use crate::wifi::WifiApSpec;
use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RadioError {
    #[error("interface {interface} is not attached to an nl80211 PHY")]
    NotWireless { interface: String },

    #[error("Wi-Fi capability probe failed: {message}")]
    ProbeFailed { message: String },

    #[error("cannot parse Wi-Fi PHY capabilities: {message}")]
    Parse { message: String },

    #[error("Wi-Fi access-point settings are unsupported by {phy}: {message}")]
    Unsupported { phy: String, message: String },
}

impl RadioError {
    pub fn is_unsupported(&self) -> bool {
        matches!(self, Self::NotWireless { .. } | Self::Unsupported { .. })
    }
}

#[async_trait]
pub(crate) trait RadioValidator: Send + Sync {
    async fn validate(&self, spec: &WifiApSpec) -> Result<(), RadioError>;
}

#[async_trait]
pub(crate) trait WifiCapabilitiesProvider: Send + Sync {
    async fn phy(&self, interface: &str) -> Result<WifiPhyCapabilities, RadioError>;

    async fn regulatory_domain(&self) -> Result<RegulatoryDomain, RadioError>;
}

pub(crate) struct IwCapabilitiesProvider {
    iw_binary: PathBuf,
}

impl IwCapabilitiesProvider {
    pub(crate) fn new(iw_binary: PathBuf) -> Self {
        Self { iw_binary }
    }

    async fn output(&self, args: &[&str]) -> Result<String, RadioError> {
        let output =
            crate::command::run(&self.iw_binary, args, &[], crate::command::COMMAND_TIMEOUT)
                .await
                .map_err(|error| RadioError::ProbeFailed {
                    message: format!("{error:#}"),
                })?;
        Ok(String::from_utf8_lossy(&output).into_owned())
    }
}

#[async_trait]
impl WifiCapabilitiesProvider for IwCapabilitiesProvider {
    async fn phy(&self, interface: &str) -> Result<WifiPhyCapabilities, RadioError> {
        let phy = wireless_phy(interface).ok_or_else(|| RadioError::NotWireless {
            interface: interface.to_string(),
        })?;
        let phy_text = self.output(&["phy", &phy, "info"]).await?;
        parse_phy_info(&phy, &phy_text)
    }

    async fn regulatory_domain(&self) -> Result<RegulatoryDomain, RadioError> {
        let text = self.output(&["reg", "get"]).await?;
        Ok(parse_reg_domains(&text))
    }
}

pub(crate) struct CapabilitiesRadioValidator {
    provider: Arc<dyn WifiCapabilitiesProvider>,
}

impl CapabilitiesRadioValidator {
    pub(crate) fn new(provider: Arc<dyn WifiCapabilitiesProvider>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl RadioValidator for CapabilitiesRadioValidator {
    async fn validate(&self, spec: &WifiApSpec) -> Result<(), RadioError> {
        let capabilities = self.provider.phy(&spec.interface).await?;
        let regulatory_domain = self.provider.regulatory_domain().await?;
        capabilities.validate(spec, &regulatory_domain)
    }
}

#[cfg(test)]
pub(crate) struct AllowAllRadioValidator;

#[cfg(test)]
#[async_trait]
impl RadioValidator for AllowAllRadioValidator {
    async fn validate(&self, _spec: &WifiApSpec) -> Result<(), RadioError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WifiChannel {
    pub(crate) frequency_mhz: u32,
    pub(crate) channel: u8,
    pub(crate) disabled: bool,
    pub(crate) no_ir: bool,
    pub(crate) radar: bool,
    pub(crate) no_ht40_plus: bool,
    pub(crate) no_ht40_minus: bool,
    pub(crate) no_80mhz: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WifiBandCapabilities {
    pub(crate) ht40: bool,
    pub(crate) vht80: bool,
    pub(crate) channels: BTreeMap<u8, WifiChannel>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RegulatoryDomain {
    pub(crate) global_country: Option<String>,
    pub(crate) per_phy: HashMap<u32, (String, bool)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WifiPhyCapabilities {
    pub(crate) phy: String,
    pub(crate) phy_index: Option<u32>,
    pub(crate) supports_ap: bool,
    pub(crate) bands: BTreeMap<WifiBand, WifiBandCapabilities>,
}

impl WifiPhyCapabilities {
    fn effective_regdomain<'a>(
        &self,
        regulatory_domain: &'a RegulatoryDomain,
    ) -> (Option<&'a str>, bool) {
        if let Some(index) = self.phy_index {
            if let Some((country, self_managed)) = regulatory_domain.per_phy.get(&index) {
                return (Some(country.as_str()), *self_managed);
            }
        }
        (regulatory_domain.global_country.as_deref(), false)
    }

    fn enforce_regulatory_flags(
        &self,
        spec: &WifiApSpec,
        regulatory_domain: &RegulatoryDomain,
    ) -> bool {
        let (effective_country, self_managed) = self.effective_regdomain(regulatory_domain);
        if self_managed {
            return true;
        }
        match spec.country_code.as_deref() {
            None => true,
            Some(requested) => effective_country == Some(requested),
        }
    }

    fn unsupported(&self, message: impl Into<String>) -> RadioError {
        RadioError::Unsupported {
            phy: self.phy.clone(),
            message: message.into(),
        }
    }

    fn validate(
        &self,
        spec: &WifiApSpec,
        regulatory_domain: &RegulatoryDomain,
    ) -> Result<(), RadioError> {
        if !self.supports_ap {
            return Err(self.unsupported("PHY does not advertise AP interface mode"));
        }
        let Some(band) = self.bands.get(&spec.band) else {
            return Err(self.unsupported(format!("{} band is not supported", spec.band)));
        };
        let enforce_regulatory = self.enforce_regulatory_flags(spec, regulatory_domain);
        if !enforce_regulatory {
            let (effective, _) = self.effective_regdomain(regulatory_domain);
            tracing::debug!(
                phy = %self.phy,
                requested_country = ?spec.country_code,
                effective_country = ?effective,
                "kernel regdomain differs from requested hostapd country; validating PHY capabilities now and regulatory flags after hostapd applies the requested country"
            );
        }

        match spec.channel_width {
            WifiChannelWidth::Ht20 => {}
            WifiChannelWidth::Ht40 if !band.ht40 => {
                return Err(self.unsupported(format!(
                    "{} band does not advertise HT40 support",
                    spec.band
                )))
            }
            WifiChannelWidth::Vht80 if !band.vht80 => {
                return Err(self.unsupported("5 GHz PHY does not advertise VHT/80 MHz support"))
            }
            _ => {}
        }

        if spec.channel == 0 {
            if self.any_usable_primary(spec.band, spec.channel_width, band, enforce_regulatory) {
                return Ok(());
            }
            return Err(self.unsupported(format!(
                "no usable {} channel supports {:?} under the effective kernel regulatory constraints",
                spec.band, spec.channel_width
            )));
        }

        self.validate_primary(
            spec.band,
            spec.channel,
            spec.channel_width,
            band,
            enforce_regulatory,
        )
    }

    fn any_usable_primary(
        &self,
        band_kind: WifiBand,
        width: WifiChannelWidth,
        band: &WifiBandCapabilities,
        enforce_regulatory: bool,
    ) -> bool {
        band.channels.keys().copied().any(|channel| {
            self.validate_primary(band_kind, channel, width, band, enforce_regulatory)
                .is_ok()
        })
    }

    fn validate_primary(
        &self,
        band_kind: WifiBand,
        channel: u8,
        width: WifiChannelWidth,
        band: &WifiBandCapabilities,
        enforce_regulatory: bool,
    ) -> Result<(), RadioError> {
        let Some(primary) = band.channels.get(&channel) else {
            return Err(self.unsupported(format!(
                "channel {channel} is not advertised by this PHY on the {band_kind} band"
            )));
        };
        if enforce_regulatory {
            self.ensure_channel_can_initiate(channel, primary)?;
        }

        match width {
            WifiChannelWidth::Ht20 => Ok(()),
            WifiChannelWidth::Ht40 => {
                let above = ht40_above(band_kind, channel);
                if enforce_regulatory
                    && ((above && primary.no_ht40_plus) || (!above && primary.no_ht40_minus))
                {
                    return Err(self.unsupported(format!(
                        "channel {channel} forbids the required HT40{} operation",
                        if above { "+" } else { "-" }
                    )));
                }
                let secondary = if above {
                    channel.checked_add(4)
                } else {
                    channel.checked_sub(4)
                }
                .ok_or_else(|| {
                    self.unsupported(format!(
                        "channel {channel} has no valid HT40 secondary channel"
                    ))
                })?;
                let Some(secondary_caps) = band.channels.get(&secondary) else {
                    return Err(self.unsupported(format!(
                        "channel {channel} requires secondary channel {secondary}, which the PHY does not advertise"
                    )));
                };
                if enforce_regulatory {
                    self.ensure_channel_can_initiate(secondary, secondary_caps)?;
                }
                Ok(())
            }
            WifiChannelWidth::Vht80 => {
                let Some(center) = vht80_center_channel(channel) else {
                    return Err(self.unsupported(format!(
                        "channel {channel} does not belong to a supported 80 MHz block"
                    )));
                };
                let start = center.saturating_sub(6);
                for member in [start, start + 4, start + 8, start + 12] {
                    let Some(member_caps) = band.channels.get(&member) else {
                        return Err(self.unsupported(format!(
                            "80 MHz block around center channel {center} is incomplete: channel {member} is absent on the PHY"
                        )));
                    };
                    if enforce_regulatory {
                        self.ensure_channel_can_initiate(member, member_caps)?;
                        if member_caps.no_80mhz {
                            return Err(self.unsupported(format!(
                                "channel {member} forbids 80 MHz operation under the effective kernel regulatory constraints"
                            )));
                        }
                    }
                }
                Ok(())
            }
        }
    }

    fn ensure_channel_can_initiate(
        &self,
        channel: u8,
        caps: &WifiChannel,
    ) -> Result<(), RadioError> {
        if caps.disabled {
            return Err(self.unsupported(format!(
                "channel {channel} is disabled by the effective kernel regdomain/PHY"
            )));
        }
        if caps.no_ir {
            return Err(self.unsupported(format!(
                "channel {channel} is marked no-IR, so an AP cannot initiate radiation on it"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct RawBand {
    ht40: bool,
    vht: bool,
    frequencies: Vec<WifiChannel>,
}

fn parse_phy_info(phy: &str, text: &str) -> Result<WifiPhyCapabilities, RadioError> {
    let mut supports_ap = false;
    let mut wiphy_index = None;
    let mut raw_bands = Vec::<RawBand>::new();
    let mut current_band = None::<usize>;

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("wiphy index:") {
            wiphy_index = value.trim().parse::<u32>().ok();
        }
        if trimmed == "* AP" {
            supports_ap = true;
        }
        if trimmed.starts_with("Band ") && trimmed.ends_with(':') {
            raw_bands.push(RawBand::default());
            current_band = Some(raw_bands.len() - 1);
            continue;
        }
        let Some(index) = current_band else { continue };
        if trimmed.contains("HT20/HT40") {
            raw_bands[index].ht40 = true;
        }
        if trimmed.starts_with("VHT Capabilities") {
            raw_bands[index].vht = true;
        }
        if let Some(channel) = parse_frequency_line(trimmed) {
            raw_bands[index].frequencies.push(channel);
        }
    }

    let mut bands = BTreeMap::new();
    for raw in raw_bands {
        let band_kind = raw
            .frequencies
            .iter()
            .find_map(|channel| match channel.frequency_mhz {
                2_400..=2_500 => Some(WifiBand::Ghz2),
                4_900..=5_900 => Some(WifiBand::Ghz5),
                _ => None,
            });
        let Some(band_kind) = band_kind else { continue };
        let entry = bands
            .entry(band_kind)
            .or_insert_with(WifiBandCapabilities::default);
        entry.ht40 |= raw.ht40;
        entry.vht80 |= raw.vht;
        for channel in raw.frequencies {
            if matches!(
                (band_kind, channel.frequency_mhz),
                (WifiBand::Ghz2, 2_400..=2_500) | (WifiBand::Ghz5, 4_900..=5_900)
            ) {
                entry.channels.insert(channel.channel, channel);
            }
        }
    }

    if bands.is_empty() {
        return Err(RadioError::Parse {
            message: format!("{phy} contains no 2.4/5 GHz frequency information"),
        });
    }

    Ok(WifiPhyCapabilities {
        phy: phy.to_string(),
        phy_index: wiphy_index,
        supports_ap,
        bands,
    })
}

fn parse_frequency_line(line: &str) -> Option<WifiChannel> {
    let rest = line.strip_prefix('*')?.trim_start();
    let mut fields = rest.split_whitespace();
    let value = fields.next()?;
    if fields.next()? != "MHz" {
        return None;
    }
    // iw also prints whole-MHz channels with decimal precision (2412.0).
    // Reject fractional MHz instead of silently rounding to another frequency.
    let whole = match value.split_once('.') {
        Some((whole, fraction))
            if !fraction.is_empty() && fraction.bytes().all(|byte| byte == b'0') =>
        {
            whole
        }
        Some(_) => return None,
        None => value,
    };
    let frequency = whole.parse::<u32>().ok()?;
    let open = rest.find('[')?;
    let close = rest[open + 1..].find(']')? + open + 1;
    let channel = rest[open + 1..close].parse::<u8>().ok()?;
    let lower = rest.to_ascii_lowercase();
    Some(WifiChannel {
        frequency_mhz: frequency,
        channel,
        disabled: lower.contains("disabled"),
        no_ir: lower.contains("no ir") || lower.contains("no-ir"),
        radar: lower.contains("radar"),
        no_ht40_plus: lower.contains("no ht40+"),
        no_ht40_minus: lower.contains("no ht40-"),
        no_80mhz: lower.contains("no 80mhz") || lower.contains("no 80 mhz"),
    })
}

fn parse_reg_domains(text: &str) -> RegulatoryDomain {
    enum Scope {
        Global,
        Phy(u32, bool),
    }
    let mut result = RegulatoryDomain::default();
    let mut scope = Scope::Global;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "global" {
            scope = Scope::Global;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("phy#") {
            let digits: String = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect();
            if let Ok(index) = digits.parse::<u32>() {
                scope = Scope::Phy(index, trimmed.contains("self-managed"));
            }
            continue;
        }
        let Some(country) = trimmed.strip_prefix("country ") else {
            continue;
        };
        let Some(code) = country.get(..2) else {
            continue;
        };
        if code != "00" && !code.bytes().all(|byte| byte.is_ascii_uppercase()) {
            continue;
        }
        match scope {
            Scope::Global => result.global_country = Some(code.to_string()),
            Scope::Phy(index, self_managed) => {
                result
                    .per_phy
                    .insert(index, (code.to_string(), self_managed));
            }
        }
    }
    result
}

fn ht40_above(band: WifiBand, channel: u8) -> bool {
    match band {
        WifiBand::Ghz2 => channel <= 7,
        WifiBand::Ghz5 => (channel.saturating_sub(36) / 4).is_multiple_of(2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WifiSecurity;

    const PHY: &str = r#"
Wiphy phy0
    wiphy index: 0
    Supported interface modes:
         * managed
         * AP
    Band 1:
        Capabilities: 0x19e7
            HT20/HT40
        Frequencies:
            * 2412 MHz [1] (20.0 dBm)
            * 2432 MHz [5] (20.0 dBm)
            * 2437 MHz [6] (20.0 dBm) (no HT40+)
            * 2452 MHz [9] (20.0 dBm)
            * 2462 MHz [11] (20.0 dBm)
            * 2472 MHz [13] (20.0 dBm) (no IR)
    Band 2:
        Capabilities: 0x1863
            HT20/HT40
        VHT Capabilities (0x339071b2):
        Frequencies:
            * 5180 MHz [36] (23.0 dBm)
            * 5200 MHz [40] (23.0 dBm)
            * 5220 MHz [44] (23.0 dBm)
            * 5240 MHz [48] (23.0 dBm)
            * 5260 MHz [52] (23.0 dBm) (no IR)
            * 5280 MHz [56] (23.0 dBm)
            * 5300 MHz [60] (23.0 dBm)
            * 5320 MHz [64] (23.0 dBm)
"#;

    fn spec(band: WifiBand, channel: u8, width: WifiChannelWidth) -> WifiApSpec {
        WifiApSpec {
            interface: "wlan0".into(),
            ssid: "test".into(),
            country_code: Some("PL".into()),
            band,
            channel,
            channel_width: width,
            security: WifiSecurity::Open,
            hidden: false,
            client_isolation: false,
            max_stations: 8,
            passphrase_file: None,
        }
    }

    fn capabilities() -> (WifiPhyCapabilities, RegulatoryDomain) {
        (
            parse_phy_info("phy0", PHY).expect("parse phy"),
            parse_reg_domains("global\ncountry PL: DFS-ETSI\n"),
        )
    }

    #[test]
    fn parses_actual_decimal_iw_output() {
        let caps = parse_phy_info("phy0", include_str!("fixtures/iw-phy-decimal.txt"))
            .expect("decimal MHz output from iw must be accepted");
        assert!(caps.supports_ap);
        let band = &caps.bands[&WifiBand::Ghz2];
        assert_eq!(band.channels.len(), 14);
        assert_eq!(band.channels[&1].frequency_mhz, 2412);
        assert!(band.channels[&14].disabled);
        assert!(caps.bands[&WifiBand::Ghz5].channels[&52].no_ir);
        assert!(caps.bands[&WifiBand::Ghz5].channels[&52].radar);
        let reg = parse_reg_domains(
            "global\ncountry 00: DFS-UNSET\nphy#0 (self-managed)\ncountry 00: DFS-UNSET\n",
        );
        caps.validate(&spec(WifiBand::Ghz2, 1, WifiChannelWidth::Ht20), &reg)
            .expect("usable 2.4 GHz AP channel");
        assert!(caps
            .validate(&spec(WifiBand::Ghz5, 36, WifiChannelWidth::Ht20), &reg)
            .expect_err("self-managed world-domain no-IR must be respected")
            .to_string()
            .contains("no-IR"));
    }

    #[test]
    fn frequency_formats_preserve_restrictions() {
        for frequency in ["2412", "2412.0", "2412.000"] {
            let line = format!("* {frequency} MHz [1] (no IR) (no HT40+) (no HT40-) (no 80MHz)");
            let channel = parse_frequency_line(&line).expect("valid frequency");
            assert_eq!(channel.frequency_mhz, 2412);
            assert!(
                channel.no_ir && channel.no_ht40_plus && channel.no_ht40_minus && channel.no_80mhz
            );
        }
        for line in [
            "* 2412.5 MHz [1]",
            "* NaN MHz [1]",
            "* 2412. MHz [1]",
            "* 2412 kHz [1]",
        ] {
            assert!(parse_frequency_line(line).is_none(), "{line}");
        }
    }

    #[test]
    fn preserves_self_managed_world_regdomain() {
        let reg = parse_reg_domains(
            "global\ncountry PL: DFS-ETSI\nphy#0 (self-managed)\ncountry 00: DFS-UNSET\n",
        );
        assert_eq!(reg.per_phy.get(&0), Some(&("00".to_string(), true)));
        let (caps, _) = capabilities();
        assert!(caps
            .validate(&spec(WifiBand::Ghz2, 13, WifiChannelWidth::Ht20), &reg)
            .is_err());
        assert_eq!(
            parse_reg_domains("country 00: DFS-UNSET")
                .global_country
                .as_deref(),
            Some("00")
        );
    }

    #[test]
    fn normalizes_phy_capability_facts() {
        let (caps, _) = capabilities();
        assert_eq!(caps.phy, "phy0");
        assert_eq!(caps.phy_index, Some(0));
        assert!(caps.supports_ap);

        let band = caps.bands.get(&WifiBand::Ghz5).expect("5 GHz band");
        assert!(band.ht40);
        assert!(band.vht80);
        let channel = band.channels.get(&36).expect("channel 36");
        assert_eq!(channel.frequency_mhz, 5180);
        assert_eq!(channel.channel, 36);
        assert!(!channel.disabled);
        assert!(!channel.no_ir);
    }

    #[test]
    fn normalizes_global_and_self_managed_regdomains() {
        let reg = parse_reg_domains(
            "global\ncountry PL: DFS-ETSI\nphy#0 (self-managed)\ncountry US: DFS-UNSET\n",
        );
        assert_eq!(reg.global_country.as_deref(), Some("PL"));
        assert_eq!(reg.per_phy.get(&0), Some(&("US".to_string(), true)));
    }

    #[test]
    fn rejects_no_ir_channel_before_hostapd() {
        let (caps, reg) = capabilities();
        let error = caps
            .validate(&spec(WifiBand::Ghz2, 13, WifiChannelWidth::Ht20), &reg)
            .expect_err("no-IR channel must be rejected");
        assert!(error.to_string().contains("no-IR"));
    }

    #[test]
    fn rejects_ht40_direction_forbidden_by_phy() {
        let (caps, reg) = capabilities();
        let error = caps
            .validate(&spec(WifiBand::Ghz2, 6, WifiChannelWidth::Ht40), &reg)
            .expect_err("HT40+ is forbidden on channel 6");
        assert!(error.to_string().contains("HT40+"));
    }

    #[test]
    fn accepts_vht80_only_when_the_whole_block_is_available() {
        let (caps, reg) = capabilities();
        caps.validate(&spec(WifiBand::Ghz5, 36, WifiChannelWidth::Vht80), &reg)
            .expect("36-48 is a complete usable 80 MHz block");

        let error = caps
            .validate(&spec(WifiBand::Ghz5, 52, WifiChannelWidth::Vht80), &reg)
            .expect_err("52 is no-IR in the effective regdomain");
        assert!(error.to_string().contains("no-IR"));
    }

    #[test]
    fn country_change_does_not_false_reject_using_the_old_global_regdomain() {
        let (caps, _) = capabilities();
        let reg = parse_reg_domains("global\ncountry US: DFS-FCC\n");
        caps.validate(&spec(WifiBand::Ghz2, 13, WifiChannelWidth::Ht20), &reg)
            .expect("hostapd will apply PL; old global no-IR flags are not authoritative");
    }

    #[test]
    fn self_managed_phy_flags_are_always_authoritative() {
        let (caps, _) = capabilities();
        let reg = parse_reg_domains(
            "global\ncountry US: DFS-FCC\nphy#0 (self-managed)\ncountry US: DFS-UNSET\n",
        );
        let error = caps
            .validate(&spec(WifiBand::Ghz2, 13, WifiChannelWidth::Ht20), &reg)
            .expect_err("self-managed PHY keeps its own regulatory restrictions");
        assert!(error.to_string().contains("no-IR"));
    }
}
