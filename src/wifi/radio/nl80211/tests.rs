use super::*;
use wl_nl80211::{
    packet_core::{DefaultNla, DoneMessage},
    Ieee80211VhtCapInfo, Nl80211Band, Nl80211Frequency,
};

fn done(code: i32) -> NetlinkMessage<GenlMessage<Nl80211Message>> {
    let mut message = DoneMessage::default();
    message.code = code;
    NetlinkMessage::new(Default::default(), NetlinkPayload::Done(message))
}

#[test]
fn partial_or_failed_dumps_are_never_accepted() {
    let fragment = NetlinkMessage::from(GenlMessage::from_payload(Nl80211Message {
        cmd: Nl80211Command::NewWiphy,
        attributes: split_phy()[0].clone(),
    }));
    let mut dump = DumpAccumulator::default();
    dump.push(fragment.clone()).unwrap();
    assert!(dump.finish().is_err());
    let mut interrupted_done = done(0);
    interrupted_done.header.flags |= NLM_F_DUMP_INTR;
    for terminal in [done(-5), interrupted_done] {
        let mut dump = DumpAccumulator::default();
        dump.push(fragment.clone()).unwrap();
        assert!(dump.push(terminal).is_err());
    }
    let mut interrupted = fragment;
    interrupted.header.flags |= NLM_F_DUMP_INTR;
    assert!(DumpAccumulator::default().push(interrupted).is_err());
    assert!(DumpAccumulator::default()
        .push(NetlinkMessage::new(
            Default::default(),
            NetlinkPayload::Overrun(vec![])
        ))
        .is_err());
}

#[test]
fn successful_dump_requires_terminal_message() {
    let mut dump = DumpAccumulator::default();
    dump.push(NetlinkMessage::from(GenlMessage::from_payload(
        Nl80211Message {
            cmd: Nl80211Command::NewWiphy,
            attributes: split_phy()[0].clone(),
        },
    )))
    .unwrap();
    dump.push(done(0)).unwrap();
    assert_eq!(dump.finish().unwrap(), vec![split_phy()[0].clone()]);
}

fn frequency(index: u16, mhz: u32, flags: Vec<Nl80211FrequencyInfo>) -> Nl80211Frequency {
    let mut info = vec![Nl80211FrequencyInfo::Freq(mhz)];
    info.extend(flags);
    Nl80211Frequency { index, info }
}

fn band(kind: Nl80211BandType, info: Vec<Nl80211BandInfo>) -> Nl80211Attr {
    Nl80211Attr::WiphyBands(vec![Nl80211Band { kind, info }])
}

fn split_phy() -> Vec<Vec<Nl80211Attr>> {
    use Nl80211FrequencyInfo::*;
    vec![
        vec![
            Nl80211Attr::Wiphy(0),
            Nl80211Attr::SupportedIftypes(vec![Nl80211IfMode::Station, Nl80211IfMode::Ap]),
        ],
        vec![
            Nl80211Attr::Wiphy(0),
            band(
                Nl80211BandType::Band2GHz,
                vec![Nl80211BandInfo::HtCapa(Ieee80211HtCaps::SupWidth2040)],
            ),
        ],
        vec![
            Nl80211Attr::Wiphy(0),
            band(
                Nl80211BandType::Band2GHz,
                vec![Nl80211BandInfo::Freqs(vec![
                    frequency(1, 2412, vec![]),
                    frequency(2, 2432, vec![]),
                    frequency(3, 2437, vec![NoHt40Plus]),
                    frequency(4, 2452, vec![]),
                    frequency(5, 2462, vec![]),
                    frequency(6, 2472, vec![NoIr]),
                ])],
            ),
        ],
        vec![
            Nl80211Attr::Wiphy(0),
            band(
                Nl80211BandType::Band5GHz,
                vec![
                    Nl80211BandInfo::HtCapa(Ieee80211HtCaps::SupWidth2040),
                    Nl80211BandInfo::VhtCap(Ieee80211VhtCapInfo::empty()),
                    Nl80211BandInfo::Freqs(vec![
                        frequency(1, 5180, vec![]),
                        frequency(2, 5200, vec![]),
                    ]),
                ],
            ),
        ],
        vec![
            Nl80211Attr::Wiphy(0),
            band(
                Nl80211BandType::Band5GHz,
                vec![Nl80211BandInfo::Freqs(vec![
                    frequency(3, 5220, vec![]),
                    frequency(4, 5240, vec![]),
                    frequency(5, 5260, vec![NoIr]),
                    frequency(6, 5280, vec![]),
                    frequency(7, 5300, vec![]),
                    frequency(8, 5320, vec![]),
                ])],
            ),
        ],
    ]
}

#[test]
fn split_dump_matches_previous_iw_normalization() {
    let expected = super::super::parse_phy_info("phy0", super::super::tests::PHY).unwrap();
    assert_eq!(parse_phy_dump("phy0", 0, &split_phy()).unwrap(), expected);
}

#[test]
fn incomplete_or_wrong_phy_dump_is_rejected() {
    assert!(parse_phy_dump("phy0", 0, &[]).is_err());
    let messages = split_phy();
    assert!(parse_phy_dump("phy0", 0, &messages[..2]).is_err());
    assert!(parse_phy_dump("phy0", 0, &messages[1..]).is_err());
    assert!(parse_phy_dump("phy1", 1, &messages).is_err());
    let mut renamed = messages.clone();
    renamed[0].push(Nl80211Attr::WiphyName("another-radio".into()));
    assert!(parse_phy_dump("phy0", 0, &renamed).is_err());
    let mut messages = messages;
    messages[1].remove(0);
    assert!(parse_phy_dump("phy0", 0, &messages).is_err());
}

#[test]
fn duplicate_fragments_cannot_erase_restrictions() {
    use Nl80211FrequencyInfo::*;
    let mut band = WifiBandCapabilities::default();
    merge_frequency(
        &mut band,
        WifiBand::Ghz5,
        &[
            Freq(5180),
            Disabled,
            NoIbss,
            Radar,
            NoHt40Plus,
            NoHt40Minus,
            No80Mhz,
        ],
    )
    .unwrap();
    merge_frequency(&mut band, WifiBand::Ghz5, &[Freq(5180)]).unwrap();
    let channel = &band.channels[&36];
    assert!(
        channel.disabled
            && channel.no_ir
            && channel.radar
            && channel.no_ht40_plus
            && channel.no_ht40_minus
            && channel.no_80mhz
    );
}

#[test]
fn malformed_or_unknown_frequency_information_is_rejected() {
    use Nl80211FrequencyInfo::*;
    for attributes in [
        vec![Disabled],
        vec![Freq(2412), Freq(2437)],
        vec![Freq(2413)],
        vec![Freq(2412), Offset(100)],
        vec![Freq(2412), Other(DefaultNla::new(1000, vec![]))],
    ] {
        assert!(merge_frequency(
            &mut WifiBandCapabilities::default(),
            WifiBand::Ghz2,
            &attributes
        )
        .is_err());
    }
}

#[test]
fn special_channels_and_no_20mhz_are_preserved() {
    use Nl80211FrequencyInfo::*;
    let mut band = WifiBandCapabilities::default();
    merge_frequency(&mut band, WifiBand::Ghz2, &[Freq(2484), No20Mhz]).unwrap();
    assert!(band.channels[&14].disabled);
    let mut band = WifiBandCapabilities::default();
    merge_frequency(&mut band, WifiBand::Ghz5, &[Freq(4920)]).unwrap();
    assert_eq!(band.channels[&184].frequency_mhz, 4920);
}

#[test]
fn driver_channels_outside_configured_frequency_windows_are_omitted() {
    use Nl80211FrequencyInfo::*;
    let mut band = WifiBandCapabilities::default();
    merge_frequency(&mut band, WifiBand::Ghz5, &[Freq(5905), Disabled]).unwrap();
    merge_frequency(&mut band, WifiBand::Ghz5, &[Freq(5180)]).unwrap();
    assert_eq!(band.channels.len(), 1);
    assert!(band.channels.contains_key(&36));
}

fn country(code: &[u8]) -> Nl80211Attr {
    Nl80211Attr::Other(DefaultNla::new(REG_ALPHA2, code.to_vec()))
}

#[test]
fn global_and_self_managed_domains_match_iw() {
    let native = parse_reg_dump(&[
        vec![country(b"PL\0")],
        vec![
            Nl80211Attr::Wiphy(0),
            country(b"00"),
            Nl80211Attr::WiphySelfManagedReg,
        ],
    ])
    .unwrap();
    let previous = super::super::parse_reg_domains(
        "global\ncountry PL: DFS-ETSI\nphy#0 (self-managed)\ncountry 00: DFS-UNSET\n",
    );
    assert_eq!(native, previous);
}

#[test]
fn malformed_or_incomplete_regulatory_dump_is_rejected() {
    for messages in [
        vec![],
        vec![vec![]],
        vec![vec![country(b"P")]],
        vec![vec![country(b"pl")]],
        vec![vec![country(b"PL"), country(b"US")]],
        vec![vec![country(b"PL")], vec![country(b"US")]],
        vec![vec![country(b"PL"), Nl80211Attr::WiphySelfManagedReg]],
        vec![vec![country(b"PL"), Nl80211Attr::Wiphy(0)]],
    ] {
        assert!(parse_reg_dump(&messages).is_err());
    }
}

#[tokio::test]
async fn non_wireless_interface_reports_not_wireless() {
    let error = Nl80211CapabilitiesProvider.phy("lo").await.unwrap_err();
    assert!(matches!(error, RadioError::NotWireless { .. }));
}

#[tokio::test]
async fn dropping_probe_aborts_connection_task() {
    let task = tokio::spawn(std::future::pending::<()>());
    let abort = task.abort_handle();
    drop(ProbeConnection(task));
    tokio::task::yield_now().await;
    assert!(abort.is_finished());
}

#[tokio::test]
#[ignore = "read-only hardware comparison; set TRAFFIC_MASQ_NL80211_INTERFACE and optionally TRAFFIC_MASQ_IW_BINARY"]
async fn native_probe_matches_iw_on_selected_radio() {
    let interface =
        std::env::var("TRAFFIC_MASQ_NL80211_INTERFACE").expect("select an interface explicitly");
    let iw = std::env::var("TRAFFIC_MASQ_IW_BINARY").unwrap_or_else(|_| "/usr/sbin/iw".into());
    let native = Nl80211CapabilitiesProvider
        .phy(&interface)
        .await
        .expect("native PHY probe");
    let output = crate::command::run(
        std::path::Path::new(&iw),
        &["phy", &native.phy, "info"],
        &[],
        PROBE_TIMEOUT,
    )
    .await
    .expect("iw PHY probe");
    let previous =
        super::super::parse_phy_info(&native.phy, std::str::from_utf8(&output).unwrap()).unwrap();
    let output = crate::command::run(
        std::path::Path::new(&iw),
        &["phy", &native.phy, "channels"],
        &[],
        PROBE_TIMEOUT,
    )
    .await
    .expect("iw channel width probe");
    let widths = iw_channel_widths(std::str::from_utf8(&output).unwrap());
    let mut projected = native.clone();
    for (kind, band) in &mut projected.bands {
        for (number, channel) in &mut band.channels {
            let old = &previous.bands[kind].channels[number];
            if !channel.disabled {
                assert_eq!(
                    widths.get(&channel.frequency_mhz),
                    Some(&(
                        channel.no_ht40_plus,
                        channel.no_ht40_minus,
                        channel.no_80mhz
                    )),
                    "width restrictions at {} MHz",
                    channel.frequency_mhz,
                );
            } else {
                // iw omits other flags entirely on disabled channels.
                channel.no_ir = old.no_ir;
                channel.radar = old.radar;
            }
            // iw info omits width flags; checked independently using channels.
            channel.no_ht40_plus = old.no_ht40_plus;
            channel.no_ht40_minus = old.no_ht40_minus;
            channel.no_80mhz = old.no_80mhz;
        }
    }
    assert_eq!(projected, previous);
    let native = Nl80211CapabilitiesProvider
        .regulatory_domain()
        .await
        .expect("native regulatory probe");
    let output = crate::command::run(
        std::path::Path::new(&iw),
        &["reg", "get"],
        &[],
        PROBE_TIMEOUT,
    )
    .await
    .expect("iw regulatory probe");
    assert_eq!(
        native,
        super::super::parse_reg_domains(std::str::from_utf8(&output).unwrap())
    );
}

fn iw_channel_widths(text: &str) -> std::collections::HashMap<u32, (bool, bool, bool)> {
    let mut result = std::collections::HashMap::new();
    let mut frequency = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('*') {
            frequency =
                super::super::parse_frequency_line(line).map(|channel| channel.frequency_mhz);
        } else if let Some(widths) = line.strip_prefix("Channel widths:") {
            let tokens: Vec<_> = widths.split_whitespace().collect();
            result.insert(
                frequency.expect("widths belong to a frequency"),
                (
                    !tokens.contains(&"HT40+"),
                    !tokens.contains(&"HT40-"),
                    !tokens.contains(&"VHT80"),
                ),
            );
        }
    }
    result
}

#[test]
fn iw_channel_listing_supplies_width_flags_missing_from_info() {
    let widths = iw_channel_widths("Band 1:\n * 2412 MHz [1]\n Channel widths: 20MHz HT40+\n * 2484 MHz [14] (disabled)\nBand 2:\n * 5180 MHz [36]\n Channel widths: 20MHz HT40- VHT80 VHT160\n");
    assert_eq!(widths.get(&2412), Some(&(false, true, true)));
    assert_eq!(widths.get(&5180), Some(&(true, false, false)));
    assert!(!widths.contains_key(&2484));
}
