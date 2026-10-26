//! Explicit AP/STA pairing and owned virtual-interface lifecycle.
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use wl_nl80211::{
    Nl80211Attr, Nl80211Command, Nl80211IfaceCombAttribute as Comb,
    Nl80211IfaceCombLimitAttribute as Limit, Nl80211InterfaceType as Kind,
};

use super::radio::nl80211::dump;
use crate::config::{InterfaceConfig, NetworkConfig, WifiBand, WifiChannelWidth};

pub(crate) use traffic_masq_protocol::concurrent_ap_name as ap_name;

pub(crate) fn parent_for<'a>(network: &'a NetworkConfig, ap: &str) -> Option<&'a str> {
    network.interfaces.iter().find_map(|(name, config)| {
        (config.wifi_concurrent && ap_name(name) == ap).then_some(name.as_str())
    })
}

// Alternatives must be evaluated separately; a combined AP/STA limit of one
// does not permit two interfaces even though both types appear in the list.
fn supports_pair(attrs: &[Comb]) -> bool {
    let mut total = None;
    let mut channels = None;
    let mut limits = None;
    for attr in attrs {
        match attr {
            Comb::Maxnum(value) if total.is_none() => total = Some(*value),
            Comb::NumChannels(value) if channels.is_none() => channels = Some(*value),
            Comb::Limits(value) if limits.is_none() => limits = Some(value),
            // These require beacon interval coordination, which is not yet
            // implemented. Do not advertise support we cannot safely satisfy.
            Comb::StaApiBiMatch | Comb::BiMinGcd(_) | Comb::Other(_) => return false,
            Comb::RadarDetectWidths(_) | Comb::RadarDetectRegins(_) => {}
            _ => return false,
        }
    }
    if total.is_none_or(|n| n < 2) || channels.is_none_or(|n| n < 1) {
        return false;
    }
    let Some(limits) = limits else {
        return false;
    };
    let mut station = false;
    let mut ap = false;
    for limit in limits {
        let mut maximum = None;
        let mut kinds = None;
        for attr in &limit.attributes {
            match attr {
                Limit::Max(n) if maximum.is_none() => maximum = Some(*n),
                Limit::Iftypes(types) if kinds.is_none() => kinds = Some(types),
                _ => return false,
            }
        }
        let (Some(maximum), Some(kinds)) = (maximum, kinds) else {
            return false;
        };
        let has_station = kinds.contains(&Kind::Station);
        let has_ap = kinds.contains(&Kind::Ap);
        if u32::from(has_station) + u32::from(has_ap) > maximum {
            return false;
        }
        // Overlapping groups are malformed; don't double-count a type.
        if (station && has_station) || (ap && has_ap) {
            return false;
        }
        station |= has_station;
        ap |= has_ap;
    }
    station && ap
}

async fn phy_index(parent: &str) -> Result<u32> {
    crate::config::validate_interface_name(parent)?;
    tokio::fs::read_to_string(
        Path::new("/sys/class/net")
            .join(parent)
            .join("phy80211/index"),
    )
    .await
    .context("Input + Output requires a present Wi-Fi adapter")?
    .trim()
    .parse()
    .context("invalid wireless PHY index")
}

pub(crate) async fn validate(parent: &str) -> Result<u32> {
    let index = phy_index(parent).await?;
    let messages = dump(
        Nl80211Command::GetWiphy,
        vec![Nl80211Attr::Wiphy(index), Nl80211Attr::SplitWiphyDump],
    )
    .await?;
    let supported = messages
        .iter()
        .filter(|attrs| attrs.contains(&Nl80211Attr::Wiphy(index)))
        .flat_map(|attrs| attrs.iter())
        .any(|attr| match attr {
            Nl80211Attr::InterfaceCombination(combinations) => {
                combinations.iter().any(|c| supports_pair(&c.attributes))
            }
            _ => false,
        });
    ensure!(supported, "{parent}: driver does not advertise a supported simultaneous AP + station combination (beacon-interval constraints are currently unsupported)");
    Ok(index)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedAp {
    parent: String,
    mac: [u8; 6],
}

fn record_path(root: &Path, parent: &str) -> PathBuf {
    root.join("wifi-concurrent")
        .join(format!("{}.json", ap_name(parent)))
}

async fn load(root: &Path, parent: &str) -> Result<Option<OwnedAp>> {
    let path = record_path(root, parent);
    if !traffic_masq_atomic_file::regular_file_exists(&path)? {
        return Ok(None);
    }
    let record: OwnedAp = serde_json::from_slice(&tokio::fs::read(&path).await?)?;
    ensure!(
        record.parent == parent,
        "virtual AP name collision for {parent}"
    );
    Ok(Some(record))
}

pub(crate) async fn has_record(root: &Path, parent: &str) -> Result<bool> {
    Ok(load(root, parent).await?.is_some())
}

async fn observed_mac(name: &str) -> Result<Option<[u8; 6]>> {
    match tokio::fs::read_to_string(Path::new("/sys/class/net").join(name).join("address")).await {
        Ok(value) => Ok(Some(
            value
                .trim()
                .parse::<traffic_masq_protocol::MacAddr>()?
                .octets(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

struct Connection(tokio::task::JoinHandle<()>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn create(index: u32, name: &str, mac: [u8; 6]) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (connection, handle, _) = wl_nl80211::new_connection()?;
        let _connection = Connection(tokio::spawn(connection));
        let mut replies = handle
            .interface()
            .add(vec![
                Nl80211Attr::Wiphy(index),
                Nl80211Attr::IfName(name.into()),
                Nl80211Attr::IfType(Kind::Ap),
                Nl80211Attr::Mac(mac),
            ])
            .execute()
            .await;
        while replies.try_next().await?.is_some() {}
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("creating virtual AP timed out")??;
    Ok(())
}

/// Called under the parent's radio/runtime reservations. The durable random MAC
/// proves ownership after a crash; a pre-existing foreign interface is refused.
pub(crate) async fn ensure_ap(root: &Path, parent: &str) -> Result<()> {
    let index = validate(parent).await?;
    let name = ap_name(parent);
    let existing = observed_mac(&name).await?;
    let record = match load(root, parent).await? {
        Some(record) => record,
        None => {
            ensure!(
                existing.is_none(),
                "virtual AP name {name} is already occupied"
            );
            let mut mac: [u8; 6] = rand::random();
            mac[0] = (mac[0] & 0xfc) | 0x02;
            let record = OwnedAp {
                parent: parent.into(),
                mac,
            };
            let path = record_path(root, parent);
            traffic_masq_atomic_file::ensure_private_dir(path.parent().unwrap(), 0o700)?;
            traffic_masq_atomic_file::replace_async(&path, &serde_json::to_vec(&record)?, 0o600)
                .await?;
            record
        }
    };
    if let Some(mac) = existing {
        ensure!(
            mac == record.mac && phy_index(&name).await? == index,
            "{name} is not the owned virtual AP; refusing to modify it"
        );
    } else {
        create(index, &name, record.mac).await?;
        ensure!(
            observed_mac(&name).await? == Some(record.mac),
            "driver did not preserve virtual AP identity"
        );
    }
    Ok(())
}

/// Services must be disabled before removing the virtual link.
pub(crate) async fn remove_ap(root: &Path, parent: &str) -> Result<()> {
    let Some(record) = load(root, parent).await? else {
        return Ok(());
    };
    let name = ap_name(parent);
    if let Some(mac) = observed_mac(&name).await? {
        ensure!(
            mac == record.mac,
            "{name} ownership changed; refusing to delete it"
        );
        let index: u32 =
            tokio::fs::read_to_string(Path::new("/sys/class/net").join(&name).join("ifindex"))
                .await?
                .trim()
                .parse()?;
        tokio::time::timeout(Duration::from_secs(10), async {
            let (connection, handle, _) = wl_nl80211::new_connection()?;
            let _connection = Connection(tokio::spawn(connection));
            let mut replies = handle
                .interface()
                .delete(vec![Nl80211Attr::IfIndex(index)])
                .execute()
                .await;
            while replies.try_next().await?.is_some() {}
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("deleting virtual AP timed out")??;
    }
    traffic_masq_atomic_file::remove_durable_async(&record_path(root, parent)).await?;
    Ok(())
}

pub(crate) fn follow_channel(config: &mut InterfaceConfig, frequency: u32) -> Result<()> {
    let (band, channel) = channel_for(frequency)?;
    if let Some(ap) = config.wifi.as_mut() {
        ap.band = band;
        ap.channel = channel;
        ap.channel_width = WifiChannelWidth::Ht20;
    }
    Ok(())
}

pub(crate) fn channel_for(frequency: u32) -> Result<(WifiBand, u8)> {
    let channel = match frequency {
        2484 => (WifiBand::Ghz2, 14),
        2412..=2472 if (frequency - 2407).is_multiple_of(5) => {
            (WifiBand::Ghz2, ((frequency - 2407) / 5) as u8)
        }
        5005..=5900 if (frequency - 5000).is_multiple_of(5) => {
            (WifiBand::Ghz5, ((frequency - 5000) / 5) as u8)
        }
        _ => bail!("upstream frequency {frequency} MHz cannot be used for the virtual AP"),
    };
    Ok(channel)
}

pub(crate) async fn recorded_parents(root: &Path) -> Result<Vec<String>> {
    let mut entries = match tokio::fs::read_dir(root.join("wifi-concurrent")).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut parents = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        if entry.path().extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        ensure!(
            entry.file_type().await?.is_file(),
            "invalid virtual AP ownership record"
        );
        let record: OwnedAp = serde_json::from_slice(&tokio::fs::read(entry.path()).await?)?;
        crate::config::validate_interface_name(&record.parent)?;
        ensure!(
            entry.path() == record_path(root, &record.parent),
            "virtual AP record name mismatch"
        );
        parents.push(record.parent);
    }
    Ok(parents)
}

pub(crate) async fn owned_parent(root: &Path, ap: &str) -> Result<Option<String>> {
    crate::config::validate_interface_name(ap)?;
    let path = root.join("wifi-concurrent").join(format!("{ap}.json"));
    if !traffic_masq_atomic_file::regular_file_exists(&path)? {
        return Ok(None);
    }
    let record: OwnedAp = serde_json::from_slice(&tokio::fs::read(path).await?)?;
    crate::config::validate_interface_name(&record.parent)?;
    ensure!(
        ap_name(&record.parent) == ap && observed_mac(ap).await? == Some(record.mac),
        "virtual AP ownership does not match {ap}"
    );
    ensure!(
        phy_index(ap).await? == phy_index(&record.parent).await?,
        "virtual AP is on a different PHY"
    );
    Ok(Some(record.parent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_nl80211::packet_core::{NlaBuffer, ParseableParametrized};
    use wl_nl80211::Nl80211IfaceCombLimit;

    fn nla(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
        bytes
    }

    fn limit(max: u32, types: &[u16]) -> Nl80211IfaceCombLimit {
        let mut attrs = nla(1, &max.to_ne_bytes());
        let types: Vec<u8> = types.iter().flat_map(|kind| nla(*kind, &[])).collect();
        attrs.extend(nla(2, &types));
        let bytes = nla(1, &attrs);
        Nl80211IfaceCombLimit::parse_with_param(&NlaBuffer::new(&bytes), 0).unwrap()
    }

    fn pair() -> Vec<Comb> {
        vec![
            Comb::Maxnum(2),
            Comb::NumChannels(1),
            Comb::Limits(vec![limit(1, &[2]), limit(1, &[3])]),
        ]
    }

    #[test]
    fn checks_total_and_shared_limits_in_one_alternative() {
        assert!(supports_pair(&pair()));
        assert!(!supports_pair(&[
            Comb::Maxnum(2),
            Comb::NumChannels(1),
            Comb::Limits(vec![limit(1, &[2, 3])])
        ]));
        assert!(supports_pair(&[
            Comb::Maxnum(2),
            Comb::NumChannels(1),
            Comb::Limits(vec![limit(2, &[2, 3])])
        ]));
        let mut attrs = pair();
        attrs[0] = Comb::Maxnum(1);
        assert!(!supports_pair(&attrs));
        attrs = pair();
        attrs[1] = Comb::NumChannels(0);
        assert!(!supports_pair(&attrs));
        assert!(!supports_pair(&[
            Comb::Maxnum(2),
            Comb::NumChannels(1),
            Comb::Limits(vec![limit(2, &[2])])
        ]));
    }

    #[test]
    fn rejects_missing_duplicate_and_unimplemented_constraints() {
        assert!(!supports_pair(&[]));
        let mut attrs = pair();
        attrs.push(Comb::Maxnum(4));
        assert!(!supports_pair(&attrs));
        attrs = pair();
        attrs.push(Comb::StaApiBiMatch);
        assert!(!supports_pair(&attrs));
        attrs = pair();
        attrs.push(Comb::BiMinGcd(100));
        assert!(!supports_pair(&attrs));
    }

    #[test]
    fn channels_follow_supported_frequencies_without_rounding() {
        assert_eq!(channel_for(2412).unwrap(), (WifiBand::Ghz2, 1));
        assert_eq!(channel_for(2484).unwrap(), (WifiBand::Ghz2, 14));
        assert_eq!(channel_for(5180).unwrap(), (WifiBand::Ghz5, 36));
        assert!(channel_for(5181).is_err());
        assert!(channel_for(5955).is_err());
    }

    #[tokio::test]
    async fn ownership_records_survive_restart_and_absent_link_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let parent = "absent-wifi0";
        let path = record_path(dir.path(), parent);
        traffic_masq_atomic_file::ensure_private_dir(path.parent().unwrap(), 0o700).unwrap();
        let record = OwnedAp {
            parent: parent.into(),
            mac: [2, 1, 2, 3, 4, 5],
        };
        traffic_masq_atomic_file::replace_async(
            &path,
            &serde_json::to_vec(&record).unwrap(),
            0o600,
        )
        .await
        .unwrap();
        assert_eq!(recorded_parents(dir.path()).await.unwrap(), vec![parent]);
        assert_eq!(
            load(dir.path(), parent).await.unwrap().unwrap().mac,
            record.mac
        );
        // No matching device means it cannot be adopted as an owned live AP.
        assert!(owned_parent(dir.path(), &ap_name(parent)).await.is_err());
        remove_ap(dir.path(), parent).await.unwrap();
        assert!(recorded_parents(dir.path()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn name_collision_and_symlink_records_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = record_path(dir.path(), "wlan0");
        traffic_masq_atomic_file::ensure_private_dir(path.parent().unwrap(), 0o700).unwrap();
        let record = OwnedAp {
            parent: "other0".into(),
            mac: [2, 1, 2, 3, 4, 5],
        };
        traffic_masq_atomic_file::replace_async(
            &path,
            &serde_json::to_vec(&record).unwrap(),
            0o600,
        )
        .await
        .unwrap();
        assert!(load(dir.path(), "wlan0").await.is_err());
        assert!(recorded_parents(dir.path()).await.is_err());
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(dir.path().join("foreign"), &path).unwrap();
        assert!(load(dir.path(), "wlan0").await.is_err());
    }
}
