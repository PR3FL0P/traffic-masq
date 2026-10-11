//! Observe radio blocks without changing rfkill state or requiring its CLI.
use std::path::Path;

pub(crate) async fn check_radio_unblocked(interface: &str) -> anyhow::Result<()> {
    if let Some(message) = blocked_radio_at(Path::new("/sys"), interface).await {
        anyhow::bail!(message);
    }
    Ok(())
}

async fn blocked_radio_at(sys: &Path, interface: &str) -> Option<String> {
    // Only the rfkill device attached to this interface's PHY is authoritative.
    let phy = tokio::fs::canonicalize(sys.join("class/net").join(interface).join("phy80211"))
        .await
        .ok()?;
    let mut entries = tokio::fs::read_dir(sys.join("class/rfkill")).await.ok()?;
    let mut blocks = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if tokio::fs::canonicalize(path.join("device"))
            .await
            .ok()
            .as_ref()
            != Some(&phy)
        {
            continue;
        }
        let hard = tokio::fs::read_to_string(path.join("hard")).await.ok();
        let soft = tokio::fs::read_to_string(path.join("soft")).await.ok();
        let parse = |value: Option<&str>| match value.map(str::trim) {
            Some("1") => Some(true),
            Some("0") => Some(false),
            _ => None,
        };
        let hard = parse(hard.as_deref());
        let soft = parse(soft.as_deref());
        if hard != Some(true) && soft != Some(true) {
            continue;
        }
        let name = entry.file_name();
        let index = name.to_str()?.strip_prefix("rfkill")?;
        if index.parse::<u32>().is_err() {
            continue;
        }
        let state = |value| match value {
            Some(true) => "true",
            Some(false) => "false",
            None => "unknown",
        };
        let mut message = format!("Wi-Fi on {interface} is blocked by rfkill{index} (PHY {}, hard={}, soft={}). Inspect `rfkill list {index}` or {}. ", phy.display(), state(hard), state(soft), path.display());
        if hard == Some(true) {
            message.push_str("Release the hardware/firmware radio switch first; a software unblock cannot clear a hard block. ");
        }
        if soft == Some(true) {
            message.push_str(&format!("If you want this radio enabled, unblock it manually with `sudo rfkill unblock {index}`. "));
        }
        if hard.is_none() || soft.is_none() {
            message.push_str(
                "Observation is incomplete; unreadable or invalid block state remains unknown. ",
            );
        }
        message.push_str("rfkill state does not identify the process that set it. traffic-masq will not unblock the radio automatically.");
        blocks.push(message);
    }
    (!blocks.is_empty()).then(|| blocks.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[tokio::test]
    async fn matches_the_phy_and_leaves_both_blocks_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let sys = dir.path();
        std::fs::create_dir_all(sys.join("class/net/wlan0")).unwrap();
        std::fs::create_dir_all(sys.join("devices/phy0")).unwrap();
        std::fs::create_dir_all(sys.join("devices/phy1")).unwrap();
        symlink(
            sys.join("devices/phy0"),
            sys.join("class/net/wlan0/phy80211"),
        )
        .unwrap();
        for (index, phy) in [(0, "phy0"), (1, "phy1")] {
            let path = sys.join(format!("class/rfkill/rfkill{index}"));
            std::fs::create_dir_all(&path).unwrap();
            symlink(sys.join(format!("devices/{phy}")), path.join("device")).unwrap();
            std::fs::write(path.join("hard"), "1\n").unwrap();
            std::fs::write(path.join("soft"), "1\n").unwrap();
        }
        let message = blocked_radio_at(sys, "wlan0").await.unwrap();
        assert!(message.contains("hard=true, soft=true"));
        assert!(message.contains("sudo rfkill unblock 0"));
        assert!(!message.contains("rfkill1"));
        assert_eq!(
            std::fs::read_to_string(sys.join("class/rfkill/rfkill0/soft")).unwrap(),
            "1\n"
        );
        std::fs::write(sys.join("class/rfkill/rfkill0/hard"), "0\n").unwrap();
        std::fs::write(sys.join("class/rfkill/rfkill0/soft"), "0\n").unwrap();
        assert!(blocked_radio_at(sys, "wlan0").await.is_none());
        std::fs::remove_file(sys.join("class/rfkill/rfkill0/hard")).unwrap();
        std::fs::write(sys.join("class/rfkill/rfkill0/soft"), "1\n").unwrap();
        let partial = blocked_radio_at(sys, "wlan0").await.unwrap();
        assert!(partial.contains("hard=unknown, soft=true"));
        assert!(partial.contains("Observation is incomplete"));
    }

    #[tokio::test]
    async fn missing_sysfs_does_not_invent_a_block() {
        let dir = tempfile::tempdir().unwrap();
        assert!(blocked_radio_at(dir.path(), "wlan0").await.is_none());
    }
}
