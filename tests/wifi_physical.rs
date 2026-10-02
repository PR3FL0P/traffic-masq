use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use traffic_masq::netlink::{NetworkProvider, RtnetlinkNetworkProvider};

mod support;

/// Inspect the explicitly selected real adapter through the same provider used
/// by the daemon. This does not change its connection or move its PHY.
#[tokio::test]
#[ignore = "requires an explicitly selected physical Wi-Fi interface"]
async fn selected_adapter_matches_sysfs_and_nl80211() -> Result<()> {
    let interface = env::var("TRAFFIC_MASQ_WIFI_INTERFACE")
        .context("set TRAFFIC_MASQ_WIFI_INTERFACE to the adapter to test")?;
    support::wifi::validate_interface(&interface, "TRAFFIC_MASQ_WIFI_INTERFACE")?;
    let root = Path::new("/sys/class/net").join(&interface);
    let device = fs::canonicalize(root.join("device"))?;
    if device.starts_with("/sys/devices/virtual") {
        bail!("selected adapter is virtual, not physical hardware");
    }
    let driver = fs::canonicalize(root.join("device/driver"))?;
    let index: u32 = fs::read_to_string(root.join("ifindex"))?.trim().parse()?;
    let flags = fs::read_to_string(root.join("flags"))?;
    let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16)?;
    let phy = support::wifi::interface_phy(&interface)?;

    let provider = RtnetlinkNetworkProvider::connect()?;
    let interfaces = provider.list_interfaces().await?;
    let matches: Vec<_> = interfaces
        .iter()
        .filter(|item| item.name == interface)
        .collect();
    assert_eq!(matches.len(), 1, "selected adapter must appear once");
    let observed = matches[0];
    assert_eq!(observed.index, index);
    assert_eq!(observed.is_up, flags & 1 != 0);
    assert!(observed.is_wireless);
    assert_eq!(provider.wireless_phy(&interface), Some(phy.clone()));
    for address in provider.list_ipv4_addresses(&interface).await? {
        assert_eq!(address.interface_index, index);
    }

    let output = Command::new("iw")
        .args(["dev", &interface, "info"])
        .output()?;
    assert!(
        output.status.success(),
        "nl80211 must recognize the adapter"
    );
    let info = String::from_utf8(output.stdout)?;
    assert!(info
        .lines()
        .any(|line| line.trim() == format!("ifindex {index}")));
    assert!(info
        .lines()
        .any(|line| line.trim() == format!("wiphy {}", phy.trim_start_matches("phy"))));
    println!(
        "Verified physical adapter {interface}: {phy}, ifindex {index}, driver {}",
        driver.display()
    );
    Ok(())
}
