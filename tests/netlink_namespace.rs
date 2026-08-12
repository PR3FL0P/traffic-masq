use std::net::Ipv4Addr;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use traffic_masq::netlink::{
    AddressOwner, AddressOwnership, Ipv4RouteSpec, NetworkProvider, RtnetlinkNetworkProvider,
    TRAFFIC_MASQ_ROUTE_PROTOCOL,
};

struct NetnsFixture {
    ns: String,
    host_if: String,
    peer_if: String,
}

impl NetnsFixture {
    fn new() -> Result<Self> {
        require_root_or_skip()?;
        require_ip_command_or_skip()?;

        let suffix = unique_suffix();
        let fixture = Self {
            ns: format!("tmns{suffix}"),
            host_if: format!("tmh{suffix}"),
            peer_if: format!("tmp{suffix}"),
        };

        run_ip(["netns", "add", fixture.ns.as_str()])?;
        run_ip([
            "link",
            "add",
            fixture.host_if.as_str(),
            "type",
            "veth",
            "peer",
            "name",
            fixture.peer_if.as_str(),
        ])?;
        run_ip([
            "link",
            "set",
            fixture.peer_if.as_str(),
            "netns",
            fixture.ns.as_str(),
        ])?;

        Ok(fixture)
    }
}

impl Drop for NetnsFixture {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "del", self.host_if.as_str()])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "del", self.ns.as_str()])
            .status();
    }
}

#[tokio::test]
#[ignore = "requires root and iproute2; run explicitly on a disposable Linux test host"]
async fn rtnetlink_can_manage_ipv4_on_veth() -> Result<()> {
    let fixture = NetnsFixture::new()?;
    let provider = RtnetlinkNetworkProvider::connect()?;
    let test_ip = Ipv4Addr::new(192, 0, 2, 10);

    provider.set_link_up(&fixture.host_if).await?;

    let interfaces = provider.list_interfaces().await?;
    let host = interfaces
        .iter()
        .find(|iface| iface.name == fixture.host_if)
        .with_context(|| format!("test interface {} was not found", fixture.host_if))?;
    assert!(host.is_up, "test interface should be up after set_link_up");
    let host_index = host.index;

    provider
        .add_ipv4_address(&fixture.host_if, test_ip, 24, AddressOwnership::Static)
        .await?;

    let addresses = provider.list_ipv4_addresses(&fixture.host_if).await?;
    assert!(
        addresses
            .iter()
            .any(|addr| addr.address == test_ip && addr.prefix_len == 24),
        "test IPv4 address should be present after add_ipv4_address"
    );

    let route_spec = Ipv4RouteSpec {
        destination: "198.51.100.0/24".parse()?,
        gateway: None,
        output_interface_index: Some(host_index),
        table: 254,
        metric: Some(4242),
        protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
    };
    provider.add_ipv4_route(&route_spec).await?;
    let created_route = provider
        .list_ipv4_routes()
        .await?
        .into_iter()
        .find(|route| {
            route.destination == route_spec.destination
                && route.output_interface_index == Some(host_index)
                && route.table == 254
                && route.metric == Some(4242)
                && route.protocol == TRAFFIC_MASQ_ROUTE_PROTOCOL
        })
        .context("test IPv4 route should be present after add_ipv4_route")?;
    provider.delete_ipv4_route(&created_route).await?;
    assert!(provider
        .list_ipv4_routes()
        .await?
        .iter()
        .all(|route| route != &created_route));

    provider
        .delete_ipv4_address(&fixture.host_if, test_ip, 24)
        .await?;

    let addresses = provider.list_ipv4_addresses(&fixture.host_if).await?;
    assert!(
        addresses.iter().all(|addr| addr.address != test_ip),
        "test IPv4 address should be absent after delete_ipv4_address"
    );

    provider.set_link_down(&fixture.host_if).await?;
    Ok(())
}

/// The one assumption the whole ownership model rests on: that the kernel
/// actually stores and returns `IFA_PROTO`. Fakes cannot answer this.
#[tokio::test]
#[ignore = "requires root, iproute2 and Linux 5.18+; run explicitly on a disposable Linux test host"]
async fn rtnetlink_round_trips_ipv4_address_ownership() -> Result<()> {
    let fixture = NetnsFixture::new()?;
    let provider = RtnetlinkNetworkProvider::connect()?;
    let test_ip = Ipv4Addr::new(192, 0, 2, 20);

    provider.set_link_up(&fixture.host_if).await?;
    provider
        .add_ipv4_address(&fixture.host_if, test_ip, 24, AddressOwnership::Static)
        .await?;

    let tagged = provider
        .list_ipv4_addresses(&fixture.host_if)
        .await?
        .into_iter()
        .find(|addr| addr.address == test_ip)
        .context("tagged address should be present")?;
    assert_eq!(
        tagged.owner(),
        AddressOwner::TrafficMasqStatic,
        "kernel must return the IFA_PROTO ownership tag it was given"
    );
    assert!(
        provider.supports_ipv4_address_protocol(),
        "a confirmed round-trip must leave ownership support enabled"
    );

    provider
        .delete_ipv4_address(&fixture.host_if, test_ip, 24)
        .await?;
    provider.set_link_down(&fixture.host_if).await?;
    Ok(())
}

/// Claiming an existing address must not take it off the link, and must not
/// disturb the address itself.
#[tokio::test]
#[ignore = "requires root, iproute2 and Linux 5.18+; run explicitly on a disposable Linux test host"]
async fn rtnetlink_retags_existing_address_in_place() -> Result<()> {
    let fixture = NetnsFixture::new()?;
    let provider = RtnetlinkNetworkProvider::connect()?;
    let test_ip = Ipv4Addr::new(192, 0, 2, 30);

    provider.set_link_up(&fixture.host_if).await?;
    provider
        .add_ipv4_address(&fixture.host_if, test_ip, 24, AddressOwnership::Untagged)
        .await?;

    let before = provider
        .list_ipv4_addresses(&fixture.host_if)
        .await?
        .into_iter()
        .find(|addr| addr.address == test_ip)
        .context("untagged address should be present")?;
    assert_eq!(before.owner(), AddressOwner::Untagged);

    provider
        .set_ipv4_address_ownership(&fixture.host_if, test_ip, 24, AddressOwnership::Static)
        .await?;

    let after = provider
        .list_ipv4_addresses(&fixture.host_if)
        .await?
        .into_iter()
        .find(|addr| addr.address == test_ip)
        .context("address must stay on the link while being claimed")?;
    assert_eq!(after.owner(), AddressOwner::TrafficMasqStatic);
    assert_eq!(after.prefix_len, before.prefix_len);
    assert_eq!(after.interface_index, before.interface_index);

    provider
        .delete_ipv4_address(&fixture.host_if, test_ip, 24)
        .await?;
    provider.set_link_down(&fixture.host_if).await?;
    Ok(())
}

fn require_root_or_skip() -> Result<()> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("failed to run id -u")?;

    if !output.status.success() {
        bail!("failed to determine effective user id");
    }

    let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if uid != "0" {
        bail!("this ignored integration test must be run as root");
    }

    Ok(())
}

fn require_ip_command_or_skip() -> Result<()> {
    let status = Command::new("ip")
        .arg("-V")
        .status()
        .context("ip command is required for test namespace setup")?;

    if !status.success() {
        bail!("ip command is required for test namespace setup");
    }

    Ok(())
}

fn run_ip<const N: usize>(args: [&str; N]) -> Result<()> {
    let status = Command::new("ip")
        .args(args)
        .status()
        .context("failed to execute ip command")?;

    if !status.success() {
        bail!("ip command failed");
    }

    Ok(())
}

fn unique_suffix() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_millis();
    let pid = std::process::id();
    format!("{:05}", (millis as u32 ^ pid) % 100_000)
}
