use std::net::Ipv4Addr;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use traffic_masq::netlink::{
    Ipv4RouteSpec, NetworkProvider, RtnetlinkNetworkProvider, TRAFFIC_MASQ_ROUTE_PROTOCOL,
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
        .add_ipv4_address(&fixture.host_if, test_ip, 24)
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
