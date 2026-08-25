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

/// The event source is the reason the daemon can stop polling, so the thing
/// worth proving is that a change made by *someone else* actually arrives.
/// Subscription succeeding is checked by unit tests; delivery needs a change,
/// and making one needs root.
#[tokio::test]
#[ignore = "requires root and iproute2; run explicitly on a disposable Linux test host"]
async fn kernel_address_changes_are_delivered_as_events() -> Result<()> {
    let fixture = NetnsFixture::new()?;
    let mut events = traffic_masq::netlink::events::subscribe_to_kernel_changes()?;
    let test_ip = Ipv4Addr::new(192, 0, 2, 40);

    // Deliberately not through our own provider: the point is noticing changes
    // this daemon did not make.
    run_ip([
        "addr",
        "add",
        &format!("{test_ip}/24"),
        "dev",
        fixture.host_if.as_str(),
    ])?;

    let event = tokio::time::timeout(std::time::Duration::from_secs(5), events.recv())
        .await
        .context("no kernel event arrived within 5s; the subscription is not delivering")?
        .context("the event stream closed")?;
    assert_eq!(event, traffic_masq::netlink::events::KernelEvent::Changed);

    run_ip([
        "addr",
        "del",
        &format!("{test_ip}/24"),
        "dev",
        fixture.host_if.as_str(),
    ])?;
    Ok(())
}

/// The whole of the transaction path, on a real kernel.
///
/// An apply is now a proposal: the manager writes a layer of desired state and
/// waits, and convergence is the only thing that touches the machine. Two
/// things have to hold on a live kernel and cannot be shown against a fake —
/// the proposed address really lands, tagged as ours, before the caller is told
/// the change is applied; and letting the confirmation deadline pass really
/// puts the committed address back, with nothing having recorded how to undo
/// anything.
#[tokio::test]
#[ignore = "requires root and iproute2; run explicitly on a disposable Linux test host"]
async fn an_unconfirmed_change_converges_and_expires_on_a_live_kernel() -> Result<()> {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use traffic_masq::config::{AppConfig, InterfaceConfig, InterfaceRole};
    use traffic_masq::core::desired::DesiredNetworkState;
    use traffic_masq::core::interface::InterfaceManager;
    use traffic_masq::core::override_manager::RuntimeOverrideManager;
    use traffic_masq::core::ownership::AddressOwnershipJournal;
    use traffic_masq::core::transaction::NetworkTransactionManager;

    let fixture = NetnsFixture::new()?;
    let state_dir = tempfile::tempdir()?;
    let committed: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
    let proposed: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 51);

    let interface = |address: Ipv4Addr| InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(format!("{address}/24").parse().expect("network")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };

    let mut base = AppConfig::default();
    base.network
        .interfaces
        .insert(fixture.host_if.clone(), interface(committed));
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &base).await?;
    let desired = DesiredNetworkState::new(base, overrides);

    let provider: Arc<dyn NetworkProvider> = Arc::new(RtnetlinkNetworkProvider::connect()?);
    let journal = AddressOwnershipJournal::in_memory();
    let interfaces = InterfaceManager::new(provider.clone(), journal.clone());

    // Stands in for the daemon's loop: same contract — read the version, make
    // the machine match, publish the result — without the supervisors, which
    // have nothing to do with what is being proved here.
    desired.attach_converger();
    let converger = tokio::spawn({
        let desired = desired.clone();
        let interfaces = interfaces.clone();
        async move {
            loop {
                let version = desired.version();
                let mut failures = BTreeMap::new();
                let effective = desired.effective().await.expect("effective config");
                let allowed = desired.management_allowlist().await;
                for (name, config) in &effective.network.interfaces {
                    if let Err(error) = interfaces
                        .apply_interface(name, config, Some(config.role), allowed.contains(name))
                        .await
                    {
                        failures.insert(name.clone(), error.to_string());
                    }
                }
                desired.report_pass(version, failures);
                desired.changed().await;
            }
        }
    });

    let manager = NetworkTransactionManager::new(
        InterfaceManager::new(provider.clone(), journal.clone()),
        Duration::from_secs(2),
        desired.clone(),
    );

    let addresses_on_link = || async {
        Ok::<_, anyhow::Error>(
            provider
                .list_ipv4_addresses(&fixture.host_if)
                .await?
                .into_iter()
                .map(|address| (address.address, address.owner()))
                .collect::<Vec<_>>(),
        )
    };

    let change = manager
        .apply(
            &fixture.host_if,
            &interface(proposed),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .context("apply must not return before the change has been converged to")?;

    assert_eq!(
        addresses_on_link().await?,
        vec![(proposed, AddressOwner::TrafficMasqStatic)],
        "the proposed address must be on the link, tagged as ours, by the time apply returns"
    );

    // Nobody confirms it. The rollback timer withdraws the proposal, and the
    // committed configuration is what convergence goes back to.
    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(manager.pending().await.is_empty());
    assert_eq!(
        addresses_on_link().await?,
        vec![(committed, AddressOwner::TrafficMasqStatic)],
        "an unconfirmed change must expire back to the committed configuration"
    );
    assert!(!desired.is_tentative(&fixture.host_if).await);
    let _ = change;

    converger.abort();
    provider
        .delete_ipv4_address(&fixture.host_if, committed, 24)
        .await?;
    provider.set_link_down(&fixture.host_if).await?;
    Ok(())
}

/// The journal and the kernel tag must never contradict each other.
///
/// They are two answers to one question — "did traffic-masq install this" — and
/// the whole point of keeping both is that either one alone is enough. That is
/// only safe while they agree on a machine where both work, and only a real
/// kernel can say whether they do: it is the kernel that stores the tag, and
/// the journal that survives it. This also covers the restart: the record is
/// re-read from disk and checked against the link, exactly as the daemon does
/// when it starts.
#[tokio::test]
#[ignore = "requires root, iproute2 and Linux 5.18+; run explicitly on a disposable Linux test host"]
async fn the_journal_and_the_kernel_tag_agree_about_who_owns_an_address() -> Result<()> {
    use std::sync::Arc;

    use traffic_masq::config::{InterfaceConfig, InterfaceRole};
    use traffic_masq::core::interface::InterfaceManager;
    use traffic_masq::core::ownership::AddressOwnershipJournal;

    let fixture = NetnsFixture::new()?;
    let state_dir = tempfile::tempdir()?;
    let test_ip = Ipv4Addr::new(192, 0, 2, 60);

    let provider: Arc<dyn NetworkProvider> = Arc::new(RtnetlinkNetworkProvider::connect()?);
    let journal = AddressOwnershipJournal::open(state_dir.path())?;
    let interfaces = InterfaceManager::new(provider.clone(), journal);

    let config = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(format!("{test_ip}/24").parse()?),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };
    interfaces
        .apply_interface(
            &fixture.host_if,
            &config,
            Some(InterfaceRole::Output),
            false,
        )
        .await?;

    let observed = provider
        .list_ipv4_addresses(&fixture.host_if)
        .await?
        .into_iter()
        .find(|address| address.address == test_ip)
        .context("the configured address should be on the link")?;
    assert_eq!(
        observed.owner(),
        AddressOwner::TrafficMasqStatic,
        "the kernel must be holding the tag this address was installed with"
    );

    // What a restart sees: the journal read back off disk, checked against the
    // machine, with the daemon's in-memory state gone.
    let reopened = AddressOwnershipJournal::open(state_dir.path())?;
    let outcome = reopened
        .reconcile(&fixture.host_if, &[observed.clone()])
        .await?;
    assert!(
        outcome.dropped.is_empty(),
        "a claim the kernel confirms must not be dropped: {:?}",
        outcome.dropped
    );
    assert!(reopened.owns(&fixture.host_if, test_ip, 24).await);

    // Taking the address off gives the claim up on both sides at once.
    let mut released = config.clone();
    released.managed = false;
    released.ipv4 = None;
    let plan = interfaces
        .plan_interface_transition(
            &fixture.host_if,
            &released,
            Some(&config),
            Some(InterfaceRole::Output),
            false,
        )
        .await?;
    interfaces.apply_plan(&plan).await?;

    assert!(provider
        .list_ipv4_addresses(&fixture.host_if)
        .await?
        .iter()
        .all(|address| address.address != test_ip));
    assert!(
        !AddressOwnershipJournal::open(state_dir.path())?
            .owns(&fixture.host_if, test_ip, 24)
            .await,
        "an address that is off the link must not still be claimed on disk"
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
