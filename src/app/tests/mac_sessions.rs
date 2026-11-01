use super::*;
use crate::core::interface::InterfaceSnapshot;

struct RestoredStation {
    network: Arc<FakeNetworkProvider>,
    snapshot: InterfaceSnapshot,
    connection_mac: [u8; 6],
    calls: Mutex<Vec<bool>>,
}

#[async_trait]
impl WifiRuntimeReconciler for RestoredStation {
    async fn ensure_alive(&self) -> Result<bool> {
        Ok(false)
    }

    async fn reconcile_interface(&self, name: &str, config: &InterfaceConfig) -> Result<()> {
        let enabled = config.wifi_client.is_some();
        self.calls.lock().await.push(enabled);
        if enabled {
            assert_eq!(
                self.network.mac_address(name).await?,
                self.snapshot.mac_address.map(|mac| mac.octets())
            );
            assert_eq!(
                self.network.list_ipv4_addresses(name).await?,
                self.snapshot.ipv4_addresses
            );
            if config.randomize_mac {
                // Model supplicant choosing a fresh identity before association.
                self.network.set_link_down(name).await?;
                self.network
                    .set_mac_address(name, self.connection_mac)
                    .await?;
                self.network.set_link_up(name).await?;
            }
        }
        Ok(())
    }

    async fn association_ready(&self, name: &str) -> Option<bool> {
        Some(self.network.mac_address(name).await.ok().flatten() == Some(self.connection_mac))
    }
}

#[tokio::test]
async fn wifi_rollback_restores_snapshot_before_association_and_dhcp() {
    // Restore even when the candidate kept the original MAC; it may still
    // have changed addresses or replaced the owned station process.
    for (randomize_mac, changed_mac) in [(true, true), (true, false), (false, true)] {
        let directory = tempdir().unwrap();
        let mut config = dhcp_client_reconcile_config();
        config.runtime.state_dir = directory.path().to_path_buf();
        config.network.interfaces.remove("lan0");
        let previous = config.network.interfaces.get_mut("wan0").unwrap();
        previous.randomize_mac = randomize_mac;
        previous.wifi_client = Some(crate::config::WifiClientConfig {
            ssid: "restored-network".into(),
            country_code: None,
            security: crate::config::WifiClientSecurity::Open,
            passphrase_file: None,
        });
        let previous = previous.clone();
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .unwrap();
        let desired = DesiredNetworkState::new(config, overrides);
        let original_mac = [2, 1, 2, 3, 4, 5];
        let snapshot = InterfaceSnapshot {
            name: "wan0".into(),
            was_up: true,
            mac_address: Some(traffic_masq_protocol::MacAddr::new(original_mac)),
            ipv4_addresses: vec![Ipv4AddressInfo {
                interface_index: 7,
                address: "198.51.100.7".parse().unwrap(),
                prefix_len: 24,
                protocol: None,
            }],
        };
        desired
            .restore("rollback", snapshot.clone(), Some(previous))
            .await;
        let network = Arc::new(FakeNetworkProvider::default());
        network
            .add_interface_with_state("wan0", 7, true, vec![])
            .await;
        network
            .interfaces
            .lock()
            .await
            .get_mut("wan0")
            .unwrap()
            .is_wireless = true;
        network.macs.lock().await.insert(
            "wan0".into(),
            if changed_mac {
                [2, 9, 8, 7, 6, 5]
            } else {
                original_mac
            },
        );
        let station = RestoredStation {
            network: network.clone(),
            snapshot,
            connection_mac: if randomize_mac {
                [2, 6, 7, 8, 9, 10]
            } else {
                original_mac
            },
            calls: Mutex::new(vec![]),
        };
        let client = FakeDhcpClientReconciler::default();
        let failures = reconcile_network_runtime_once(
            &desired,
            &AddressOwnershipJournal::in_memory(),
            network.clone(),
            &FakeDhcpReconciler::default(),
            None::<&FakeWifiReconciler>,
            Some(&station),
            Some(&client),
        )
        .await
        .unwrap();
        assert!(failures.is_empty(), "{failures:?}");
        assert_eq!(*station.calls.lock().await, vec![false, true]);
        assert_eq!(station.association_ready("wan0").await, Some(true));
        assert_eq!(*client.readiness.lock().await, vec![("wan0".into(), true)]);
        assert_eq!(*client.disable_calls.lock().await, vec!["wan0"]);
    }
}
