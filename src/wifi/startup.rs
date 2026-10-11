//! Wi-Fi startup checks and normal supervisor initialization.

use std::path::Path;

use anyhow::{Context, Result};

use crate::config::AppConfig;
use crate::wifi::{HostapdSupervisor, WifiClientSupervisor};

async fn preflight_hostapd_binary(binary: &Path) -> Result<()> {
    crate::command::probe(binary).await.with_context(|| {
        format!(
            "hostapd binary {} is not runnable — install hostapd or fix wifi.hostapd_binary",
            binary.display()
        )
    })?;
    Ok(())
}

async fn preflight_wpa_supplicant_binary(binary: &Path) -> Result<()> {
    crate::command::probe(binary).await.with_context(|| {
        format!(
            "wpa_supplicant binary {} is not runnable — install wpa_supplicant or fix wifi_client.wpa_supplicant_binary",
            binary.display()
        )
    })?;
    Ok(())
}

/// Start AP supervision, using `wifi.enabled` only as a startup binary-check hint.
/// The supervisor exists even when Wi-Fi is initially disabled so it can be enabled later.
pub(crate) async fn start_ap(config: &AppConfig) -> Result<HostapdSupervisor> {
    if config.wifi.enabled {
        preflight_hostapd_binary(&config.wifi.hostapd_binary).await?;
    }
    Ok(HostapdSupervisor::start(config).await?)
}

/// Start station supervision, retaining the same runtime-enable behavior as AP supervision.
pub(crate) async fn start_client(config: &AppConfig) -> Result<WifiClientSupervisor> {
    if config.wifi_client.enabled {
        preflight_wpa_supplicant_binary(&config.wifi_client.wpa_supplicant_binary).await?;
    }
    Ok(WifiClientSupervisor::start(config).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn preflight_accepts_a_runnable_binary() {
        let binary = if Path::new("/bin/true").exists() {
            "/bin/true"
        } else {
            "/bin/sh"
        };
        preflight_hostapd_binary(Path::new(binary))
            .await
            .expect("a real, executable binary must pass preflight");
    }

    #[tokio::test]
    async fn preflight_reports_a_missing_binary_clearly() {
        let error = preflight_hostapd_binary(Path::new("/definitely/not/a/real/hostapd"))
            .await
            .expect_err("a nonexistent binary must fail preflight");
        let message = format!("{error:#}");
        assert!(message.contains("hostapd"), "{message}");
        assert!(
            message.contains("/definitely/not/a/real/hostapd"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn ap_supervisor_is_built_even_when_disabled_at_startup() {
        let directory = tempdir().expect("tempdir");
        let mut config = AppConfig::default();
        config.runtime.state_dir = directory.path().join("state");
        config.wifi.enabled = false;
        config.wifi.hostapd_binary = "/definitely/not/a/real/hostapd".into();

        let supervisor = start_ap(&config)
            .await
            .expect("a missing binary must not fail startup while Wi-Fi is off");

        assert!(
            supervisor.preflight_binary().await.is_err(),
            "a missing hostapd must still be diagnosed when later enabled"
        );
    }

    #[tokio::test]
    async fn enabled_ap_checks_hostapd() {
        let mut config = AppConfig::default();
        config.wifi.enabled = true;
        config.wifi.hostapd_binary = "/definitely/not/a/real/hostapd".into();

        let error = start_ap(&config).await.err().expect("hostapd must fail");
        assert!(error.to_string().contains("hostapd"), "{error:#}");
    }

    #[tokio::test]
    async fn enabled_ap_startup_requires_no_iw_or_radio_probe() {
        let directory = tempdir().expect("tempdir");
        let mut config = AppConfig::default();
        config.runtime.state_dir = directory.path().join("state");
        config.wifi.enabled = true;
        config.wifi.hostapd_binary = "/bin/true".into();
        start_ap(&config)
            .await
            .expect("only hostapd is probed at startup");
    }

    #[tokio::test]
    async fn client_supervisor_is_built_even_when_disabled_at_startup() {
        let directory = tempdir().expect("tempdir");
        let mut config = AppConfig::default();
        config.runtime.state_dir = directory.path().join("state");
        config.wifi_client.enabled = false;
        config.wifi_client.wpa_supplicant_binary = "/definitely/not/a/real/wpa_supplicant".into();

        let supervisor = start_client(&config)
            .await
            .expect("a missing binary must not fail startup while the client is off");

        assert!(supervisor.preflight_binary().await.is_err());
    }

    #[tokio::test]
    async fn enabled_client_checks_wpa_supplicant() {
        let mut config = AppConfig::default();
        config.wifi_client.enabled = true;
        config.wifi_client.wpa_supplicant_binary = "/definitely/not/a/real/wpa_supplicant".into();

        let error = start_client(&config)
            .await
            .err()
            .expect("wpa_supplicant must fail");
        assert!(
            error.to_string().contains("wpa_supplicant binary"),
            "{error:#}"
        );
    }
}
