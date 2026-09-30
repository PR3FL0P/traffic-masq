//! Wi-Fi supervisor status conversion at the API boundary.

use crate::wifi::lifecycle::WifiHealth;
use crate::wifi::{HostapdState, WifiApSpec, WifiApStatus, WifiClientStatus, WpaState};
use traffic_masq_protocol::{
    HostapdStateView, WifiApSpecView, WifiApStatusView, WifiClientStatusView, WifiHealthView,
    WpaStateView,
};

macro_rules! state_conversion {
    ($domain:ident, $view:ident, $($variant:ident),+ $(,)?) => {
        impl From<$domain> for $view {
            fn from(value: $domain) -> Self {
                match value {
                    $($domain::$variant => Self::$variant,)+
                    $domain::Other(value) => Self::Other(value),
                }
            }
        }
        impl From<$view> for $domain {
            fn from(value: $view) -> Self {
                match value {
                    $($view::$variant => Self::$variant,)+
                    $view::Other(value) => Self::Other(value),
                }
            }
        }
    };
}

state_conversion!(
    HostapdState,
    HostapdStateView,
    Uninitialized,
    CountryUpdate,
    Acs,
    HtScan,
    Dfs,
    Disabled,
    Enabled
);
state_conversion!(
    WpaState,
    WpaStateView,
    Disconnected,
    InterfaceDisabled,
    Inactive,
    Scanning,
    Authenticating,
    Associating,
    Associated,
    FourWayHandshake,
    GroupHandshake,
    Completed
);

impl From<WifiHealth> for WifiHealthView {
    fn from(value: WifiHealth) -> Self {
        match value {
            WifiHealth::Healthy => Self::Healthy,
            WifiHealth::Starting => Self::Starting,
            WifiHealth::Retrying {
                error,
                attempts,
                retry_in_secs,
                competing_managers,
                advice,
            } => Self::Retrying {
                error,
                attempts,
                retry_in_secs,
                competing_managers,
                advice,
            },
        }
    }
}

impl From<WifiHealthView> for WifiHealth {
    fn from(value: WifiHealthView) -> Self {
        match value {
            WifiHealthView::Healthy => Self::Healthy,
            WifiHealthView::Starting => Self::Starting,
            WifiHealthView::Retrying {
                error,
                attempts,
                retry_in_secs,
                competing_managers,
                advice,
            } => Self::Retrying {
                error,
                attempts,
                retry_in_secs,
                competing_managers,
                advice,
            },
        }
    }
}

impl From<WifiApSpecView> for WifiApSpec {
    fn from(value: WifiApSpecView) -> Self {
        Self {
            interface: value.interface,
            ssid: value.ssid,
            country_code: value.country_code,
            band: value.band,
            channel: value.channel,
            channel_width: value.channel_width,
            security: value.security,
            hidden: value.hidden,
            client_isolation: value.client_isolation,
            max_stations: value.max_stations,
            passphrase_file: value.passphrase_file,
        }
    }
}

impl From<WifiApStatus> for WifiApStatusView {
    fn from(value: WifiApStatus) -> Self {
        Self {
            interface: value.interface,
            spec: value.spec.into(),
            pid: value.pid,
            hostapd_state: value.hostapd_state.into(),
            num_stations: value.num_stations,
            health: value.health.into(),
        }
    }
}

impl From<WifiApStatusView> for WifiApStatus {
    fn from(value: WifiApStatusView) -> Self {
        Self {
            interface: value.interface,
            spec: value.spec.into(),
            pid: value.pid,
            hostapd_state: value.hostapd_state.into(),
            num_stations: value.num_stations,
            health: value.health.into(),
        }
    }
}

impl From<WifiClientStatus> for WifiClientStatusView {
    fn from(value: WifiClientStatus) -> Self {
        Self {
            interface: value.interface,
            spec: value.spec.into(),
            pid: value.pid,
            wpa_state: value.wpa_state.into(),
            bssid: value.bssid,
            freq: value.freq,
            health: value.health.into(),
        }
    }
}

impl From<WifiClientStatusView> for WifiClientStatus {
    fn from(value: WifiClientStatusView) -> Self {
        Self {
            interface: value.interface,
            spec: value.spec.into(),
            pid: value.pid,
            wpa_state: value.wpa_state.into(),
            bssid: value.bssid,
            freq: value.freq,
            health: value.health.into(),
        }
    }
}
