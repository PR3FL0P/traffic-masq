use crossterm::event::KeyCode;
use ratatui::{layout::Rect, style::Style, text::Line, widgets::Paragraph};
use traffic_masq_protocol::{DhcpLeaseView, MacAddr, Station};

use super::{
    api::{
        client::ApiClient,
        model::{Request, Response},
    },
    current_unix_time, input,
    layout::panel,
    logs::LogLevel,
    theme, Screen, TuiApp,
};

#[derive(Default)]
pub(crate) struct View {
    interface: String,
    stations: Vec<Station>,
    leases: Vec<DhcpLeaseView>,
    selected: usize,
    scroll: usize,
    loaded: bool,
    error: Option<String>,
    lease_error: Option<String>,
    confirm: Option<MacAddr>,
    focus: Focus,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Focus {
    #[default]
    List,
    Refresh,
    Disconnect,
    Back,
}
const FOCUS: [Focus; 4] = [Focus::List, Focus::Refresh, Focus::Disconnect, Focus::Back];
const ACTIONS: [(Focus, &str); 3] = [
    (Focus::Refresh, "Refresh"),
    (Focus::Disconnect, "Disconnect selected client"),
    (Focus::Back, "Back"),
];

pub(crate) async fn open(app: &mut TuiApp, client: &ApiClient, interface: String) {
    app.wifi_stations = Some(View {
        interface,
        ..View::default()
    });
    app.screen = Screen::WifiStations;
    refresh(app, client).await;
}

fn response_error(response: Response) -> String {
    match response {
        Response::Error { message } => message,
        Response::WifiError { detail } => format!("{detail:?}"),
        other => format!("Unexpected response: {other:?}"),
    }
}

pub(crate) async fn refresh(app: &mut TuiApp, client: &ApiClient) {
    let Some(view) = &app.wifi_stations else {
        return;
    };
    if view.confirm.is_some() {
        return;
    }
    let interface = view.interface.clone();
    let stations = client
        .request(&Request::ListWifiStations {
            interface: interface.clone(),
        })
        .await;
    let leases = client
        .request(&Request::ListLeases {
            interface: interface.clone(),
        })
        .await;
    let Some(view) = &mut app.wifi_stations else {
        return;
    };
    match stations {
        Ok(Response::WifiStations {
            interface: returned,
            stations,
        }) if returned == interface => {
            replace_stations(view, stations);
            view.loaded = true;
            view.error = None;
        }
        Ok(response) => view.error = Some(response_error(response)),
        Err(error) => view.error = Some(error.to_string()),
    }
    match leases {
        Ok(Response::Leases {
            interface: returned,
            leases,
        }) if returned == interface => {
            view.leases = leases;
            view.lease_error = None;
        }
        Ok(response) => view.lease_error = Some(response_error(response)),
        Err(error) => view.lease_error = Some(error.to_string()),
    }
}

fn replace_stations(view: &mut View, mut stations: Vec<Station>) {
    let selected = view.stations.get(view.selected).map(|station| station.mac);
    stations.sort_by_key(|station| station.mac);
    view.selected = selected
        .and_then(|mac| stations.iter().position(|s| s.mac == mac))
        .unwrap_or(0);
    view.stations = stations;
}

fn lease_for(view: &View, mac: MacAddr, now: u64) -> Option<&DhcpLeaseView> {
    if view.lease_error.is_some() {
        return None;
    }
    view.leases
        .iter()
        .filter(|lease| lease.mac == mac.octets() && !lease.is_expired_at(now))
        .max_by_key(|lease| lease.expires_at_unix)
}

pub(crate) fn select_row(app: &mut TuiApp, index: usize) {
    if let Some(view) = &mut app.wifi_stations {
        if view.confirm.is_none() {
            view.selected = index.min(view.stations.len().saturating_sub(1));
            view.focus = Focus::List;
        }
    }
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let (Some(view), Some((focus, _))) = (app.wifi_stations.as_mut(), ACTIONS.get(slot)) {
        view.focus = *focus;
    }
}

pub(crate) fn render(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(view) = &mut app.wifi_stations else {
        return;
    };
    let block = panel("Connected Wi-Fi devices");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if let Some(mac) = view.confirm {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(format!("Disconnect {mac} from {}?", view.interface)),
                Line::from("This disconnects the client now. It may reconnect; this is not a ban."),
                Line::from("Enter: disconnect    Esc: cancel"),
            ]),
            inner,
        );
        return;
    }
    let mut lines = vec![Line::from(format!(
        "AP: {} | Associated clients: {}",
        view.interface,
        if view.loaded {
            view.stations.len().to_string()
        } else {
            "unknown".into()
        }
    ))];
    if let Some(error) = &view.error {
        lines.push(Line::styled(
            format!("STALE / unavailable: {error}"),
            Style::default().fg(theme::WARN),
        ));
    }
    if view.lease_error.is_some() {
        lines.push(Line::styled(
            "DHCP leases unavailable; client IP addresses are unknown",
            Style::default().fg(theme::WARN),
        ));
    }
    lines.push(Line::from(
        "MAC address           DHCP IPv4 / lease remaining",
    ));
    let header = lines.len() as u16;
    let available = inner
        .height
        .saturating_sub(header + ACTIONS.len() as u16 + 1);
    let visible = (available / 2).max(1) as usize;
    view.scroll = view.scroll.min(view.selected);
    if view.selected >= view.scroll + visible {
        view.scroll = view.selected + 1 - visible;
    }
    view.scroll = view.scroll.min(view.stations.len().saturating_sub(visible));
    let drawn_rows = view.stations.len().saturating_sub(view.scroll).min(visible);
    app.ui.list_area = Some(Rect::new(
        inner.x,
        inner.y + header,
        inner.width,
        (drawn_rows as u16 * 2).min(available),
    ));
    app.ui.list_row_height = 2;
    app.ui.list_count = view.stations.len();
    app.ui.list_scroll_offset = view.scroll;
    let now = current_unix_time();
    for (index, station) in view
        .stations
        .iter()
        .enumerate()
        .skip(view.scroll)
        .take(visible)
    {
        let lease = lease_for(view, station.mac, now)
            .map(|l| format!("{} / {}s", l.ip, l.expires_at_unix.saturating_sub(now)))
            .unwrap_or_else(|| "unknown (no active DHCP lease)".into());
        let style = Style::default().fg(if index == view.selected {
            theme::ACCENT
        } else {
            theme::TEXT
        });
        lines.push(Line::styled(
            format!(
                "{} {}  {lease}",
                if index == view.selected { "▶" } else { " " },
                station.mac
            ),
            style,
        ));
        let details = ["signal", "connected_time", "rx_bytes", "tx_bytes"]
            .iter()
            .filter_map(|key| station.raw.get(*key).map(|v| format!("{key}={v}")))
            .collect::<Vec<_>>()
            .join("  ");
        lines.push(Line::styled(
            format!("  {details}"),
            Style::default().fg(theme::MUTED),
        ));
    }
    if view.loaded && view.stations.is_empty() {
        lines.push(Line::from("No associated clients"));
    }
    frame.render_widget(
        Paragraph::new(lines),
        Rect::new(inner.x, inner.y, inner.width, header + available),
    );
    let action_y = inner.y + inner.height.saturating_sub(ACTIONS.len() as u16);
    for (index, (focus, label)) in ACTIONS.iter().enumerate() {
        let rect = Rect::new(inner.x, action_y + index as u16, inner.width, 1);
        frame.render_widget(
            Paragraph::new(format!(
                "{} {label}",
                if view.focus == *focus { "▶" } else { " " }
            ))
            .style(Style::default().fg(theme::ACCENT)),
            rect,
        );
        app.ui.buttons.push((rect, index));
    }
}

pub(crate) async fn handle_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(view) = &mut app.wifi_stations else {
        return;
    };
    if let Some(mac) = view.confirm {
        match key {
            KeyCode::Esc => view.confirm = None,
            KeyCode::Enter => {
                let interface = view.interface.clone();
                // Clear confirmation before the request: an uncertain response must never retry on Enter.
                view.confirm = None;
                view.focus = Focus::List;
                match client
                    .request(&Request::WifiDeauthStation {
                        interface: interface.clone(),
                        mac: mac.to_string(),
                    })
                    .await
                {
                    Ok(Response::WifiStations {
                        interface: returned,
                        stations,
                    }) if returned == interface => {
                        if let Some(view) = &mut app.wifi_stations {
                            replace_stations(view, stations);
                            view.error = None;
                        }
                        app.push_message(
                            LogLevel::Info,
                            format!(
                                "Disconnect request completed for {mac}; the client may reconnect"
                            ),
                        );
                    }
                    Ok(response) => app.push_message(LogLevel::Error, response_error(response)),
                    Err(error) => app.push_message(
                        LogLevel::Error,
                        format!("Disconnect outcome unverified: {error}. Refresh before retrying"),
                    ),
                }
            }
            _ => {}
        }
        return;
    }
    match key {
        KeyCode::Esc => {
            app.wifi_stations = None;
            app.screen = Screen::Wifi;
        }
        KeyCode::Tab | KeyCode::BackTab => {
            view.focus = input::move_wrapped(&FOCUS, view.focus, key == KeyCode::Tab)
        }
        KeyCode::Up | KeyCode::Down => {
            view.focus = Focus::List;
            view.selected = if key == KeyCode::Down {
                (view.selected + 1).min(view.stations.len().saturating_sub(1))
            } else {
                view.selected.saturating_sub(1)
            };
        }
        KeyCode::Char('r') => refresh(app, client).await,
        KeyCode::Char('d') if view.loaded && view.error.is_none() => {
            view.confirm = view.stations.get(view.selected).map(|s| s.mac);
        }
        KeyCode::Enter => match view.focus {
            Focus::Refresh => refresh(app, client).await,
            Focus::Disconnect => {
                if view.loaded && view.error.is_none() {
                    view.confirm = view.stations.get(view.selected).map(|s| s.mac);
                }
            }
            Focus::Back => {
                app.wifi_stations = None;
                app.screen = Screen::Wifi;
            }
            Focus::List => {}
        },
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn station(mac: &str) -> Station {
        Station {
            mac: mac.parse().unwrap(),
            raw: Default::default(),
        }
    }
    #[test]
    fn selection_tracks_mac_and_leases_ignore_expired_or_stale_results() {
        let a = station("00:11:22:33:44:55");
        let b = station("00:11:22:33:44:66");
        let mut view = View {
            stations: vec![b.clone()],
            ..Default::default()
        };
        replace_stations(&mut view, vec![b.clone(), a]);
        assert_eq!(view.stations[view.selected].mac, b.mac);
        view.leases.push(DhcpLeaseView {
            mac: b.mac.octets(),
            ip: "192.0.2.2".parse().unwrap(),
            expires_at_unix: 100,
        });
        assert!(lease_for(&view, b.mac, 99).is_some());
        assert!(lease_for(&view, b.mac, 100).is_none());
        view.lease_error = Some("offline".into());
        assert!(lease_for(&view, b.mac, 99).is_none());
    }
    #[tokio::test]
    async fn disconnect_requires_confirmation_and_uses_latched_mac() {
        let a = station("00:11:22:33:44:55");
        let mock = super::super::test_api::mock(vec![Response::WifiStations {
            interface: "wlan1".into(),
            stations: vec![],
        }])
        .await;
        let mut app = TuiApp {
            screen: Screen::WifiStations,
            wifi_stations: Some(View {
                interface: "wlan1".into(),
                stations: vec![a.clone()],
                loaded: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        handle_key(&mut app, KeyCode::Char('d'), &mock.client).await;
        assert!(mock.calls.lock().unwrap().is_empty());
        // A periodic refresh must not change the selected target during confirmation.
        refresh(&mut app, &mock.client).await;
        assert!(mock.calls.lock().unwrap().is_empty());
        handle_key(&mut app, KeyCode::Esc, &mock.client).await;
        assert!(app.wifi_stations.as_ref().unwrap().confirm.is_none());
        handle_key(&mut app, KeyCode::Char('d'), &mock.client).await;
        select_row(&mut app, 99);
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        let calls = mock.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method, "POST");
        assert_eq!(calls[0].path, "/api/v1/control");
        assert_eq!(calls[0].body["type"], "wifi_deauth_station");
        assert_eq!(calls[0].body["interface"], "wlan1");
        assert_eq!(calls[0].body["mac"], "00:11:22:33:44:55");
        assert!(app.wifi_stations.as_ref().unwrap().stations.is_empty());
    }

    #[tokio::test]
    async fn unavailable_stations_retain_rows_and_disable_disconnect() {
        let mock = super::super::test_api::mock(vec![
            Response::Error {
                message: "hostapd unavailable".into(),
            },
            Response::Error {
                message: "DHCP unavailable".into(),
            },
        ])
        .await;
        let mut app = TuiApp {
            wifi_stations: Some(View {
                interface: "wlan1".into(),
                stations: vec![station("00:11:22:33:44:55")],
                loaded: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        refresh(&mut app, &mock.client).await;
        handle_key(&mut app, KeyCode::Char('d'), &mock.client).await;
        let view = app.wifi_stations.as_ref().unwrap();
        assert_eq!(view.stations.len(), 1);
        assert!(view.error.is_some() && view.lease_error.is_some());
        assert!(view.confirm.is_none());
    }
    #[test]
    fn station_list_scrolls_and_only_drawn_rows_are_clickable() {
        for (width, height) in [(80, 24), (120, 30)] {
            let stations = (0..20)
                .map(|i| station(&format!("00:11:22:33:44:{i:02x}")))
                .collect();
            let mut app = TuiApp {
                screen: Screen::WifiStations,
                wifi_stations: Some(View {
                    interface: "wlan1".into(),
                    stations,
                    selected: 19,
                    loaded: true,
                    ..Default::default()
                }),
                ..Default::default()
            };
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|f| super::super::render(f, &mut app, false))
                .unwrap();
            let list = app.ui.list_area.unwrap();
            assert_eq!(
                list.height % 2,
                0,
                "blank half-row must not select an invisible client"
            );
            assert_eq!(app.ui.list_scroll_offset + list.height as usize / 2, 20);
            assert_eq!(app.ui.buttons.len(), 3);
            for (rect, _) in &app.ui.buttons {
                assert!(rect.y >= list.bottom());
            }
            app.wifi_stations.as_mut().unwrap().confirm =
                Some("00:11:22:33:44:13".parse().unwrap());
            terminal
                .draw(|f| super::super::render(f, &mut app, false))
                .unwrap();
            assert!(app.ui.buttons.is_empty());
            assert!(app.ui.list_area.is_none());
        }
    }
}
