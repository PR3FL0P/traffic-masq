use super::*;
use crate::tui::{input, layout};

pub(crate) async fn open_wifi_connect_prompt(
    app: &mut TuiApp,
    client: &ApiClient,
    interface: String,
    profile_id: String,
    ssid: String,
) {
    let current_static_ip = match client
        .request(&Request::GetInterfaceConfig {
            interface: interface.clone(),
        })
        .await
    {
        Ok(Response::InterfaceConfig {
            config: Some(cfg), ..
        }) => cfg.ipv4.map(|ip| ip.to_string()),
        Ok(response) => {
            report_unexpected(app, response);
            return;
        }
        Err(error) => {
            app.push_message(
                LogLevel::Warn,
                format!("Could not read current IP configuration: {error}"),
            );
            return;
        }
    };

    app.wifi_connect = Some(WifiConnectPrompt::new(
        interface,
        profile_id,
        ssid,
        current_static_ip,
    ));
    app.screen = Screen::WifiConnectPrompt;
}

pub(crate) async fn handle_wifi_connect_prompt_key(
    app: &mut TuiApp,
    key: KeyCode,
    client: &ApiClient,
) {
    let Some(prompt) = app.wifi_connect.as_mut() else {
        app.screen = Screen::Wifi;
        return;
    };

    match key {
        KeyCode::Esc => {
            app.wifi_connect = None;
            app.screen = if app.wifi_profiles.is_some() {
                Screen::WifiProfiles
            } else {
                Screen::Wifi
            };
        }
        KeyCode::F(10) => {
            submit_wifi_connect(app, client).await;
        }
        KeyCode::Up => {
            let focusable = prompt.focusable_fields();
            if let Some(pos) = focusable.iter().position(|f| *f == prompt.field) {
                if pos > 0 {
                    prompt.field = focusable[pos - 1];
                    if prompt.field == WifiConnectField::StaticCidr {
                        prompt.cursor = prompt.static_cidr.len();
                    }
                }
            }
        }
        KeyCode::Down | KeyCode::Tab => {
            let focusable = prompt.focusable_fields();
            if let Some(pos) = focusable.iter().position(|f| *f == prompt.field) {
                if pos + 1 < focusable.len() {
                    prompt.field = focusable[pos + 1];
                    if prompt.field == WifiConnectField::StaticCidr {
                        prompt.cursor = prompt.static_cidr.len();
                    }
                }
            }
        }
        KeyCode::Left if prompt.field == WifiConnectField::Cancel => {
            prompt.field = WifiConnectField::Submit;
        }
        KeyCode::Right if prompt.field == WifiConnectField::Submit => {
            prompt.field = WifiConnectField::Cancel;
        }
        KeyCode::Char(' ') if matches!(prompt.field, WifiConnectField::Choice(_)) => {
            if let WifiConnectField::Choice(choice) = prompt.field {
                prompt.choice = choice;
            }
        }
        KeyCode::Enter => match prompt.field {
            WifiConnectField::Choice(c) => {
                prompt.choice = c;
                if c == WifiIpChoice::NewStatic {
                    prompt.field = WifiConnectField::StaticCidr;
                    prompt.cursor = prompt.static_cidr.len();
                } else {
                    prompt.field = WifiConnectField::Submit;
                }
            }
            WifiConnectField::StaticCidr => {
                prompt.field = WifiConnectField::Submit;
            }
            WifiConnectField::Submit => {
                submit_wifi_connect(app, client).await;
            }
            WifiConnectField::Cancel => {
                app.wifi_connect = None;
                app.screen = if app.wifi_profiles.is_some() {
                    Screen::WifiProfiles
                } else {
                    Screen::Wifi
                };
            }
        },
        other if prompt.field == WifiConnectField::StaticCidr => {
            let cursor = &mut prompt.cursor;
            input::TextEditor::new(&mut prompt.static_cidr, cursor)
                .handle_key_filtered(other, |c| c.is_ascii_digit() || c == '.' || c == '/');
        }
        _ => {}
    }
}

async fn disable_dhcp_for_static(app: &mut TuiApp, client: &ApiClient, interface: &str) -> bool {
    use crate::api::model::DhcpClientErrorDetail;
    match client
        .request(&Request::DisableDhcpClient {
            interface: interface.to_string(),
        })
        .await
    {
        Ok(Response::DhcpClientDisabled { .. })
        | Ok(Response::DhcpClientError {
            detail: DhcpClientErrorDetail::Disabled | DhcpClientErrorDetail::DhcpClientDisabled,
        }) => true,
        Ok(response) => {
            app.push_message(
                LogLevel::Warn,
                format!("Cannot configure static IP: DHCP client was not stopped: {response:?}"),
            );
            false
        }
        Err(error) => {
            app.push_message(
                LogLevel::Warn,
                format!("Cannot configure static IP: DHCP client was not stopped: {error}"),
            );
            false
        }
    }
}

pub(super) async fn apply_wifi_static_ip(
    app: &mut TuiApp,
    client: &ApiClient,
    interface: &str,
    cidr: &str,
) -> bool {
    match client
        .request(&Request::ApplyInterfaceEdit {
            interface: interface.to_string(),
            edit: InterfaceEditRequest {
                cidr: cidr.to_string(),
                role: InterfaceRole::Input,
                managed: true,
                allow_management_change: true,
            },
        })
        .await
    {
        Ok(Response::NetworkChangePending { change }) => {
            match client
                .request(&Request::CommitNetworkChange {
                    token: change.token.clone(),
                })
                .await
            {
                Ok(Response::NetworkChangeCommitted { .. }) => true,
                result => {
                    // Retain the token and deadline so the user can inspect/roll back
                    // an ambiguous commit instead of losing the pending transaction.
                    app.pending = Some(change);
                    app.pending_return_screen = Screen::Wifi;
                    app.screen = Screen::PendingChange;
                    app.push_message(LogLevel::Warn, format!("Static IP commit was not confirmed: {result:?}. Inspect pending state before retrying."));
                    false
                }
            }
        }
        Ok(Response::NetworkChangeCommitted { .. }) => true,
        result => {
            app.push_message(
                LogLevel::Warn,
                format!("Static IP configuration failed: {result:?}"),
            );
            false
        }
    }
}

pub(super) async fn submit_wifi_connect(app: &mut TuiApp, client: &ApiClient) {
    let Some(prompt) = app.wifi_connect.clone() else {
        return;
    };
    let static_cidr = match prompt.choice {
        WifiIpChoice::Dhcp => None,
        WifiIpChoice::KeepStatic => prompt.current_static_ip.as_deref(),
        WifiIpChoice::NewStatic => Some(prompt.static_cidr.trim()),
    };
    if prompt.choice != WifiIpChoice::Dhcp {
        let Some(cidr) = static_cidr.filter(|cidr| !cidr.is_empty()) else {
            app.push_message(LogLevel::Warn, "Static IP / CIDR is required");
            return;
        };
        if let Err(error) = cidr.parse::<ipnet::Ipv4Net>() {
            app.push_message(
                LogLevel::Warn,
                format!("Invalid CIDR format (e.g. 192.168.1.100/24): {error}"),
            );
            return;
        }
    }

    // Activation validates that an IP configuration already exists. Configure
    // it first, and stop immediately if any prerequisite fails.
    if let Some(cidr) = static_cidr {
        if !disable_dhcp_for_static(app, client, &prompt.interface).await
            || !apply_wifi_static_ip(app, client, &prompt.interface, cidr).await
        {
            return;
        }
    } else {
        match client
            .request(&Request::ConfigureDhcpClient {
                interface: prompt.interface.clone(),
                config: DhcpClientConfigRequest::default(),
            })
            .await
        {
            Ok(Response::DhcpClientInterface { .. }) => {}
            result => {
                app.push_message(
                    LogLevel::Warn,
                    format!("DHCP client configuration failed: {result:?}"),
                );
                return;
            }
        }
    }

    match client
        .request(&Request::ActivateWifiClientProfile {
            interface: prompt.interface.clone(),
            profile_id: prompt.profile_id.clone(),
        })
        .await
    {
        Ok(Response::WifiClientProfileActivated { .. }) => {
            app.push_message(
                LogLevel::Info,
                format!(
                    "Profile '{}' activated; waiting for Wi-Fi connection and IP readiness.",
                    prompt.ssid
                ),
            );
            app.wifi_connect = None;
            app.screen = Screen::Wifi;
            load_wifi_data(app, client).await;
        }
        result => {
            app.push_message(LogLevel::Warn, format!("IP configuration was updated, but profile activation was not confirmed: {result:?}. Inspect interface state before retrying."));
        }
    }
}

pub(crate) fn render_wifi_connect_prompt(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
) {
    let Some(prompt) = &app.wifi_connect else {
        return;
    };
    let block = panel(&format!(
        "Connect to '{}' on {}",
        prompt.ssid, prompt.interface
    ));
    let mut lines = Vec::new();

    lines.push(Line::from(
        "Select how IPv4 will be obtained for this connection:",
    ));
    lines.push(Line::from(""));

    // Option 1: DHCP
    let dhcp_active = prompt.field == WifiConnectField::Choice(WifiIpChoice::Dhcp);
    let dhcp_selected = prompt.choice == WifiIpChoice::Dhcp;
    let dhcp_radio = if dhcp_selected { "(•) " } else { "( ) " };
    let dhcp_prefix = if dhcp_active { "▶ " } else { "  " };
    lines.push(Line::styled(
        format!("{dhcp_prefix}{dhcp_radio}Obtain IP address automatically via DHCP (recommended)"),
        selected_style(dhcp_active),
    ));

    // Option 2 (conditional): Keep current static IP
    if let Some(ip) = &prompt.current_static_ip {
        let keep_active = prompt.field == WifiConnectField::Choice(WifiIpChoice::KeepStatic);
        let keep_selected = prompt.choice == WifiIpChoice::KeepStatic;
        let keep_radio = if keep_selected { "(•) " } else { "( ) " };
        let keep_prefix = if keep_active { "▶ " } else { "  " };
        lines.push(Line::styled(
            format!("{keep_prefix}{keep_radio}Keep current static IP ({ip})"),
            selected_style(keep_active),
        ));
    }

    // Option 3: Configure static IP
    let new_active = prompt.field == WifiConnectField::Choice(WifiIpChoice::NewStatic);
    let new_selected = prompt.choice == WifiIpChoice::NewStatic;
    let new_radio = if new_selected { "(•) " } else { "( ) " };
    let new_prefix = if new_active { "▶ " } else { "  " };
    lines.push(Line::styled(
        format!("{new_prefix}{new_radio}Configure static IP address"),
        selected_style(new_active),
    ));

    if prompt.choice == WifiIpChoice::NewStatic {
        lines.push(Line::from(""));

        // Static CIDR
        let cidr_active = prompt.field == WifiConnectField::StaticCidr;
        let cidr_style = selected_style(cidr_active);
        let cidr_prefix = format!(
            "{}{:<24}",
            if cidr_active { "▶ " } else { "  " },
            "IP / CIDR:"
        );
        let mut cidr_spans = vec![Span::styled(cidr_prefix, cidr_style)];
        if cidr_active {
            cidr_spans.extend(input::render_value_with_cursor(
                &prompt.static_cidr,
                prompt.cursor,
                true,
                cidr_style,
            ));
        } else {
            cidr_spans.push(Span::styled(
                if prompt.static_cidr.is_empty() {
                    "e.g. 192.168.1.100/24".to_string()
                } else {
                    prompt.static_cidr.clone()
                },
                if prompt.static_cidr.is_empty() {
                    Style::default().fg(theme::MUTED)
                } else {
                    cidr_style
                },
            ));
        }
        lines.push(Line::from(cidr_spans));
    }

    lines.push(Line::from(""));

    let buttons_line = lines.len();
    // Buttons
    let submit_active = prompt.field == WifiConnectField::Submit;
    let cancel_active = prompt.field == WifiConnectField::Cancel;
    lines.push(Line::from(vec![
        Span::styled(
            if submit_active {
                "▶ [ Connect (Enter) ] "
            } else {
                "  [ Connect ] "
            },
            selected_style(submit_active),
        ),
        Span::raw("    "),
        Span::styled(
            if cancel_active {
                "▶ [ Cancel (Esc) ]"
            } else {
                "  [ Cancel ]"
            },
            selected_style(cancel_active),
        ),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "↑/↓: focus • Enter: select • F10: connect • Esc: cancel",
        Style::default().fg(theme::MUTED),
    ));

    let inner = block.inner(area);
    let offset = layout::focused_lines_offset(&lines, inner.height);
    if buttons_line >= offset && buttons_line < offset + inner.height as usize {
        let y = inner.y + (buttons_line - offset) as u16;
        let submit_width = if submit_active { 21 } else { 14 };
        let cancel_x = submit_width + 4;
        app.ui
            .buttons
            .push((Rect::new(inner.x, y, submit_width.min(inner.width), 1), 0));
        if cancel_x < inner.width {
            app.ui.buttons.push((
                Rect::new(inner.x + cancel_x, y, inner.width - cancel_x, 1),
                1,
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(offset).collect::<Vec<_>>()).block(block),
        area,
    );
}
