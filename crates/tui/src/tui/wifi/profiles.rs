use super::*;

pub(super) fn open_create_profile(app: &mut TuiApp, interface: String) {
    app.wifi_profile_editor = Some(WifiProfileEditor {
        dirty: false,
        exit_requested: false,
        interface,
        original_id: None,
        field: ProfileField::Id,
        id: String::new(),
        ssid: String::new(),
        security: WifiClientSecurity::Wpa2,
        country: String::new(),
        priority: "0".into(),
        autoconnect: false,
        passphrase: String::new(),
        has_passphrase: false,
        cursor: 0,
    });
    app.screen = Screen::WifiProfileEditor;
}

pub(super) async fn open_profiles(
    app: &mut TuiApp,
    client: &ApiClient,
    interface: String,
    mode: WifiProfilesMode,
) {
    match client.request(&Request::ListWifiClientProfiles).await {
        Ok(Response::WifiClientProfiles { mut profiles }) => {
            profiles.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));
            let previous = app.wifi_profiles.as_ref();
            let previous_id = previous
                .and_then(|view| view.profiles.get(view.selected_profile))
                .map(|profile| &profile.id);
            let selected_profile = previous_id
                .and_then(|id| profiles.iter().position(|profile| &profile.id == id))
                .unwrap_or_else(|| {
                    previous
                        .map_or(0, |view| view.selected_profile)
                        .min(profiles.len().saturating_sub(1))
                });
            let mode = if profiles.is_empty() && mode == WifiProfilesMode::ProfileActions {
                WifiProfilesMode::Management
            } else {
                mode
            };
            let selected = match mode {
                WifiProfilesMode::Menu => 0,
                WifiProfilesMode::Management | WifiProfilesMode::Connect => selected_profile,
                WifiProfilesMode::ProfileActions => 0,
            };
            app.wifi_profiles = Some(WifiProfilesView {
                delete_confirmation: None,
                interface,
                profiles,
                mode,
                selected,
                selected_profile,
            });
            app.screen = Screen::WifiProfiles;
        }
        Ok(Response::WifiClientProfileError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"))
        }
        Ok(response) => report_unexpected(app, response),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) fn render_wifi_profiles(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(view) = &app.wifi_profiles else {
        return;
    };
    if view.delete_confirmation.is_some() {
        if let Some(dialog) = super::delete_confirmation::client_dialog(view) {
            dialog.render(
                frame,
                area,
                &mut app.ui,
                app.confirmation_focus,
                app.confirmation_scroll,
            );
        }
        return;
    }
    match view.mode {
        WifiProfilesMode::Menu => render_profiles_menu(frame, area, &mut app.ui, view),
        WifiProfilesMode::Management | WifiProfilesMode::Connect => {
            render_profiles_management(frame, area, &mut app.ui, view)
        }
        WifiProfilesMode::ProfileActions => render_profile_actions(frame, area, &mut app.ui, view),
    }
}

fn render_profiles_menu(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    ui: &mut UiLayout,
    view: &WifiProfilesView,
) {
    let block = panel(&format!(
        "Saved profiles — {}",
        if view.interface.is_empty() {
            "library"
        } else {
            &view.interface
        }
    ));
    let inner = block.inner(area);

    ui.list_area = Some(inner);
    ui.list_count = WifiProfilesMenuAction::ALL.len();
    ui.list_row_height = 1;
    ui.list_scroll_offset = 0;

    let count = view.profiles.len();
    let count_desc = match count {
        0 => "no profiles saved".to_string(),
        1 => "1 profile saved".to_string(),
        n => format!("{n} profiles saved"),
    };

    let mut lines = Vec::new();
    for (idx, action) in WifiProfilesMenuAction::ALL.iter().enumerate() {
        let is_selected = view.selected == idx;
        lines.push(Line::styled(
            format!(
                "{}{:<16} {}",
                if is_selected { "▶ " } else { "  " },
                action.label(),
                action.description(&count_desc)
            ),
            selected_style(is_selected),
        ));
    }

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "  ↑/↓: navigate │ Enter: select │ Esc: back",
        Style::default().fg(theme::MUTED),
    ));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_profiles_management(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    ui: &mut UiLayout,
    view: &WifiProfilesView,
) {
    let target = view
        .profiles
        .get(view.selected_profile)
        .map_or("none", |p| p.id.as_str());
    let title = if view.mode == WifiProfilesMode::Connect {
        format!("Connect saved profile — Enter: IPv4 policy ({target})")
    } else {
        format!("Saved profiles — Management (selected: {target})")
    };
    let block = panel(&title);
    let inner = block.inner(area);

    if view.profiles.is_empty() {
        ui.list_area = Some(inner);
        ui.list_count = 0;
        ui.list_row_height = 1;
        ui.list_scroll_offset = 0;

        let lines = vec![
            Line::styled(
                "  No saved Wi-Fi profiles found.",
                Style::default().fg(theme::MUTED),
            ),
            Line::from(""),
            Line::styled(
                "  Press [Enter] to create a new profile, or [Esc] to return.",
                Style::default().fg(theme::ACCENT),
            ),
        ];
        frame.render_widget(Paragraph::new(lines).block(block), area);
        return;
    }

    let offset = view
        .selected
        .saturating_sub(inner.height.saturating_sub(1) as usize);
    ui.list_area = Some(inner);
    ui.list_count = view.profiles.len();
    ui.list_row_height = 1;
    ui.list_scroll_offset = offset;

    let lines = view
        .profiles
        .iter()
        .enumerate()
        .map(|(index, profile)| {
            let is_selected = index == view.selected;
            Line::styled(
                format!(
                    "{}{: <18} {: <28} {: <5} auto:{} priority {}{}",
                    if is_selected { "▶ " } else { "  " },
                    profile.id,
                    profile.ssid,
                    client_security_label(profile.security),
                    if profile.autoconnect { "on" } else { "off" },
                    profile.priority,
                    if profile.has_passphrase {
                        "  key: saved"
                    } else {
                        ""
                    }
                ),
                selected_style(is_selected),
            )
        })
        .collect::<Vec<_>>();

    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(offset).collect::<Vec<_>>()).block(block),
        area,
    );
}

fn render_profile_actions(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    ui: &mut UiLayout,
    view: &WifiProfilesView,
) {
    let target = view
        .profiles
        .get(view.selected_profile)
        .map_or("none", |p| p.id.as_str());
    let title = format!("Profile management — target: {target}");
    let block = panel(&title);
    let inner = block.inner(area);

    let has_header = view.profiles.get(view.selected_profile).is_some();
    let header_lines = if has_header { 2 } else { 0 };

    let list_area = Rect::new(
        inner.x,
        inner.y + header_lines as u16,
        inner.width,
        inner.height.saturating_sub(header_lines as u16),
    );
    let offset = view
        .selected
        .saturating_sub(list_area.height.saturating_sub(1) as usize);

    ui.list_area = Some(list_area);
    ui.list_count = WifiProfileAction::for_interface(&view.interface).len();
    ui.list_row_height = 1;
    ui.list_scroll_offset = offset;

    let mut lines = Vec::new();
    if let Some(profile) = view.profiles.get(view.selected_profile) {
        lines.push(Line::styled(
            format!(
                "  ID: {} │ SSID: {} │ Security: {} │ Priority: {} │ Auto: {}",
                profile.id,
                profile.ssid,
                client_security_label(profile.security),
                profile.priority,
                if profile.autoconnect { "on" } else { "off" }
            ),
            Style::default().fg(theme::ACCENT),
        ));
        lines.push(Line::from(""));
    }

    for (slot, action) in WifiProfileAction::for_interface(&view.interface)
        .iter()
        .enumerate()
        .skip(offset)
    {
        let is_selected = view.selected == slot;
        lines.push(Line::styled(
            format!(
                "{}{}",
                if is_selected { "▶ " } else { "  " },
                action.label()
            ),
            selected_style(is_selected),
        ));
    }

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "  ↑/↓: choose action │ Enter: execute │ Esc: back",
        Style::default().fg(theme::MUTED),
    ));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

pub(crate) async fn handle_wifi_profiles_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(view) = app.wifi_profiles.as_mut() else {
        app.screen = Screen::Wifi;
        return;
    };
    if view.delete_confirmation.is_some() {
        match key {
            KeyCode::Enter => {
                let id = view
                    .delete_confirmation
                    .take()
                    .expect("confirmation is open");
                profile_request(app, client, Ok(Request::DeleteWifiClientProfile { id })).await;
            }
            KeyCode::Esc => view.delete_confirmation = None,
            _ => {}
        }
        return;
    }

    if key == KeyCode::Esc && view.mode == WifiProfilesMode::Connect {
        app.screen = Screen::Wifi;
        return;
    }
    match view.mode {
        WifiProfilesMode::Menu => match key {
            KeyCode::Esc => {
                app.wifi_profiles = None;
                app.screen = Screen::Wifi;
            }
            KeyCode::Up => {
                view.selected = view.selected.saturating_sub(1);
            }
            KeyCode::Down => {
                let max_index = WifiProfilesMenuAction::ALL.len().saturating_sub(1);
                view.selected = (view.selected + 1).min(max_index);
            }
            KeyCode::Home => {
                view.selected = 0;
            }
            KeyCode::End => {
                view.selected = WifiProfilesMenuAction::ALL.len().saturating_sub(1);
            }
            KeyCode::Enter => activate_profile_row(app, client).await,
            _ => {}
        },
        WifiProfilesMode::Management | WifiProfilesMode::Connect => {
            if view.profiles.is_empty() {
                match key {
                    KeyCode::Esc => {
                        view.mode = WifiProfilesMode::Menu;
                        view.selected = 0;
                    }
                    KeyCode::Enter => {
                        let interface = view.interface.clone();
                        open_create_profile(app, interface);
                    }
                    _ => {}
                }
                return;
            }

            let count = view.profiles.len();
            match key {
                KeyCode::Esc => {
                    view.mode = WifiProfilesMode::Menu;
                    view.selected = 0;
                }
                KeyCode::Up => {
                    view.selected = view.selected.saturating_sub(1);
                    view.selected_profile = view.selected;
                }
                KeyCode::Down if view.selected + 1 < count => {
                    view.selected += 1;
                    view.selected_profile = view.selected;
                }
                KeyCode::Home => {
                    view.selected = 0;
                    view.selected_profile = 0;
                }
                KeyCode::End => {
                    view.selected = count.saturating_sub(1);
                    view.selected_profile = view.selected;
                }
                KeyCode::Enter => activate_profile_row(app, client).await,
                _ => {}
            }
        }
        WifiProfilesMode::ProfileActions => match key {
            KeyCode::Esc => {
                view.mode = WifiProfilesMode::Management;
                view.selected = view.selected_profile;
            }
            KeyCode::Up => {
                view.selected = view.selected.saturating_sub(1);
            }
            KeyCode::Down => {
                let max_index = WifiProfileAction::for_interface(&view.interface)
                    .len()
                    .saturating_sub(1);
                view.selected = (view.selected + 1).min(max_index);
            }
            KeyCode::Home => {
                view.selected = 0;
            }
            KeyCode::End => {
                view.selected = WifiProfileAction::for_interface(&view.interface)
                    .len()
                    .saturating_sub(1);
            }
            KeyCode::Enter => activate_profile_row(app, client).await,
            _ => {}
        },
    }
}

async fn activate_profile_action(app: &mut TuiApp, client: &ApiClient, action: WifiProfileAction) {
    if matches!(
        action,
        WifiProfileAction::Activate | WifiProfileAction::Deactivate
    ) && app
        .wifi_profiles
        .as_ref()
        .is_none_or(|view| view.interface.is_empty())
    {
        app.push_message(
            LogLevel::Warn,
            "Select an input interface in Wi-Fi to connect a profile",
        );
        return;
    }
    match action {
        WifiProfileAction::Back => {
            if let Some(current) = app.wifi_profiles.as_mut() {
                current.mode = WifiProfilesMode::Management;
                current.selected = current.selected_profile;
            }
        }
        WifiProfileAction::Deactivate => {
            let interface = app
                .wifi_profiles
                .as_ref()
                .map(|v| v.interface.clone())
                .unwrap_or_default();
            profile_request(
                app,
                client,
                Ok(Request::DeactivateWifiClientProfile { interface }),
            )
            .await;
        }
        WifiProfileAction::Activate | WifiProfileAction::Edit | WifiProfileAction::Delete => {
            let Some((interface, profile)) = app.wifi_profiles.as_ref().and_then(|v| {
                v.profiles
                    .get(v.selected_profile)
                    .cloned()
                    .map(|p| (v.interface.clone(), p))
            }) else {
                app.push_message(LogLevel::Warn, "Select a profile first");
                return;
            };

            match action {
                WifiProfileAction::Activate => {
                    open_wifi_connect_prompt(app, client, interface, profile.id, profile.ssid)
                        .await;
                }
                WifiProfileAction::Edit => {
                    app.wifi_profile_editor =
                        Some(WifiProfileEditor::from_profile(interface, &profile));
                    app.screen = Screen::WifiProfileEditor;
                }
                WifiProfileAction::Delete => {
                    if let Some(current) = app.wifi_profiles.as_mut() {
                        current.delete_confirmation = Some(profile.id.clone());
                    }
                }
                WifiProfileAction::Deactivate | WifiProfileAction::Back => unreachable!(),
            }
        }
    }
}

async fn activate_profile_row(app: &mut TuiApp, client: &ApiClient) {
    let Some((mode, selected, is_empty, interface)) = app.wifi_profiles.as_ref().map(|v| {
        (
            v.mode,
            v.selected,
            v.profiles.is_empty(),
            v.interface.clone(),
        )
    }) else {
        return;
    };
    match mode {
        WifiProfilesMode::Menu => match WifiProfilesMenuAction::from_index(selected) {
            Some(WifiProfilesMenuAction::Management) => {
                if let Some(current) = app.wifi_profiles.as_mut() {
                    current.mode = WifiProfilesMode::Management;
                    current.selected = if current.profiles.is_empty() {
                        0
                    } else {
                        current.selected_profile.min(current.profiles.len() - 1)
                    };
                }
            }
            Some(WifiProfilesMenuAction::CreateNew) => {
                open_create_profile(app, interface);
            }
            None => {}
        },
        WifiProfilesMode::Connect if !is_empty => {
            activate_profile_action(app, client, WifiProfileAction::Activate).await;
        }
        WifiProfilesMode::Management | WifiProfilesMode::Connect => {
            if is_empty {
                open_create_profile(app, interface);
            } else if let Some(current) = app.wifi_profiles.as_mut() {
                current.mode = WifiProfilesMode::ProfileActions;
                current.selected = 0;
            }
        }
        WifiProfilesMode::ProfileActions => {
            if let Some(action) = WifiProfileAction::for_interface(&interface)
                .get(selected)
                .copied()
            {
                activate_profile_action(app, client, action).await;
            }
        }
    }
}

async fn profile_request(
    app: &mut TuiApp,
    client: &ApiClient,
    request: Result<Request, &'static str>,
) {
    let request = match request {
        Ok(request) => request,
        Err(message) => {
            app.push_message(LogLevel::Warn, message);
            return;
        }
    };
    match client.request(&request).await {
        Ok(Response::NetworkChangePending { change }) => {
            app.pending_focus = 0;
            app.pending = Some(change);
            app.pending_return_screen = Screen::WifiProfiles;
            app.screen = Screen::PendingChange;
            app.push_message(
                LogLevel::Info,
                "Wi-Fi client deactivation is tentative; confirm before the rollback timer expires",
            );
        }
        Ok(Response::InterfaceIntentSaved { interface, .. }) => {
            app.push_message(
                LogLevel::Info,
                format!("Saved settings updated for missing interface {interface}"),
            );
            load_wifi_data(app, client).await;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(Response::WifiClientProfileActivated { .. })
        | Ok(Response::WifiClientDisabled { .. }) => {
            app.push_message(LogLevel::Info, "Wi-Fi profile action applied");
            let interface = app
                .wifi_profiles
                .as_ref()
                .map(|v| v.interface.clone())
                .unwrap_or_default();
            let mode = app
                .wifi_profiles
                .as_ref()
                .map(|v| v.mode)
                .unwrap_or(WifiProfilesMode::Management);
            open_profiles(app, client, interface, mode).await;
        }
        Ok(Response::WifiClientProfileDeleted { .. }) => {
            app.push_message(LogLevel::Info, "Wi-Fi profile action applied");
            let interface = app
                .wifi_profiles
                .as_ref()
                .map(|v| v.interface.clone())
                .unwrap_or_default();
            open_profiles(app, client, interface, WifiProfilesMode::Management).await;
        }
        Ok(Response::WifiClientProfileError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"))
        }
        Ok(Response::WifiClientError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"))
        }
        Ok(response) => report_unexpected(app, response),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}
