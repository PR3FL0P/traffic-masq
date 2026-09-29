use super::*;
use crate::api::model::WifiApProfileSummary;

#[derive(Debug, Clone)]
pub(crate) struct WifiApProfilesView {
    pub(crate) interface: String,
    pub(crate) profiles: Vec<WifiApProfileSummary>,
    pub(crate) mode: WifiProfilesMode,
    pub(crate) selected: usize,
    pub(crate) selected_profile: usize,
    pub(crate) delete_confirmation: Option<String>,
}

const ACTIONS: [WifiProfileAction; 4] = [
    WifiProfileAction::Activate,
    WifiProfileAction::Edit,
    WifiProfileAction::Delete,
    WifiProfileAction::Back,
];

impl WifiApProfilesView {
    fn actions(&self) -> &'static [WifiProfileAction] {
        if self.interface.is_empty() {
            &ACTIONS[1..]
        } else {
            &ACTIONS
        }
    }

    pub(crate) fn select(&mut self, index: usize) {
        let count = match self.mode {
            WifiProfilesMode::Menu => 2,
            WifiProfilesMode::Management => self.profiles.len(),
            WifiProfilesMode::ProfileActions => self.actions().len(),
        };
        self.selected = index.min(count.saturating_sub(1));
        if self.mode == WifiProfilesMode::Management {
            self.selected_profile = self.selected;
        }
    }
}

pub(super) async fn open_ap_profiles(
    app: &mut TuiApp,
    client: &ApiClient,
    interface: String,
    mode: WifiProfilesMode,
) {
    match client.request(&Request::ListWifiApProfiles).await {
        Ok(Response::WifiApProfiles { mut profiles }) => {
            profiles.sort_by(|a, b| a.id.cmp(&b.id));
            let previous = app
                .wifi_ap_profiles
                .as_ref()
                .filter(|v| v.interface == interface);
            let selected_profile = previous
                .and_then(|v| v.profiles.get(v.selected_profile))
                .and_then(|p| profiles.iter().position(|new| new.id == p.id))
                .unwrap_or_else(|| {
                    previous
                        .map_or(0, |v| v.selected_profile)
                        .min(profiles.len().saturating_sub(1))
                });
            let mode = if profiles.is_empty() && mode == WifiProfilesMode::ProfileActions {
                WifiProfilesMode::Management
            } else {
                mode
            };
            app.wifi_ap_profiles = Some(WifiApProfilesView {
                interface,
                profiles,
                mode,
                selected_profile,
                selected: if mode == WifiProfilesMode::Management {
                    selected_profile
                } else {
                    0
                },
                delete_confirmation: None,
            });
            app.screen = Screen::WifiApProfiles;
        }
        Ok(Response::WifiError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"))
        }
        Ok(response) => report_unexpected(app, response),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(super) fn open_ap_profile_editor(
    app: &mut TuiApp,
    interface: String,
    profile: Option<&WifiApProfileSummary>,
) {
    // A new profile must never inherit the running AP's credential state.
    let mut editor = WifiEditor::from_row(&WifiRow {
        interface,
        role: WifiRole::Unknown,
        ap: None,
        client: None,
    });
    editor.profile_mode = true;
    editor.field = WifiField::ProfileId;
    if let Some(profile) = profile {
        editor.profile_id = profile.id.clone();
        editor.original_profile_id = Some(profile.id.clone());
        editor.ssid = profile.settings.ssid.clone();
        editor.security = profile.settings.security;
        editor.country_code = profile.settings.country_code.clone().unwrap_or_default();
        editor.radio_settings = Some(profile.settings.clone());
        editor.configure_dhcp = profile.configure_dhcp;
        editor.disable_dhcp = profile.disable_dhcp;
        editor.subnet = profile.subnet.map(|ip| ip.to_string()).unwrap_or_default();
        editor.existing = profile.has_passphrase;
        editor.field = WifiField::Ssid;
    }
    editor.reset_cursor();
    app.wifi_editor = Some(editor);
    app.screen = Screen::WifiEditor;
}

pub(crate) fn render_wifi_ap_profiles(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
) {
    let Some(view) = &app.wifi_ap_profiles else {
        return;
    };
    let target = view.profiles.get(view.selected_profile);
    let title = if let Some(id) = &view.delete_confirmation {
        format!("Delete {id}? Y: confirm, any other key: cancel")
    } else {
        format!(
            "Saved AP profiles — {}",
            if view.interface.is_empty() {
                "library"
            } else {
                &view.interface
            }
        )
    };
    let block = panel(&title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut list_area = inner;
    let labels: Vec<String> = match view.mode {
        WifiProfilesMode::Menu => vec![
            format!("Management — {} saved profiles", view.profiles.len()),
            "Create new profile".into(),
        ],
        WifiProfilesMode::Management if view.profiles.is_empty() => {
            vec!["No saved AP profiles. Enter: create a profile".into()]
        }
        WifiProfilesMode::Management => view
            .profiles
            .iter()
            .map(|p| {
                format!(
                    "{:<16} {:<28} {} · {} · channel {}",
                    p.id,
                    p.settings.ssid,
                    describe_ap_security(p.settings.security),
                    p.settings.band,
                    if p.settings.channel == 0 {
                        "Auto".into()
                    } else {
                        p.settings.channel.to_string()
                    }
                )
            })
            .collect(),
        WifiProfilesMode::ProfileActions => {
            if let Some(profile) = target {
                let header_height = inner.height.min(2);
                frame.render_widget(
                    Paragraph::new(format!(
                        "ID: {} │ SSID: {} │ {}",
                        profile.id,
                        profile.settings.ssid,
                        describe_ap_security(profile.settings.security)
                    ))
                    .style(Style::default().fg(theme::ACCENT)),
                    Rect::new(inner.x, inner.y, inner.width, header_height),
                );
                list_area.y += header_height;
                list_area.height = list_area.height.saturating_sub(header_height);
            }
            view.actions()
                .iter()
                .map(|action| {
                    if *action == WifiProfileAction::Activate {
                        "Apply profile"
                    } else {
                        action.label()
                    }
                    .into()
                })
                .collect()
        }
    };
    let offset = view
        .selected
        .saturating_sub(list_area.height.saturating_sub(1) as usize);
    app.ui.list_area = Some(list_area);
    app.ui.list_count = labels.len();
    app.ui.list_row_height = 1;
    app.ui.list_scroll_offset = offset;
    let lines: Vec<Line<'_>> = labels
        .into_iter()
        .enumerate()
        .skip(offset)
        .map(|(i, label)| {
            Line::styled(
                format!("{}{}", if view.selected == i { "▶ " } else { "  " }, label),
                selected_style(view.selected == i),
            )
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), list_area);
}

pub(crate) async fn handle_wifi_ap_profiles_key(
    app: &mut TuiApp,
    key: KeyCode,
    client: &ApiClient,
) {
    let Some(view) = app.wifi_ap_profiles.as_mut() else {
        app.screen = Screen::Wifi;
        return;
    };
    if let Some(id) = view.delete_confirmation.take() {
        if matches!(key, KeyCode::Char('y' | 'Y')) {
            let interface = view.interface.clone();
            match client.request(&Request::DeleteWifiApProfile { id }).await {
                Ok(Response::WifiApProfileDeleted { .. }) => {
                    app.push_message(
                        LogLevel::Info,
                        "AP profile deleted; running access point is unchanged",
                    );
                    open_ap_profiles(app, client, interface, WifiProfilesMode::Management).await;
                }
                Ok(Response::WifiError { detail }) => {
                    app.push_message(LogLevel::Error, format!("{detail:?}"))
                }
                Ok(response) => report_unexpected(app, response),
                Err(error) => app.push_message(LogLevel::Error, error.to_string()),
            }
        }
        return;
    }
    match key {
        KeyCode::Up => view.select(view.selected.saturating_sub(1)),
        KeyCode::Down => view.select(view.selected.saturating_add(1)),
        KeyCode::Home => view.select(0),
        KeyCode::End => view.select(usize::MAX),
        KeyCode::Esc => match view.mode {
            WifiProfilesMode::Menu => {
                app.wifi_ap_profiles = None;
                app.screen = Screen::Wifi;
            }
            WifiProfilesMode::Management => {
                view.mode = WifiProfilesMode::Menu;
                view.select(0);
            }
            WifiProfilesMode::ProfileActions => {
                view.mode = WifiProfilesMode::Management;
                view.select(view.selected_profile);
            }
        },
        KeyCode::Enter => match view.mode {
            WifiProfilesMode::Menu => {
                if view.selected == 0 {
                    view.mode = WifiProfilesMode::Management;
                    view.select(view.selected_profile);
                } else {
                    let interface = view.interface.clone();
                    open_ap_profile_editor(app, interface, None);
                }
            }
            WifiProfilesMode::Management => {
                if view.profiles.is_empty() {
                    let interface = view.interface.clone();
                    open_ap_profile_editor(app, interface, None);
                } else {
                    view.mode = WifiProfilesMode::ProfileActions;
                    view.select(0);
                }
            }
            WifiProfilesMode::ProfileActions => {
                let Some(action) = view.actions().get(view.selected).copied() else {
                    return;
                };
                if action == WifiProfileAction::Back {
                    view.mode = WifiProfilesMode::Management;
                    view.select(view.selected_profile);
                    return;
                }
                let Some(profile) = view.profiles.get(view.selected_profile).cloned() else {
                    return;
                };
                let interface = view.interface.clone();
                match action {
                    WifiProfileAction::Edit => {
                        open_ap_profile_editor(app, interface, Some(&profile))
                    }
                    WifiProfileAction::Delete => view.delete_confirmation = Some(profile.id),
                    WifiProfileAction::Activate => {
                        if interface.is_empty() {
                            app.push_message(
                                LogLevel::Warn,
                                "Select an output interface in Wi-Fi to apply an AP profile",
                            );
                            return;
                        }
                        match client
                            .request(&Request::ActivateWifiApProfile {
                                interface,
                                profile_id: profile.id,
                            })
                            .await
                        {
                            Ok(Response::NetworkChangePending { change }) => {
                                app.pending = Some(change);
                                app.pending_return_screen = Screen::WifiApProfiles;
                                app.screen = Screen::PendingChange;
                                app.push_message(LogLevel::Info, "AP profile applied tentatively; confirm before the rollback timer expires");
                            }
                            Ok(Response::WifiError { detail }) => {
                                app.push_message(LogLevel::Error, format!("{detail:?}"))
                            }
                            Ok(response) => report_unexpected(app, response),
                            Err(error) => app.push_message(LogLevel::Error, error.to_string()),
                        }
                    }
                    _ => unreachable!(),
                }
            }
        },
        _ => {}
    }
}
