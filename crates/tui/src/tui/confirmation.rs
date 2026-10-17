//! Shared presentation and input contract for immediate action confirmations.
use super::{
    layout::{panel, UiLayout},
    theme, Screen, TuiApp,
};
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::Line,
    widgets::{Paragraph, Wrap},
};

pub(super) struct Dialog {
    pub(super) title: &'static str,
    pub(super) action: &'static str,
    pub(super) secondary: Option<&'static str>,
    pub(super) lines: Vec<String>,
}

#[derive(Clone, Copy)]
enum Action {
    Execute,
    Cancel,
    Secondary,
}

pub(super) fn key_for_slot(slot: usize) -> Option<KeyCode> {
    match slot {
        slot if slot == Action::Execute as usize => Some(KeyCode::Enter),
        slot if slot == Action::Cancel as usize => Some(KeyCode::Esc),
        slot if slot == Action::Secondary as usize => Some(KeyCode::Delete),
        _ => None,
    }
}

pub(super) fn current(app: &TuiApp) -> Option<Dialog> {
    match app.screen {
        Screen::WifiProfiles | Screen::WifiApProfiles => super::wifi::profile_delete_dialog(app),
        Screen::WifiEditor => super::wifi::discard_confirmation(app),
        Screen::InterfaceEditor => super::interfaces::confirmation(app),
        Screen::RouterHealth => super::router_health::confirmation(app),
        Screen::Settings => super::settings::confirmation(app),
        Screen::WifiStations => super::wifi_stations::confirmation(app),
        Screen::Provisioning => super::provisioning::confirmation(app),
        Screen::Vpn => super::vpn::confirmation(app),
        Screen::Log if app.logs_clear_confirmation => Some(Dialog {
            secondary: None,
            title: "Clear client log?",
            action: "Clear",
            lines: vec![
                "Target: client log for the current connection".into(),
                "The saved client log history will be cleared. This cannot be undone.".into(),
            ],
        }),
        _ => None,
    }
}

impl Dialog {
    pub(super) fn render(
        &self,
        frame: &mut ratatui::Frame<'_>,
        area: Rect,
        ui: &mut UiLayout,
        focus: usize,
    ) {
        let block = panel(self.title);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let chunks = Layout::vertical([
            Constraint::Min(0),
            Constraint::Length(if self.secondary.is_some() { 3 } else { 2 }),
        ])
        .split(inner);
        frame.render_widget(
            Paragraph::new(
                self.lines
                    .iter()
                    .cloned()
                    .map(Line::from)
                    .collect::<Vec<_>>(),
            )
            .wrap(Wrap { trim: false }),
            chunks[0],
        );
        ui.list_area = None;
        ui.list_count = 0;
        ui.buttons.clear();
        let mut actions = vec![
            (Action::Execute, format!("[{}]", self.action)),
            (
                Action::Cancel,
                if self.secondary.is_some() {
                    "[Continue editing]".into()
                } else {
                    "[Cancel]".into()
                },
            ),
        ];
        if let Some(label) = self.secondary {
            actions.push((Action::Secondary, format!("[{label}]")));
        }
        for (row, (action, label)) in actions.into_iter().enumerate() {
            let active = action as usize == focus;
            let color = if active {
                theme::WARN
            } else {
                theme::SELECTED_BG
            };
            let label = format!("{}{label}", if active { "▶ " } else { "  " });
            let button = Rect::new(
                chunks[1].x,
                chunks[1].y.saturating_add(row as u16),
                (label.len() as u16).min(chunks[1].width),
                1,
            )
            .intersection(chunks[1]);
            if button.is_empty() {
                continue;
            }
            ui.buttons.push((button, action as usize));
            frame.render_widget(
                Paragraph::new(label).style(
                    Style::default()
                        .fg(theme::SELECTED_FG)
                        .bg(color)
                        .add_modifier(Modifier::BOLD),
                ),
                button,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::{self, api::client::ApiClient, logs};
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    #[tokio::test]
    async fn modal_blocks_navigation_and_supports_both_mouse_actions() {
        for confirm in [false, true] {
            let client = ApiClient::new("/nonexistent.sock");
            let mut app = TuiApp {
                screen: Screen::Log,
                ..Default::default()
            };
            app.push_message(logs::LogLevel::Info, "keep this entry");
            app.logs_focus = logs::LogFocus::Clear;
            logs::handle_log_key(&mut app, KeyCode::Enter);
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
            terminal.draw(|f| tui::render(f, &mut app, false)).unwrap();
            for key in [
                KeyCode::Down,
                KeyCode::Left,
                KeyCode::Tab,
                KeyCode::Char('y'),
            ] {
                tui::handle_key(&mut app, key, &client, false).await;
            }
            tui::navigate_to_section(&mut app, tui::Section::Vpn, &client, false).await;
            assert_eq!(app.screen, Screen::Log);
            assert!(app.logs_clear_confirmation);
            assert_eq!(app.logs_focus, logs::LogFocus::Clear);
            assert!(app.ui.list_area.is_none());
            assert_eq!(app.ui.buttons.len(), 2);
            let (rect, _) = app.ui.buttons[if confirm { 0 } else { 1 }];
            assert!(rect.bottom() <= 20);
            tui::handle_mouse(
                &mut app,
                MouseEvent {
                    kind: MouseEventKind::Down(MouseButton::Left),
                    column: rect.x,
                    row: rect.y,
                    modifiers: KeyModifiers::NONE,
                },
                &client,
                false,
            )
            .await;
            assert!(!app.logs_clear_confirmation);
            if confirm {
                assert_eq!(app.logs.len(), 1);
                assert_eq!(app.logs[0].message, "Log cleared");
            } else {
                assert_eq!(app.logs[0].message, "keep this entry");
            }
        }
    }
}
