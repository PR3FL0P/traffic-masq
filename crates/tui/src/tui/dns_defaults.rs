//! DNS defaults are copied when creating a DHCP server, never applied to existing servers.
use crossterm::event::KeyCode;
use ratatui::{layout::Rect, style::Style, text::Line, widgets::Paragraph};
use traffic_masq_protocol::DhcpDnsDefaults;

use super::{
    api::{
        client::ApiClient,
        model::{Request, Response},
    },
    layout,
    logs::LogLevel,
    theme, Screen, TuiApp,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Servers,
    Save,
    Reload,
}
const FIELDS: [Field; 3] = [Field::Servers, Field::Save, Field::Reload];

#[derive(Debug, Clone)]
pub(crate) struct Editor {
    field: Field,
    servers: String,
    cursor: usize,
    error: Option<String>,
}

pub(crate) async fn fetch(client: &ApiClient) -> anyhow::Result<DhcpDnsDefaults> {
    match client.request(&Request::GetDhcpDnsDefaults).await? {
        Response::DhcpDnsDefaults { settings } => Ok(settings),
        Response::Error { message } => anyhow::bail!(message),
        response => anyhow::bail!("Unexpected DNS defaults response: {response:?}"),
    }
}

pub(crate) fn format_servers(settings: &DhcpDnsDefaults) -> String {
    settings
        .servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_servers(value: &str) -> Result<DhcpDnsDefaults, String> {
    let servers = if value.trim().is_empty() {
        Vec::new()
    } else {
        value
            .split(',')
            .map(|part| {
                part.trim().parse().map_err(|_| {
                    "Enter IPv4 DNS addresses separated by commas, or leave empty".to_string()
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let settings = DhcpDnsDefaults { servers };
    settings.validate()?;
    Ok(settings)
}

pub(crate) async fn open(app: &mut TuiApp, client: &ApiClient) {
    match fetch(client).await {
        Ok(settings) => {
            let servers = format_servers(&settings);
            app.dns_defaults = Some(Editor {
                field: Field::Servers,
                cursor: super::input::grapheme_count(&servers),
                servers,
                error: None,
            });
            app.screen = Screen::DnsDefaults;
        }
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) fn render(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(editor) = &app.dns_defaults else {
        return;
    };
    let style = Style::default().fg(theme::ACCENT);
    let mut lines = vec![layout::text_field_row(
        "DNS servers",
        &editor.servers,
        editor.field == Field::Servers,
        editor.cursor,
        true,
        style,
    )];
    if let Some(error) = &editor.error {
        lines.push(Line::styled(error.clone(), Style::default().fg(theme::BAD)));
    }
    lines.extend([
        Line::from("  IPv4 addresses separated by commas. Empty = do not advertise DNS."),
        Line::from("  Used for new DHCP servers, including Wi-Fi AP setup."),
        Line::from("  Existing servers keep their DNS settings. No restart required."),
        Line::from(""),
        layout::field_row("Save", editor.field == Field::Save, style),
        layout::field_row("Reload", editor.field == Field::Reload, style),
    ]);
    let block = layout::panel("Default DNS for new DHCP servers");
    let inner = block.inner(area);
    let offset = layout::focused_lines_offset(&lines, inner.height) as u16;
    let save_row = if editor.error.is_some() { 6 } else { 5 };
    for (row, slot, width) in [
        (0u16, 0, inner.width),
        (save_row, 1, 6),
        (save_row + 1, 2, 8),
    ] {
        if row >= offset && row - offset < inner.height {
            app.ui.buttons.push((
                Rect::new(inner.x, inner.y + row - offset, width.min(inner.width), 1),
                slot,
            ));
        }
    }
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines).scroll((offset, 0)), inner);
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let Some(editor) = &mut app.dns_defaults {
        editor.field = FIELDS[slot.min(2)];
    }
}

pub(crate) async fn handle_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = &mut app.dns_defaults else {
        return;
    };
    match key {
        KeyCode::Esc => app.screen = Screen::Settings,
        KeyCode::Up | KeyCode::Down => {
            editor.field = super::input::move_clamped(&FIELDS, editor.field, key == KeyCode::Down)
        }
        KeyCode::Enter if editor.field == Field::Servers => editor.field = Field::Save,
        KeyCode::Enter if editor.field == Field::Reload => open(app, client).await,
        KeyCode::Enter if editor.field == Field::Save => {
            let settings = match parse_servers(&editor.servers) {
                Ok(settings) => settings,
                Err(error) => {
                    editor.error = Some(error);
                    editor.field = Field::Servers;
                    return;
                }
            };
            match client
                .request(&Request::ConfigureDhcpDnsDefaults { settings })
                .await
            {
                Ok(Response::DhcpDnsDefaults { settings }) => {
                    editor.servers = format_servers(&settings);
                    editor.cursor = super::input::grapheme_count(&editor.servers);
                    editor.error = None;
                    app.push_message(LogLevel::Info, "DNS defaults saved for new DHCP servers");
                }
                Ok(Response::Error { message }) => editor.error = Some(message),
                Ok(response) => editor.error = Some(format!("Unexpected response: {response:?}")),
                Err(error) => editor.error = Some(error.to_string()),
            }
        }
        key if editor.field == Field::Servers
            && super::input::TextEditor::new(&mut editor.servers, &mut editor.cursor)
                .handle_key(key) =>
        {
            editor.error = None;
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_custom_and_empty_dns_but_rejects_invalid_addresses() {
        assert_eq!(parse_servers("1.1.1.1, 9.9.9.9").unwrap().servers.len(), 2);
        assert!(parse_servers("  ").unwrap().servers.is_empty());
        for input in [
            "1.1.1.1,",
            "example.com",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(parse_servers(input).is_err(), "{input}");
        }
    }
}
