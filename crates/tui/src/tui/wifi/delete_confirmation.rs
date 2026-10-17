use super::*;
use crate::tui::confirmation::Dialog;

pub(in crate::tui) fn profile_delete_dialog(app: &TuiApp) -> Option<Dialog> {
    let (id, ssid, consequences) = match app.screen {
        Screen::WifiProfiles => {
            let view = app.wifi_profiles.as_ref()?;
            let id = view.delete_confirmation.as_ref()?;
            let ssid = view
                .profiles
                .iter()
                .find(|p| &p.id == id)
                .map_or("", |p| p.ssid.as_str());
            (id, ssid, "Saved interface settings are kept. Disconnect an active profile before deleting it.")
        }
        Screen::WifiApProfiles => {
            let view = app.wifi_ap_profiles.as_ref()?;
            let id = view.delete_confirmation.as_ref()?;
            let ssid = view
                .profiles
                .iter()
                .find(|p| &p.id == id)
                .map_or("", |p| p.settings.ssid.as_str());
            (
                id,
                ssid,
                "The running access point and saved interface settings are kept.",
            )
        }
        _ => return None,
    };
    Some(delete_dialog(id, ssid, consequences))
}

fn delete_dialog(id: &str, ssid: &str, consequences: &str) -> Dialog {
    Dialog {
        secondary: None,
        title: "Delete saved Wi-Fi profile?",
        action: "Delete",
        lines: vec![
            format!("Profile: {id}"),
            format!("SSID: {ssid}"),
            String::new(),
            "The saved profile and its stored password will be deleted.".into(),
            consequences.into(),
            "Deletion is immediate and cannot be undone.".into(),
        ],
    }
}

pub(super) fn render_delete_confirmation(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    ui: &mut UiLayout,
    id: &str,
    ssid: &str,
    consequences: &str,
    focus: usize,
) {
    delete_dialog(id, ssid, consequences).render(frame, area, ui, focus);
}
