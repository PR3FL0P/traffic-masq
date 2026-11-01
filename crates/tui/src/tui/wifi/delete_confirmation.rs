use super::*;
use crate::tui::confirmation::Dialog;

pub(in crate::tui) fn profile_delete_dialog(app: &TuiApp) -> Option<Dialog> {
    match app.screen {
        Screen::WifiProfiles => client_dialog(app.wifi_ui.wifi_profiles.as_ref()?),
        Screen::WifiApProfiles => ap_dialog(app.wifi_ui.wifi_ap_profiles.as_ref()?),
        _ => None,
    }
}

pub(super) fn client_dialog(view: &WifiProfilesView) -> Option<Dialog> {
    let id = view.delete_confirmation.as_ref()?;
    let ssid = view
        .profiles
        .iter()
        .find(|profile| &profile.id == id)
        .map_or("", |profile| profile.ssid.as_str());
    Some(delete_dialog(
        id,
        ssid,
        "Saved interface settings are kept. Disconnect an active profile before deleting it.",
    ))
}

pub(super) fn ap_dialog(view: &WifiApProfilesView) -> Option<Dialog> {
    let id = view.delete_confirmation.as_ref()?;
    let ssid = view
        .profiles
        .iter()
        .find(|profile| &profile.id == id)
        .map_or("", |profile| profile.settings.ssid.as_str());
    Some(delete_dialog(
        id,
        ssid,
        "The running access point and saved interface settings are kept.",
    ))
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
