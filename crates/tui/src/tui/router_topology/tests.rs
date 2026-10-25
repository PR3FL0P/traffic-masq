use super::*;
use crossterm::event::KeyCode;
use ratatui::{backend::TestBackend, Terminal};

#[test]
fn wrapped_topology_preserves_text_styles_and_unicode_width() {
    let style = Style::default()
        .fg(theme::GOOD)
        .add_modifier(Modifier::BOLD);
    let original = "vpn-東京-long-interface → eth0";
    let lines = wrap_lines(vec![Line::styled(original, style)], 12);
    assert!(lines.len() > 1);
    assert!(lines
        .iter()
        .all(|line| line.width() <= 12 && line.style == style));
    let text: String = lines
        .iter()
        .flat_map(|line| &line.spans)
        .map(|span| span.content.as_ref())
        .collect();
    assert_eq!(text, original);
}

#[test]
fn explicit_forwarding_keeps_selected_route_section() {
    let mut router = RouterData::default();
    router.proposed_router_config.forwarding = Some(vec![]);
    let lines = topology_lines(&router, true);
    assert!(lines
        .iter()
        .any(|line| line.to_string().contains("Selected route")));
}

#[test]
fn topology_resize_clamps_scroll_and_keeps_footer_visible() {
    let mut app = TuiApp::default();
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    for (width, height) in [(30, 16), (80, 16), (120, 40)] {
        app.ui.buttons.clear();
        app.router.topology.scroll = (u16::MAX, u16::MAX);
        terminal
            .draw(|frame| render(frame, Rect::new(0, 0, width, height), &mut app, true))
            .unwrap();
        let view = &app.router.topology;
        assert_eq!(view.scroll.0, view.max_scroll.0);
        assert_eq!(view.scroll.1, 0);
        assert_eq!(app.ui.buttons[0].0.y, height - 2);
    }
}

#[test]
fn topology_view_key_navigation_and_clamping() {
    let mut view = TopologyView {
        loaded: true,
        ..Default::default()
    };
    assert!(!view.open);
    assert!(view.loaded);
    assert_eq!(view.scroll, (0, 0));

    view.show();
    assert!(view.open);
    view.page_height = 5;
    view.max_scroll = (10, 20);

    // Vertical scroll down
    view.handle_key(KeyCode::Down);
    assert_eq!(view.scroll, (1, 0));

    // Page down jumps by page_height
    view.handle_key(KeyCode::PageDown);
    assert_eq!(view.scroll, (6, 0));

    // Page down clamps to max_scroll.0
    view.handle_key(KeyCode::PageDown);
    assert_eq!(view.scroll, (10, 0));

    // Page up jumps by page_height
    view.handle_key(KeyCode::PageUp);
    assert_eq!(view.scroll, (5, 0));

    // Up decrements by 1
    view.handle_key(KeyCode::Up);
    assert_eq!(view.scroll, (4, 0));

    // End jumps to max_scroll.0
    view.handle_key(KeyCode::End);
    assert_eq!(view.scroll, (10, 0));

    // Home resets to (0, 0)
    view.handle_key(KeyCode::Home);
    assert_eq!(view.scroll, (0, 0));

    // Horizontal scroll right and left
    view.handle_key(KeyCode::Right);
    assert_eq!(view.scroll, (0, 4));
    view.handle_key(KeyCode::Left);
    assert_eq!(view.scroll, (0, 0));

    // Horizontal scroll clamps to max_scroll.1
    for _ in 0..10 {
        view.handle_key(KeyCode::Right);
    }
    assert_eq!(view.scroll, (0, 20));

    // Esc closes view and resets scroll
    view.handle_key(KeyCode::Esc);
    assert!(!view.open);
    assert_eq!(view.scroll, (0, 0));

    // 't', Enter, and Space also close view
    for close_key in [KeyCode::Char('t'), KeyCode::Enter, KeyCode::Char(' ')] {
        view.show();
        view.scroll = (3, 3);
        view.handle_key(close_key);
        assert!(!view.open);
        assert_eq!(view.scroll, (0, 0));
    }
}

#[test]
fn topology_render_button_bounds_and_hitbox() {
    let mut app = TuiApp::default();
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

    // Test collapsed / side panel mode (expanded = false)
    app.ui.buttons.clear();
    terminal
        .draw(|frame| render(frame, Rect::new(0, 0, 30, 20), &mut app, false))
        .unwrap();
    assert_eq!(app.ui.buttons.len(), 1);
    let (btn_rect, slot) = app.ui.buttons[0];
    assert_eq!(slot, 6);
    assert_eq!(btn_rect.width, 11); // "[t: expand]".len()

    // Test expanded mode (expanded = true)
    app.ui.buttons.clear();
    terminal
        .draw(|frame| render(frame, Rect::new(0, 0, 80, 24), &mut app, true))
        .unwrap();
    assert_eq!(app.ui.buttons.len(), 1);
    let (btn_rect, slot) = app.ui.buttons[0];
    assert_eq!(slot, 6);
    assert_eq!(btn_rect.width, 23); // "[Back: t / Esc / Enter]".len()
    assert!(crate::tui::layout::point_in_rect(
        (btn_rect.x + 22, btn_rect.y),
        btn_rect
    ));
}

#[test]
fn topology_lines_rendering_states() {
    let mut router = RouterData::default();
    let lines = topology_lines(&router, false);
    let text: String = lines
        .iter()
        .flat_map(|l| l.spans.iter().map(|s| s.content.as_ref()))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(text.contains("Router: disabled"));
    assert!(text.contains("VPN: none configured"));
    assert!(text.contains("Uplink: not configured"));

    // Warning when loaded is false
    router.topology.loaded = false;
    let lines_unloaded = topology_lines(&router, false);
    let text_unloaded: String = lines_unloaded
        .iter()
        .flat_map(|l| l.spans.iter().map(|s| s.content.as_ref()))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(text_unloaded.contains("Refresh incomplete / no data"));

    // Warning when staged is true
    router.staged = true;
    let lines_staged = topology_lines(&router, false);
    let text_staged: String = lines_staged
        .iter()
        .flat_map(|l| l.spans.iter().map(|s| s.content.as_ref()))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(text_staged.contains("Includes staged configuration edits"));
}

#[test]
fn explicit_forwarding_does_not_hide_chain_or_uplink() {
    let mut router = RouterData::default();
    router.proposed_router_config.forwarding = Some(vec![]);
    router.proposed_router_config.uplink = Some(traffic_masq_protocol::UplinkConfigView {
        interface: "wan0".into(),
        mode: traffic_masq_protocol::UplinkMode::External,
    });
    router.proposed_router_config.vpn_chain = vec![traffic_masq_protocol::VpnHopConfigView {
        profile_name: "exit.conf".into(),
    }];
    let text = topology_lines(&router, true)
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("No forwarding connections"));
    assert!(text.contains("VPN: tm-wg-0"));
    assert!(text.contains("Profile: exit.conf"));
    assert!(text.contains("Uplink: wan0"));
}
