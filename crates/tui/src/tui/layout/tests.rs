use super::*;

#[test]
fn point_in_rect_matches_inclusive_top_left_exclusive_bottom_right() {
    let rect = Rect::new(2, 3, 4, 5);
    assert!(point_in_rect((2, 3), rect));
    assert!(point_in_rect((5, 7), rect));
    assert!(!point_in_rect((6, 3), rect));
    assert!(!point_in_rect((2, 8), rect));
    assert!(!point_in_rect((1, 3), rect));
}

#[test]
fn section_at_finds_the_tab_containing_the_click_point() {
    let tabs = [
        (Rect::new(0, 0, 8, 1), Section::Dashboard),
        (Rect::new(8, 0, 8, 1), Section::Interfaces),
        (Rect::new(16, 0, 8, 1), Section::Dhcp),
        (Rect::new(24, 0, 8, 1), Section::DhcpClient),
        (Rect::new(32, 0, 8, 1), Section::Router),
        (Rect::new(40, 0, 8, 1), Section::Vpn),
        (Rect::new(48, 0, 8, 1), Section::Wifi),
        (Rect::new(56, 0, 8, 1), Section::Settings),
        (Rect::new(64, 0, 8, 1), Section::Log),
    ];
    assert_eq!(section_at(&tabs, (3, 0)), Some(Section::Dashboard));
    assert_eq!(section_at(&tabs, (11, 0)), Some(Section::Interfaces));
    assert_eq!(section_at(&tabs, (19, 0)), Some(Section::Dhcp));
    assert_eq!(section_at(&tabs, (27, 0)), Some(Section::DhcpClient));
    assert_eq!(section_at(&tabs, (35, 0)), Some(Section::Router));
    assert_eq!(section_at(&tabs, (43, 0)), Some(Section::Vpn));
    assert_eq!(section_at(&tabs, (51, 0)), Some(Section::Wifi));
    assert_eq!(section_at(&tabs, (59, 0)), Some(Section::Settings));
    assert_eq!(section_at(&tabs, (67, 0)), Some(Section::Log));
    assert_eq!(section_at(&tabs, (73, 0)), None);
}

#[test]
fn section_at_works_without_dhcp_client_tab() {
    let tabs = [
        (Rect::new(0, 0, 8, 1), Section::Dashboard),
        (Rect::new(8, 0, 8, 1), Section::Interfaces),
        (Rect::new(16, 0, 8, 1), Section::Dhcp),
        (Rect::new(24, 0, 8, 1), Section::Router),
        (Rect::new(32, 0, 8, 1), Section::Vpn),
        (Rect::new(40, 0, 8, 1), Section::Wifi),
        (Rect::new(48, 0, 8, 1), Section::Settings),
        (Rect::new(56, 0, 8, 1), Section::Log),
    ];
    assert_eq!(section_at(&tabs, (19, 0)), Some(Section::Dhcp));
    assert_eq!(section_at(&tabs, (27, 0)), Some(Section::Router));
}
#[test]
fn clip_interactions_removes_hidden_buttons_and_clips_lists() {
    let mut ui = UiLayout {
        buttons: vec![(Rect::new(2, 4, 5, 1), 0), (Rect::new(2, 12, 5, 1), 1)],
        list_area: Some(Rect::new(1, 5, 10, 10)),
        list_row_height: 1,
        list_count: 20,
        list_scroll_offset: 3,
        ..Default::default()
    };
    let bounds = Rect::new(0, 3, 20, 7);
    ui.clip_interactions(bounds);

    assert_eq!(ui.buttons, vec![(Rect::new(2, 4, 5, 1), 0)]);
    assert_eq!(ui.list_area, Some(Rect::new(1, 5, 10, 5)));
    assert_eq!(ui.list_scroll_offset, 3);
    assert_eq!(ui.content_area, Some(bounds));
}

#[test]
fn clip_interactions_drops_list_outside_content() {
    let mut ui = UiLayout {
        list_area: Some(Rect::new(0, 20, 10, 2)),
        list_count: 2,
        ..Default::default()
    };
    ui.clip_interactions(Rect::new(0, 3, 20, 10));
    assert!(ui.list_area.is_none());
    assert_eq!(ui.list_count, 0);
}

#[test]
fn narrow_footer_keeps_action_meanings() {
    let app = TuiApp {
        screen: Screen::Router,
        ..Default::default()
    };
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 4)).unwrap();
    terminal.draw(|f| render_footer(f, f.area(), &app)).unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(text.contains("Enter:activate"));
    assert!(text.contains("Esc:back"));
    assert!(text.contains("Ctrl+K:all keys"));
}

#[test]
fn wrapping_form_rows_preserves_cursor_style_and_graphemes() {
    let cursor = Style::default()
        .bg(theme::SELECTED_BG)
        .fg(theme::SELECTED_FG);
    let rows = wrap_styled_lines(
        vec![Line::from(vec![
            Span::raw("ab界"),
            Span::styled("e\u{301}", cursor),
            Span::raw("cd"),
        ])],
        4,
    );
    assert_eq!(
        rows.iter().map(Line::to_string).collect::<Vec<_>>(),
        ["ab界", "e\u{301}cd"]
    );
    assert_eq!(rows[1].spans[0].content, "e\u{301}");
    assert_eq!(rows[1].spans[0].style, cursor);
}
