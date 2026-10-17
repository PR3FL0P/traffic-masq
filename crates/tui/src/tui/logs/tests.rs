use super::*;

#[test]
fn scrolling_past_the_last_entry_moves_onto_the_action_rows() {
    let mut app = TuiApp::default();
    app.logs.push_back(LogEntry {
        at_unix: 0,
        level: LogLevel::Info,
        message: "one".to_string(),
    });

    app.logs_max_scroll = 1;
    handle_log_key(&mut app, KeyCode::Down);
    assert_eq!(app.logs_focus, LogFocus::Scroll);
    assert_eq!(app.logs_scroll, 1);

    handle_log_key(&mut app, KeyCode::Down);
    assert_eq!(app.logs_focus, LogFocus::Export);
    handle_log_key(&mut app, KeyCode::Down);
    assert_eq!(app.logs_focus, LogFocus::Clear);
    handle_log_key(&mut app, KeyCode::Down);
    assert_eq!(
        app.logs_focus,
        LogFocus::Clear,
        "must clamp at the last row"
    );

    handle_log_key(&mut app, KeyCode::Up);
    assert_eq!(app.logs_focus, LogFocus::Export);
    handle_log_key(&mut app, KeyCode::Up);
    assert_eq!(app.logs_focus, LogFocus::Scroll);
}

#[test]
fn moving_up_one_row_from_the_bottom_is_not_snapped_back() {
    let mut app = TuiApp::default();
    for i in 0..20 {
        app.logs.push_back(LogEntry {
            at_unix: i,
            level: LogLevel::Info,
            message: format!("entry-{i}"),
        });
    }
    app.logs_scroll = 10;
    app.logs_max_scroll = 10;
    handle_log_key(&mut app, KeyCode::Up);
    assert_eq!(app.logs_scroll, 9);
}

#[test]
fn clearing_the_log_requires_confirmation_and_can_be_cancelled() {
    let mut app = TuiApp::default();
    app.logs.push_back(LogEntry {
        at_unix: 0,
        level: LogLevel::Info,
        message: "one".to_string(),
    });
    app.logs_focus = LogFocus::Clear;

    handle_log_key(&mut app, KeyCode::Enter);
    assert!(app.logs_clear_confirmation);
    assert_eq!(app.logs.back().unwrap().message, "one");
    handle_log_key(&mut app, KeyCode::Esc);
    assert!(!app.logs_clear_confirmation);
    assert_eq!(app.logs.back().unwrap().message, "one");
    handle_log_key(&mut app, KeyCode::Enter);
    handle_log_key(&mut app, KeyCode::Down);
    assert!(app.logs_clear_confirmation);
    handle_log_key(&mut app, KeyCode::Enter);
    assert!(!app.logs_clear_confirmation);

    assert_eq!(app.logs.len(), 1);
    assert_eq!(app.logs.back().expect("entry").message, "Log cleared");
    assert_eq!(app.logs_scroll, 0);
}

#[test]
fn paging_returns_the_cursor_to_the_scroll_region() {
    let mut app = TuiApp {
        logs_focus: LogFocus::Clear,
        ..Default::default()
    };
    handle_log_key(&mut app, KeyCode::PageUp);
    assert_eq!(app.logs_focus, LogFocus::Scroll);
}

#[test]
fn simple_errors_get_actionable_hints() {
    let message =
        with_troubleshooting_hint(LogLevel::Error, "interface eth0 is unmanaged".to_string());
    assert!(message.contains("Hint:"));
    assert!(message.contains("Configure with traffic-masq"));

    let unchanged = with_troubleshooting_hint(LogLevel::Error, "unknown error".to_string());
    assert_eq!(unchanged, "unknown error");
}

#[test]
fn wrapped_diagnostics_preserve_the_hint_and_unicode() {
    let message = "interface wlan0 is absent; convergence is deferred | Hint: подключите адаптер";
    let rows = wrap_log_message(message, 24);
    assert!(rows.len() > 1);
    assert_eq!(rows.concat(), message);
    assert!(rows
        .iter()
        .all(|row| unicode_width::UnicodeWidthStr::width(row.as_str()) <= 24));
}

#[test]
fn long_log_can_be_scrolled_to_its_hint() {
    use ratatui::{backend::TestBackend, Terminal};
    let mut app = TuiApp::default();
    app.push_message(
        LogLevel::Warn,
        format!("{} Hint: reconnect adapter", "diagnostic ".repeat(40)),
    );
    let mut terminal = Terminal::new(TestBackend::new(50, 12)).unwrap();
    terminal
        .draw(|frame| render_log(frame, frame.area(), &mut app))
        .unwrap();
    assert!(app.logs_max_scroll > 0);
    let buffer = terminal.backend().buffer();
    // Join the visible content rows, excluding borders and padding. A word
    // may legitimately span two terminal rows.
    let text: String = (1..7)
        .map(|y| {
            let row: String = (1..49).map(|x| buffer[(x, y)].symbol()).collect();
            row.trim_end().to_string()
        })
        .collect();
    assert!(text.contains("reconnect adapter"), "{text}");
    handle_log_key(&mut app, KeyCode::Home);
    assert_eq!(app.logs_scroll, 0);
}

#[test]
fn warnings_wrap_at_word_boundaries_and_keep_graphemes() {
    assert_eq!(
        wrap_log_message("alpha beta gamma", 10),
        vec!["alpha beta", " gamma"]
    );
    let text = "a verylongtokenwithnospace адаптер 👩‍💻";
    let rows = wrap_log_message(text, 12);
    assert_eq!(rows.concat(), text);
    assert!(rows
        .iter()
        .all(|row| unicode_width::UnicodeWidthStr::width(row.as_str()) <= 12));
}
