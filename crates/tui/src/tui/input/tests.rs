use super::*;

#[test]
fn text_editor_basic_operations() {
    let mut val = String::from("hello");
    let mut cur = 5;
    let mut ed = TextEditor::new(&mut val, &mut cur);

    assert_eq!(*ed.cursor, 5);
    ed.move_left();
    assert_eq!(*ed.cursor, 4);

    ed.insert('!');
    assert_eq!(ed.value, "hell!o");
    assert_eq!(*ed.cursor, 5);

    assert!(ed.backspace());
    assert_eq!(ed.value, "hello");
    assert_eq!(*ed.cursor, 4);

    ed.move_home();
    assert_eq!(*ed.cursor, 0);
    assert!(!ed.backspace());
    assert!(ed.delete());
    assert_eq!(ed.value, "ello");

    ed.move_end();
    assert_eq!(*ed.cursor, 4);
    assert!(!ed.delete());
}

#[test]
fn text_editor_unicode_multibyte() {
    let mut val = String::from("café");
    let mut cur = 4;
    let mut ed = TextEditor::new(&mut val, &mut cur);

    ed.move_left();
    assert_eq!(*ed.cursor, 3);
    ed.insert('!');
    assert_eq!(ed.value, "caf!é");
    assert_eq!(*ed.cursor, 4);

    ed.backspace();
    assert_eq!(ed.value, "café");
    assert_eq!(*ed.cursor, 3);
}

#[test]
fn text_editor_treats_combining_sequences_as_one_cursor_step() {
    let mut val = String::from("e\u{301}x");
    let mut cur = val.chars().count();
    let mut ed = TextEditor::new(&mut val, &mut cur);

    assert_eq!(*ed.cursor, 2);
    ed.move_left();
    assert_eq!(*ed.cursor, 1);
    assert!(ed.backspace());
    assert_eq!(ed.value, "x");
    assert_eq!(*ed.cursor, 0);

    ed.insert('e');
    ed.insert('\u{301}');
    assert_eq!(ed.value, "e\u{301}x");
    assert_eq!(*ed.cursor, 1);
}

#[test]
fn active_long_values_keep_the_cursor_in_a_bounded_viewport() {
    let spans = render_value_with_cursor(
        "abcdefghijklmnopqrstuvwxyz0123456789",
        36,
        true,
        Style::default(),
    );
    let rendered = spans.iter().fold(String::new(), |mut rendered, span| {
        rendered.push_str(span.content.as_ref());
        rendered
    });
    assert!(rendered.starts_with('…'));
    assert!(rendered.ends_with(' '));
    assert!(rendered.len() < 30);
}

#[test]
fn text_editor_handles_filtered_keys() {
    let mut val = String::new();
    let mut cur = 0;
    let mut ed = TextEditor::new(&mut val, &mut cur);

    assert!(ed.handle_key_filtered(KeyCode::Char('1'), |c| c.is_ascii_digit()));
    assert!(!ed.handle_key_filtered(KeyCode::Char('a'), |c| c.is_ascii_digit()));
    assert_eq!(ed.value, "1");
}
