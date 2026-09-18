use crossterm::event::KeyCode;
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;

use super::theme;

/// Moves within an ordered set of focusable fields without wrapping.
pub(crate) fn move_clamped<T: Copy + PartialEq>(items: &[T], current: T, forward: bool) -> T {
    let index = items.iter().position(|item| *item == current).unwrap_or(0);
    items[if forward {
        (index + 1).min(items.len() - 1)
    } else {
        index.saturating_sub(1)
    }]
}

/// Moves within an ordered set of focusable fields and wraps at both ends.
pub(crate) fn move_wrapped<T: Copy + PartialEq>(items: &[T], current: T, forward: bool) -> T {
    let index = items.iter().position(|item| *item == current).unwrap_or(0);
    let step = if forward { 1 } else { items.len() - 1 };
    items[(index + step) % items.len()]
}

/// Helper for editing text with a movable cursor, insertion, deletion, and navigation.
pub(crate) struct TextEditor<'a> {
    pub value: &'a mut String,
    pub cursor: &'a mut usize,
}

impl<'a> TextEditor<'a> {
    pub fn new(value: &'a mut String, cursor: &'a mut usize) -> Self {
        let char_count = value.chars().count();
        if *cursor > char_count {
            *cursor = char_count;
        }
        Self { value, cursor }
    }

    pub fn insert(&mut self, c: char) {
        let char_count = self.value.chars().count();
        let idx = (*self.cursor).min(char_count);
        let byte_pos = self
            .value
            .char_indices()
            .nth(idx)
            .map(|(i, _)| i)
            .unwrap_or(self.value.len());
        self.value.insert(byte_pos, c);
        *self.cursor += 1;
    }

    pub fn backspace(&mut self) -> bool {
        if *self.cursor > 0 {
            *self.cursor -= 1;
            let byte_pos = self
                .value
                .char_indices()
                .nth(*self.cursor)
                .map(|(i, _)| i)
                .unwrap_or(self.value.len());
            self.value.remove(byte_pos);
            true
        } else {
            false
        }
    }

    pub fn delete(&mut self) -> bool {
        let char_count = self.value.chars().count();
        if *self.cursor < char_count {
            let byte_pos = self
                .value
                .char_indices()
                .nth(*self.cursor)
                .map(|(i, _)| i)
                .unwrap_or(self.value.len());
            self.value.remove(byte_pos);
            true
        } else {
            false
        }
    }

    pub fn move_left(&mut self) -> bool {
        if *self.cursor > 0 {
            *self.cursor -= 1;
            true
        } else {
            false
        }
    }

    pub fn move_right(&mut self) -> bool {
        let char_count = self.value.chars().count();
        if *self.cursor < char_count {
            *self.cursor += 1;
            true
        } else {
            false
        }
    }

    pub fn move_home(&mut self) {
        *self.cursor = 0;
    }

    pub fn move_end(&mut self) {
        *self.cursor = self.value.chars().count();
    }

    pub fn handle_key(&mut self, key: KeyCode) -> bool {
        self.handle_key_filtered(key, |c| !c.is_control())
    }

    pub fn handle_key_filtered(&mut self, key: KeyCode, filter: impl Fn(char) -> bool) -> bool {
        match key {
            KeyCode::Left => self.move_left(),
            KeyCode::Right => self.move_right(),
            KeyCode::Home => {
                self.move_home();
                true
            }
            KeyCode::End => {
                self.move_end();
                true
            }
            KeyCode::Backspace => self.backspace(),
            KeyCode::Delete => self.delete(),
            KeyCode::Char(c) if filter(c) => {
                self.insert(c);
                true
            }
            _ => false,
        }
    }
}

/// Returns true if the blinking cursor is currently in its visible phase.
pub(crate) fn is_cursor_blink_visible() -> bool {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    (millis / 500).is_multiple_of(2)
}

/// Formats text into Spans, rendering the cursor on the currently selected character.
pub(crate) fn render_value_with_cursor(
    text: &str,
    cursor: usize,
    active: bool,
    base_style: Style,
) -> Vec<Span<'static>> {
    if !active {
        return vec![Span::styled(text.to_string(), base_style)];
    }

    let char_count = text.chars().count();
    let clamped_cursor = cursor.min(char_count);
    let blink = is_cursor_blink_visible();

    let cursor_style = Style::default()
        .fg(theme::SELECTED_FG)
        .bg(theme::SELECTED_BG)
        .add_modifier(Modifier::BOLD);

    let mut spans = Vec::new();
    let chars: Vec<char> = text.chars().collect();

    if clamped_cursor < char_count {
        if clamped_cursor > 0 {
            let before: String = chars[..clamped_cursor].iter().collect();
            spans.push(Span::styled(before, base_style));
        }
        let current: String = chars[clamped_cursor..=clamped_cursor].iter().collect();
        let style = if blink {
            cursor_style
        } else {
            base_style.add_modifier(Modifier::UNDERLINED)
        };
        spans.push(Span::styled(current, style));
        if clamped_cursor + 1 < char_count {
            let after: String = chars[clamped_cursor + 1..].iter().collect();
            spans.push(Span::styled(after, base_style));
        }
    } else {
        if !text.is_empty() {
            spans.push(Span::styled(text.to_string(), base_style));
        }
        let cursor_char = " ";
        let style = if blink { cursor_style } else { base_style };
        spans.push(Span::styled(cursor_char.to_string(), style));
    }

    spans
}

/// Formats masked password text into Spans with cursor highlighting.
pub(crate) fn render_masked_with_cursor(
    char_count: usize,
    cursor: usize,
    active: bool,
    mask_char: char,
    base_style: Style,
) -> Vec<Span<'static>> {
    if !active {
        return vec![Span::styled(
            mask_char.to_string().repeat(char_count),
            base_style,
        )];
    }

    let clamped_cursor = cursor.min(char_count);
    let blink = is_cursor_blink_visible();

    let cursor_style = Style::default()
        .fg(theme::SELECTED_FG)
        .bg(theme::SELECTED_BG)
        .add_modifier(Modifier::BOLD);

    let mut spans = Vec::new();

    if clamped_cursor < char_count {
        if clamped_cursor > 0 {
            spans.push(Span::styled(
                mask_char.to_string().repeat(clamped_cursor),
                base_style,
            ));
        }
        let style = if blink {
            cursor_style
        } else {
            base_style.add_modifier(Modifier::UNDERLINED)
        };
        spans.push(Span::styled(mask_char.to_string(), style));
        if clamped_cursor + 1 < char_count {
            spans.push(Span::styled(
                mask_char
                    .to_string()
                    .repeat(char_count - clamped_cursor - 1),
                base_style,
            ));
        }
    } else {
        if char_count > 0 {
            spans.push(Span::styled(
                mask_char.to_string().repeat(char_count),
                base_style,
            ));
        }
        let cursor_char = " ";
        let style = if blink { cursor_style } else { base_style };
        spans.push(Span::styled(cursor_char.to_string(), style));
    }

    spans
}

#[cfg(test)]
mod tests {
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
    fn text_editor_handles_filtered_keys() {
        let mut val = String::new();
        let mut cur = 0;
        let mut ed = TextEditor::new(&mut val, &mut cur);

        assert!(ed.handle_key_filtered(KeyCode::Char('1'), |c| c.is_ascii_digit()));
        assert!(!ed.handle_key_filtered(KeyCode::Char('a'), |c| c.is_ascii_digit()));
        assert_eq!(ed.value, "1");
    }
}
