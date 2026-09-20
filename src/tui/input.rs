use crossterm::event::KeyCode;
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

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

pub(crate) fn grapheme_count(text: &str) -> usize {
    text.graphemes(true).count()
}

fn grapheme_byte_position(text: &str, index: usize) -> usize {
    text.grapheme_indices(true)
        .nth(index)
        .map(|(byte, _)| byte)
        .unwrap_or(text.len())
}

fn grapheme_byte_range(text: &str, index: usize) -> Option<std::ops::Range<usize>> {
    let start = text.grapheme_indices(true).nth(index)?.0;
    let end = text[start..]
        .grapheme_indices(true)
        .nth(1)
        .map(|(relative, _)| start + relative)
        .unwrap_or(text.len());
    Some(start..end)
}

fn grapheme_cursor_after_byte(text: &str, byte: usize) -> usize {
    if byte == 0 {
        return 0;
    }
    for (index, (start, grapheme)) in text.grapheme_indices(true).enumerate() {
        if byte <= start + grapheme.len() {
            return index + 1;
        }
    }
    grapheme_count(text)
}

/// Helper for editing text with a movable cursor, insertion, deletion, and navigation.
/// Cursor indices are extended grapheme clusters, not UTF-8 bytes or Unicode scalars.
pub(crate) struct TextEditor<'a> {
    pub value: &'a mut String,
    pub cursor: &'a mut usize,
}

impl<'a> TextEditor<'a> {
    pub fn new(value: &'a mut String, cursor: &'a mut usize) -> Self {
        let count = grapheme_count(value);
        if *cursor > count {
            *cursor = count;
        }
        Self { value, cursor }
    }

    pub fn insert(&mut self, c: char) {
        let count = grapheme_count(self.value);
        let index = (*self.cursor).min(count);
        let byte_pos = grapheme_byte_position(self.value, index);
        self.value.insert(byte_pos, c);
        *self.cursor = grapheme_cursor_after_byte(self.value, byte_pos + c.len_utf8());
    }

    pub fn backspace(&mut self) -> bool {
        if *self.cursor == 0 {
            return false;
        }
        let index = self.cursor.saturating_sub(1);
        let Some(range) = grapheme_byte_range(self.value, index) else {
            *self.cursor = grapheme_count(self.value);
            return false;
        };
        self.value.replace_range(range, "");
        *self.cursor = index;
        true
    }

    pub fn delete(&mut self) -> bool {
        let count = grapheme_count(self.value);
        if *self.cursor >= count {
            return false;
        }
        let Some(range) = grapheme_byte_range(self.value, *self.cursor) else {
            return false;
        };
        self.value.replace_range(range, "");
        true
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
        let count = grapheme_count(self.value);
        if *self.cursor < count {
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
        *self.cursor = grapheme_count(self.value);
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

    const EDIT_WINDOW_CELLS: usize = 24;
    let graphemes = text.graphemes(true).collect::<Vec<_>>();
    let count = graphemes.len();
    let cursor = cursor.min(count);
    let cursor_width = if cursor < count {
        UnicodeWidthStr::width(graphemes[cursor]).max(1)
    } else {
        1
    };
    let budget = EDIT_WINDOW_CELLS.saturating_sub(1).max(cursor_width);
    let mut used = cursor_width;
    let mut start = cursor;
    while start > 0 {
        let width = UnicodeWidthStr::width(graphemes[start - 1]);
        if used.saturating_add(width) > budget {
            break;
        }
        start -= 1;
        used = used.saturating_add(width);
    }
    let mut end = if cursor < count { cursor + 1 } else { cursor };
    while end < count {
        let width = UnicodeWidthStr::width(graphemes[end]);
        if used.saturating_add(width) > budget {
            break;
        }
        used = used.saturating_add(width);
        end += 1;
    }
    let local_cursor = cursor.saturating_sub(start);
    let visible = &graphemes[start..end];
    let blink = is_cursor_blink_visible();

    let cursor_style = Style::default()
        .fg(theme::SELECTED_FG)
        .bg(theme::SELECTED_BG)
        .add_modifier(Modifier::BOLD);
    let mut spans = Vec::new();
    if start > 0 {
        spans.push(Span::styled("…", Style::default().fg(theme::MUTED)));
    }

    if cursor < count {
        if local_cursor > 0 {
            spans.push(Span::styled(visible[..local_cursor].concat(), base_style));
        }
        let style = if blink {
            cursor_style
        } else {
            base_style.add_modifier(Modifier::UNDERLINED)
        };
        spans.push(Span::styled(visible[local_cursor].to_string(), style));
        if local_cursor + 1 < visible.len() {
            spans.push(Span::styled(
                visible[local_cursor + 1..].concat(),
                base_style,
            ));
        }
    } else {
        if !visible.is_empty() {
            spans.push(Span::styled(visible.concat(), base_style));
        }
        let style = if blink { cursor_style } else { base_style };
        spans.push(Span::styled(" ".to_string(), style));
    }

    spans
}

/// Formats masked password text into Spans with cursor highlighting.
pub(crate) fn render_masked_with_cursor(
    grapheme_count: usize,
    cursor: usize,
    active: bool,
    mask_char: char,
    base_style: Style,
) -> Vec<Span<'static>> {
    if !active {
        return vec![Span::styled(
            mask_char.to_string().repeat(grapheme_count),
            base_style,
        )];
    }

    const EDIT_WINDOW_CHARS: usize = 18;
    let clamped_cursor = cursor.min(grapheme_count);
    let start = clamped_cursor.saturating_sub(EDIT_WINDOW_CHARS.saturating_sub(1));
    let end = (start + EDIT_WINDOW_CHARS).min(grapheme_count);
    let local_cursor = clamped_cursor.saturating_sub(start);
    let visible_count = end.saturating_sub(start);
    let blink = is_cursor_blink_visible();

    let cursor_style = Style::default()
        .fg(theme::SELECTED_FG)
        .bg(theme::SELECTED_BG)
        .add_modifier(Modifier::BOLD);
    let mut spans = Vec::new();
    if start > 0 {
        spans.push(Span::styled("…", Style::default().fg(theme::MUTED)));
    }

    if clamped_cursor < grapheme_count {
        if local_cursor > 0 {
            spans.push(Span::styled(
                mask_char.to_string().repeat(local_cursor),
                base_style,
            ));
        }
        let style = if blink {
            cursor_style
        } else {
            base_style.add_modifier(Modifier::UNDERLINED)
        };
        spans.push(Span::styled(mask_char.to_string(), style));
        if local_cursor + 1 < visible_count {
            spans.push(Span::styled(
                mask_char
                    .to_string()
                    .repeat(visible_count - local_cursor - 1),
                base_style,
            ));
        }
    } else {
        if visible_count > 0 {
            spans.push(Span::styled(
                mask_char.to_string().repeat(visible_count),
                base_style,
            ));
        }
        let style = if blink { cursor_style } else { base_style };
        spans.push(Span::styled(" ".to_string(), style));
    }

    spans
}

#[cfg(test)]
mod tests;
