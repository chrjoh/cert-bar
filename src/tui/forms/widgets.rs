//! Shared form-field renderers used by every per-screen form module.
//!
//! These helpers turn a label + value + focus flag into a single `Line` so each
//! form is just an ordered list of rows rendered into a bordered block. The
//! label column is a fixed [`LABEL_WIDTH`] (matching the design doc's
//! `Length(14)`); the active row's label is bold ([`Theme::active_label`]) while
//! inactive labels are muted ([`Theme::inactive_label`]).
//!
//! Every style comes from the [`Theme`] accessors — no literal colors live here,
//! so the `NO_COLOR` fallback keeps the forms legible.

use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};

use crate::tui::app::{App, Focus};
use crate::tui::theme::Theme;

/// Width of the left-hand label column (design doc: `Length(14)`).
pub const LABEL_WIDTH: usize = 14;

/// Builds the bordered form block titled `title`. Uses a thick focused border
/// when the form pane currently holds focus (distinguishable by weight alone),
/// otherwise a plain muted border.
pub fn form_block<'a>(title: &'a str, app: &App, theme: &Theme) -> Block<'a> {
    let focused = app.focus == Focus::Form;
    let (border_type, border_style) = if focused {
        (BorderType::Thick, theme.focused_border())
    } else {
        (BorderType::Plain, theme.border())
    };
    Block::default()
        .borders(Borders::ALL)
        .border_type(border_type)
        .border_style(border_style)
        .title(Line::from(format!(" {title} ")).style(theme.title()))
        .style(theme.base())
}

/// The label span for a row, bold when `active`, muted otherwise, padded to the
/// label column width.
fn label_span(label: &str, active: bool, theme: &Theme) -> Span<'static> {
    let style = if active {
        theme.active_label()
    } else {
        theme.inactive_label()
    };
    Span::styled(format!("{label:<LABEL_WIDTH$}"), style)
}

/// A labeled free-text input row. The buffer is shown inside `[ … ]`; the active
/// row appends a block cursor so the edit point is visible without a separate
/// persisted widget (cursor lives only in this rendered line, not in `app`).
pub fn text_row(label: &str, value: &str, active: bool, theme: &Theme) -> Line<'static> {
    let cursor = if active { "█" } else { "" };
    Line::from(vec![
        label_span(label, active, theme),
        Span::styled(format!("[{value}{cursor}]"), value_style(active, theme)),
    ])
}

/// A labeled optional free-text input row. Identical to [`text_row`] but, when
/// empty and not focused, shows a dim `(optional)` marker instead of an empty
/// box so the field reads as deliberately unset rather than missing.
pub fn optional_text_row(label: &str, value: &str, active: bool, theme: &Theme) -> Line<'static> {
    if value.is_empty() && !active {
        return Line::from(vec![
            label_span(label, active, theme),
            Span::styled("(optional)".to_string(), theme.disabled()),
        ]);
    }
    text_row(label, value, active, theme)
}

/// A labeled enum cycler row rendered as `< value ▸ >`. `value` is the display
/// label of the currently selected option (read from a `*_OPTIONS` slice by the
/// caller).
pub fn cycler_row(label: &str, value: &str, active: bool, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        label_span(label, active, theme),
        Span::styled(format!("< {value} ▸ >"), value_style(active, theme)),
    ])
}

/// A labeled boolean toggle row rendered as `[x] label` / `[ ] label`.
pub fn toggle_row(
    label: &str,
    checked: bool,
    text: &str,
    active: bool,
    theme: &Theme,
) -> Line<'static> {
    let mark = if checked { "[x]" } else { "[ ]" };
    Line::from(vec![
        label_span(label, active, theme),
        Span::styled(format!("{mark} {text}"), value_style(active, theme)),
    ])
}

/// A labeled multi-select group rendered **one option per line** so every option
/// stays visible regardless of form width. The `cursor`-th option is marked with
/// a leading `>` and highlighted (reversed) when the group is `active`, so the
/// user steps between options with ←→ and toggles only the highlighted one with
/// Space — without ever being forced to select an option just to move past it.
/// Each option also shows `[x]`/`[ ]`, so selection never relies on color alone.
///
/// The label occupies the column on the first row; continuation rows pad the
/// label column so the options stay aligned under it.
pub fn multiselect_rows(
    label: &str,
    options: &[String],
    selected: &[bool],
    cursor: usize,
    active: bool,
    theme: &Theme,
) -> Vec<Line<'static>> {
    options
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let label_text = if i == 0 { label } else { "" };
            let on = selected.get(i).copied().unwrap_or(false);
            let mark = if on { "[x]" } else { "[ ]" };
            let is_cursor = active && i == cursor;
            let pointer = if is_cursor { "> " } else { "  " };
            let row_style = if is_cursor {
                theme.selected()
            } else {
                value_style(false, theme)
            };
            Line::from(vec![
                label_span(label_text, active && i == 0, theme),
                Span::styled(format!("{pointer}{mark} {name}"), row_style),
            ])
        })
        .collect()
}

/// A labeled read-only note row: the value column shows `note` in the
/// disabled/muted style. Used for a field that is not applicable for the current
/// selection (e.g. `hash alg` when the chosen key type has no external hash).
pub fn note_row(label: &str, note: &str, active: bool, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        label_span(label, active, theme),
        Span::styled(note.to_string(), theme.disabled()),
    ])
}

/// A free-standing section header line (no label column), styled as accent text
/// so list/group boundaries read clearly.
pub fn header(text: &str, theme: &Theme) -> Line<'static> {
    Line::from(Span::styled(text.to_string(), theme.accent()))
}

/// Value styling: bold (active) reuses the active-label emphasis so the focused
/// row stands out by weight even on monochrome terminals; inactive uses body
/// text.
fn value_style(active: bool, theme: &Theme) -> Style {
    if active {
        theme.active_label()
    } else {
        Style::default().fg(theme.text_primary)
    }
}

/// Renders the assembled `lines` into the bordered `block` within `area`.
///
/// When the form has more lines than the block's inner height, it scrolls just
/// enough to keep `active_line` (the line index of the focused field) visible,
/// so tall forms never clip the field the user is editing.
pub fn render_form(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    active_line: usize,
    app: &App,
    theme: &Theme,
) {
    let block = form_block(title, app, theme);
    // Inner height available for content (area minus the top/bottom borders).
    let inner_height = area.height.saturating_sub(2) as usize;
    let scroll = if inner_height == 0 || lines.len() <= inner_height {
        0
    } else {
        let max_offset = lines.len() - inner_height;
        active_line.saturating_sub(inner_height - 1).min(max_offset)
    };
    let paragraph = Paragraph::new(lines)
        .block(block)
        .style(theme.base())
        .alignment(Alignment::Left)
        .scroll((scroll as u16, 0));
    frame.render_widget(paragraph, area);
}
