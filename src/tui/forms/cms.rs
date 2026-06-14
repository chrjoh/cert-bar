//! CMS form renderer (mirrors [`crate::config::Cms`]).
//!
//! The CMS screen edits one of N CMS entries (`app.cms_list`); this renderer
//! draws a small **CMS** sub-list above the form so the user can pick which
//! entry to edit. The `form` handed to [`render`] is the active entry
//! (`app.cms_list[cms_index]`).
//!
//! Fields follow the **exact** order the reducer in [`crate::tui::app`] expects:
//!
//! | idx | field          | widget                  |
//! | --- | -------------- | ----------------------- |
//! | 0   | id             | text input              |
//! | 1   | data file      | text input              |
//! | 2   | recipient      | text input (optional)   |
//! | 3   | signer cert    | text input (optional)   |
//! | 4   | signer key     | text input (optional)   |
//!
//! The `detached` boolean is toggled with `Space` (handled by the reducer) and
//! rendered as a `[x]`/`[ ]` row paired with its label so meaning never relies
//! on color alone.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, ListState};

use super::widgets::{header, optional_text_row, render_form, text_row, toggle_row};
use crate::tui::app::{App, CmsForm, Focus};
use crate::tui::theme::Theme;

/// Maximum number of rows the CMS sub-list grows to before scrolling; the form
/// keeps the rest (the sub-list shrinks first on short terminals).
const ENTRIES_MAX_ROWS: u16 = 6;
/// Minimum rows the sub-list aims for (plus its top/bottom border).
const ENTRIES_MIN_ROWS: u16 = 1;

/// Discoverability marker for path rows: when the row owns focus, the file
/// browser is reachable with `Ctrl+O`. Rendered as a muted trailing span (paired
/// with the `Ctrl+O` label text, so it reads without relying on color) rather
/// than a new widget — keeps the existing `widgets.rs` row idiom untouched.
const BROWSE_HINT: &str = "  (Ctrl+O to browse)";

/// Appends the muted `(Ctrl+O to browse)` hint to an existing path row `line` when
/// that row is `active`. Non-focused rows are returned unchanged so the marker
/// only appears on the field the user can act on. Styling comes solely from
/// [`Theme::muted`] — no literal colors.
fn with_browse_hint(mut line: Line<'static>, active: bool, theme: &Theme) -> Line<'static> {
    if active {
        line.spans
            .push(Span::styled(BROWSE_HINT.to_string(), theme.muted()));
    }
    line
}

/// Renders the CMS screen into `area`: a CMS sub-list on top, the form for the
/// active entry (`form`) below.
///
/// `form` is the active entry resolved by the caller; `app.cms_list` /
/// `app.cms_index` drive the sub-list. The sub-list takes a small `Length`
/// (capped at [`ENTRIES_MAX_ROWS`] content rows) that shrinks before the form
/// on short terminals; the form takes the remaining `Min(0)`.
pub fn render(frame: &mut Frame, area: Rect, form: &CmsForm, app: &App, theme: &Theme) {
    // Sub-list height: one row per entry (capped), plus the two border rows,
    // but never so tall it would crowd out the form on a short pane.
    let count = app.cms_list.len() as u16;
    let wanted_rows = count.clamp(ENTRIES_MIN_ROWS, ENTRIES_MAX_ROWS);
    // Leave at least 3 rows for the form block; the sub-list shrinks first.
    let max_list_height = area.height.saturating_sub(3);
    let list_height = (wanted_rows + 2).min(max_list_height);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(list_height), Constraint::Min(0)])
        .split(area);

    render_entries(frame, chunks[0], app, theme);
    render_form_pane(frame, chunks[1], form, app, theme);
}

/// Renders the CMS sub-list (entry ids + a compact detached marker).
fn render_entries(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    if area.height < 2 {
        return;
    }
    let focused = app.focus == Focus::Entries;
    let (border_type, border_style) = if focused {
        (BorderType::Thick, theme.focused_border())
    } else {
        (BorderType::Plain, theme.border())
    };

    let title = format!(" CMS ({}) — a add · d delete ", app.cms_list.len());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(border_type)
        .border_style(border_style)
        .title(Line::from(title).style(theme.title()))
        .style(theme.base());

    let items: Vec<ListItem> = app
        .cms_list
        .iter()
        .map(|c| ListItem::new(Line::from(entry_label(c))))
        .collect();

    let list = List::new(items)
        .block(block)
        .style(theme.base())
        .highlight_style(theme.selected())
        .highlight_symbol("> ");

    let mut state = ListState::default();
    let idx = app.cms_index.min(app.cms_list.len().saturating_sub(1));
    state.select(Some(idx));
    frame.render_stateful_widget(list, area, &mut state);
}

/// One sub-list row: the entry id (or `(unnamed)`) and a compact `(detached)`
/// marker when the entry produces a detached signature.
fn entry_label(c: &CmsForm) -> String {
    let id = if c.id.is_empty() {
        "(unnamed)"
    } else {
        c.id.as_str()
    };
    let tag = if c.detached { " (detached)" } else { "" };
    format!("{id}{tag}")
}

/// Renders the form for the active entry into `area`, with an `editing i/N`
/// title and the browse hint on focused path rows.
fn render_form_pane(frame: &mut Frame, area: Rect, form: &CmsForm, app: &App, theme: &Theme) {
    let f = form.field;
    let lines: Vec<Line<'static>> = vec![
        text_row("id", &form.id, f == 0, theme),
        with_browse_hint(
            text_row("data file", &form.data_file, f == 1, theme),
            f == 1,
            theme,
        ),
        toggle_row(
            "detached",
            form.detached,
            "detached signature",
            false,
            theme,
        ),
        with_browse_hint(
            optional_text_row("recipient", &form.recipient, f == 2, theme),
            f == 2,
            theme,
        ),
        Line::from(""),
        header("Signer (optional)", theme),
        with_browse_hint(
            optional_text_row("cert pem", &form.signer.cert_pem_file, f == 3, theme),
            f == 3,
            theme,
        ),
        with_browse_hint(
            optional_text_row("key pem", &form.signer.private_key_pem_file, f == 4, theme),
            f == 4,
            theme,
        ),
    ];

    // CMS is short and never overflows the form pane, so the focused line is
    // just the field index (the detached toggle sits between, but the small
    // offset never triggers scrolling).
    let total = app.cms_list.len();
    let current = app.cms_index.min(total.saturating_sub(1)) + 1;
    let title = format!("CMS — editing {current}/{total}");
    render_form(frame, area, &title, lines, f, app, theme);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render_to_string(app: &App) -> String {
        render_sized(app, 60, 24)
    }

    fn render_sized(app: &App, w: u16, h: u16) -> String {
        let theme = Theme::dark();
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).expect("backend");
        terminal
            .draw(|frame| render(frame, frame.area(), app.cms(), app, &theme))
            .expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    fn cms_app() -> App {
        let mut app = App::new("./out".to_string());
        app.screen = crate::tui::app::Screen::Cms;
        app.focus = crate::tui::app::Focus::Form;
        app
    }

    #[test]
    fn renders_title_and_labels() {
        let app = cms_app();
        let out = render_to_string(&app);
        assert!(out.contains("CMS"));
        assert!(out.contains("data file"));
        assert!(out.contains("detached"));
    }

    #[test]
    fn detached_toggle_reflects_state() {
        let mut app = cms_app();
        app.cms_mut().detached = true;
        let out = render_to_string(&app);
        assert!(out.contains("[x]"), "detached on should show [x]");
    }

    #[test]
    fn browse_hint_shown_on_focused_path_row() {
        let mut app = cms_app();
        // Field 1 is the `data file` path row.
        app.cms_mut().field = 1;
        let out = render_to_string(&app);
        assert!(
            out.contains("Ctrl+O"),
            "focused path row should show the Ctrl+O browse hint"
        );
    }

    #[test]
    fn browse_hint_absent_when_id_focused() {
        let mut app = cms_app();
        // Field 0 is `id`, which is not a browsable path.
        app.cms_mut().field = 0;
        let out = render_to_string(&app);
        assert!(
            !out.contains("Ctrl+O"),
            "non-path row (id) must not show the browse hint"
        );
    }

    #[test]
    fn browse_hint_shown_on_focused_signer_path_rows() {
        // Field 3 = signer cert pem, field 4 = signer key pem.
        for field in [3_usize, 4] {
            let mut app = cms_app();
            app.cms_mut().field = field;
            let out = render_to_string(&app);
            assert!(
                out.contains("Ctrl+O"),
                "focused signer path row {field} should show the browse hint"
            );
        }
    }

    #[test]
    fn entries_sublist_shows_ids_and_count() {
        let mut app = cms_app();
        app.cms_mut().id = "alpha".to_string();
        app.update(crate::tui::app::Message::AddRow); // index 1
        app.cms_mut().id = "beta".to_string();
        let out = render_to_string(&app);
        assert!(out.contains("CMS (2)"), "shows the entry count");
        assert!(out.contains("alpha"), "shows the first entry id");
        assert!(out.contains("beta"), "shows the second entry id");
    }

    #[test]
    fn detached_entry_shows_marker_in_sublist() {
        let mut app = cms_app();
        app.cms_mut().id = "signed".to_string();
        app.cms_mut().detached = true;
        let out = render_to_string(&app);
        assert!(
            out.contains("(detached)"),
            "a detached entry shows the (detached) marker in the sub-list"
        );
    }

    #[test]
    fn selected_entry_shows_marker() {
        let mut app = cms_app();
        app.cms_mut().id = "alpha".to_string();
        app.update(crate::tui::app::Message::AddRow); // 2 entries, index 1
        app.cms_mut().id = "beta".to_string();
        app.cms_index = 0; // select the first entry
        let out = render_to_string(&app);
        assert!(
            out.contains("> "),
            "the selected sub-list entry shows the '> ' marker"
        );
    }

    #[test]
    fn unnamed_entry_renders_placeholder() {
        let app = cms_app();
        let out = render_to_string(&app);
        assert!(
            out.contains("(unnamed)"),
            "an entry with an empty id shows the placeholder"
        );
    }

    #[test]
    fn editing_header_shows_index_over_total() {
        let mut app = cms_app();
        app.update(crate::tui::app::Message::AddRow); // 2 entries, index 1
        app.cms_index = 0;
        let out = render_to_string(&app);
        assert!(
            out.contains("editing 1/2"),
            "form title shows 1-based editing i/N"
        );
    }

    #[test]
    fn single_entry_shows_editing_one_of_one() {
        let app = cms_app();
        let out = render_to_string(&app);
        assert!(
            out.contains("editing 1/1"),
            "a freshly-seeded CMS screen shows editing 1/1"
        );
    }

    #[test]
    fn degenerate_area_does_not_panic() {
        let app = cms_app();
        let theme = Theme::dark();
        let backend = TestBackend::new(1, 1);
        let mut terminal = Terminal::new(backend).expect("backend");
        terminal
            .draw(|frame| render(frame, frame.area(), app.cms(), &app, &theme))
            .expect("draw");
    }
}
