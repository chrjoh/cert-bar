//! Certificate form renderer (mirrors [`crate::config::Certificate`]).
//!
//! The Cert screen edits one of N certificate entries (`app.cert_list`); this
//! renderer draws a small **Certificates** sub-list above the form so the user
//! can pick which entry to edit (a chain of CA → intermediate → leaf is built
//! by adding entries and referencing each other's `id` via `parent`). The
//! `form` handed to [`render`] is the active entry (`app.cert_list[cert_index]`).
//!
//! Fields are laid out in the **exact** order the reducer in
//! [`crate::tui::app`] navigates and cycles, so the focused-field index lines up
//! with the highlighted row:
//!
//! | idx | field            | widget                          |
//! | --- | ---------------- | ------------------------------- |
//! | 0   | id               | text input                      |
//! | 1   | common name      | text input                      |
//! | 2   | country          | text input                      |
//! | 3   | organization     | text input                      |
//! | 4   | key type         | enum cycler (`KEY_TYPE_OPTIONS`)|
//! | 5   | hash alg         | enum cycler (`HASH_ALG_OPTIONS`)|
//! | 6   | usage            | multi-select (`USAGE_OPTIONS`)  |
//! | 7   | alt names        | text input (comma-separated)    |
//! | 8   | CA               | boolean toggle                  |
//! | 9   | key length       | text input (RSA only)           |
//! | 10  | valid to         | text input (optional)           |
//! | 11  | parent           | text input (optional)           |
//! | 12  | signer cert pem  | text input (optional, path)     |
//! | 13  | signer key pem   | text input (optional, path)     |

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, ListState};

use super::widgets::{
    cycler_row, header, multiselect_rows, note_row, optional_text_row, render_form, text_row,
    toggle_row,
};
use crate::tui::app::{
    App, CertForm, Focus, HASH_ALG_OPTIONS, KEY_TYPE_OPTIONS, RSA_KEY_LENGTH_OPTIONS, USAGE_OPTIONS,
};
use crate::tui::theme::Theme;

/// Maximum number of rows the Certificates sub-list grows to before scrolling;
/// the form keeps the rest (the sub-list shrinks first on short terminals).
const ENTRIES_MAX_ROWS: u16 = 6;
/// Minimum rows the sub-list aims for (plus its top/bottom border).
const ENTRIES_MIN_ROWS: u16 = 1;

/// Renders the Certificate screen into `area`: a Certificates sub-list on top,
/// the form for the active entry (`form`) below.
///
/// `form` is the active entry resolved by the caller; `app.cert_list` /
/// `app.cert_index` drive the sub-list. The sub-list takes a small `Length`
/// (capped at [`ENTRIES_MAX_ROWS`] content rows) that shrinks before the form
/// on short terminals; the form takes the remaining `Min(0)` and keeps its
/// existing scroll behavior.
pub fn render(frame: &mut Frame, area: Rect, form: &CertForm, app: &App, theme: &Theme) {
    // Sub-list height: one row per entry (capped), plus the two border rows,
    // but never so tall it would crowd out the form on a short pane.
    let count = app.cert_list.len() as u16;
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

/// Renders the Certificates sub-list (entry ids + a compact CA/parent tag).
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

    let title = format!(
        " Certificates ({}) — a add · d delete ",
        app.cert_list.len()
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(border_type)
        .border_style(border_style)
        .title(Line::from(title).style(theme.title()))
        .style(theme.base());

    let items: Vec<ListItem> = app
        .cert_list
        .iter()
        .map(|c| ListItem::new(Line::from(entry_label(c))))
        .collect();

    let list = List::new(items)
        .block(block)
        .style(theme.base())
        .highlight_style(theme.selected())
        .highlight_symbol("> ");

    let mut state = ListState::default();
    let idx = app.cert_index.min(app.cert_list.len().saturating_sub(1));
    state.select(Some(idx));
    frame.render_stateful_widget(list, area, &mut state);
}

/// One sub-list row: the entry id (or `(unnamed)`) and a compact tag — `(CA)`
/// when `ca`, else `parent: <id>` when a parent is set.
fn entry_label(c: &CertForm) -> String {
    let id = if c.id.is_empty() {
        "(unnamed)"
    } else {
        c.id.as_str()
    };
    let tag = if c.ca {
        " (CA)".to_string()
    } else if !c.parent.is_empty() {
        format!(" parent: {}", c.parent)
    } else {
        String::new()
    };
    format!("{id}{tag}")
}

/// Renders the form for the active entry into `area`, with an `editing i/N`
/// title and the browse hint on focused path rows.
fn render_form_pane(frame: &mut Frame, area: Rect, form: &CertForm, app: &App, theme: &Theme) {
    let f = form.field;
    let selected_key = &KEY_TYPE_OPTIONS[form.key_type % KEY_TYPE_OPTIONS.len()];
    let key_type = format!("{selected_key:?}");
    let hash_alg = format!(
        "{:?}",
        HASH_ALG_OPTIONS[form.hash_alg % HASH_ALG_OPTIONS.len()]
    );
    let usage_opts: Vec<String> = USAGE_OPTIONS.iter().map(|o| format!("{o:?}")).collect();
    let usage_len = usage_opts.len();

    // `hash alg` only applies to RSA/ECDSA; for Ed25519 and PQC keys show that it
    // is not used (and convert leaves it unset so it is omitted from saved YAML).
    let hash_row = if selected_key.uses_hash_alg() {
        cycler_row("hash alg", &hash_alg, f == 5, theme)
    } else {
        note_row(
            "hash alg",
            &format!("n/a — not used for {key_type} keys"),
            f == 5,
            theme,
        )
    };

    // `key length` is a fixed-option cycler for RSA only; other key types have a
    // size fixed by the variant, so it is shown as not-applicable.
    let key_length_row = if selected_key.uses_rsa_key_length() {
        let bits = RSA_KEY_LENGTH_OPTIONS[form.key_length % RSA_KEY_LENGTH_OPTIONS.len()];
        cycler_row("key length", &bits.to_string(), f == 9, theme)
    } else {
        note_row(
            "key length",
            &format!("n/a — not used for {key_type} keys"),
            f == 9,
            theme,
        )
    };

    let mut lines: Vec<Line<'static>> = vec![
        text_row("id", &form.id, f == 0, theme),
        text_row("common name", &form.common_name, f == 1, theme),
        text_row("country", &form.country, f == 2, theme),
        text_row("organization", &form.organization, f == 3, theme),
        cycler_row("key type", &key_type, f == 4, theme),
        hash_row,
    ];
    let usage_start = lines.len();
    lines.extend(multiselect_rows(
        "usage",
        &usage_opts,
        &form.usage,
        form.usage_cursor,
        f == 6,
        theme,
    ));
    let after_usage = lines.len();
    lines.extend([
        text_row("alt names", &form.altnames, f == 7, theme),
        toggle_row("CA", form.ca, "is CA", f == 8, theme),
        key_length_row,
        optional_text_row("valid to", &form.valid_to, f == 10, theme),
        optional_text_row("parent", &form.parent, f == 11, theme),
        Line::from(""),
        header("Signer (optional, when no parent)", theme),
        path_row("cert pem", &form.signer.cert_pem_file, f == 12, theme),
        path_row("key pem", &form.signer.private_key_pem_file, f == 13, theme),
    ]);

    // Line index of the focused field, so the form scrolls to keep it visible.
    // The usage group (field 6) spans `usage_len` rows; its active line is the
    // highlighted option. Fields after it are offset by the extra usage rows.
    // Fields 12/13 sit past the blank spacer + the "Signer" header, so they are
    // offset by an additional 2 lines beyond the 7..=11 block start.
    let active_line = match f {
        0..=5 => f,
        6 => usage_start + form.usage_cursor.min(usage_len.saturating_sub(1)),
        7..=11 => after_usage + (f - 7),
        12 => after_usage + 7, // signer cert pem: 5 rows (7..=11) + blank + header
        _ => after_usage + 8,  // field 13 (signer key pem)
    };

    let total = app.cert_list.len();
    let current = app.cert_index.min(total.saturating_sub(1)) + 1;
    let title = format!("Certificate — editing {current}/{total}");
    render_form(frame, area, &title, lines, active_line, app, theme);
}

/// A path-input row: an [`optional_text_row`] with a right-side muted
/// `(Ctrl+O to browse)` hint appended only when the row is focused, so the user
/// learns the browse affordance exactly when it applies. The hint is built from
/// `theme.muted()` (no literal colors).
fn path_row(label: &str, value: &str, active: bool, theme: &Theme) -> Line<'static> {
    let mut line = optional_text_row(label, value, active, theme);
    if active {
        line.push_span(Span::styled("  (Ctrl+O to browse)", theme.muted()));
    }
    line
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
            .draw(|frame| render(frame, frame.area(), app.cert(), app, &theme))
            .expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    fn cert_app() -> App {
        let mut app = App::new("./out".to_string());
        app.screen = crate::tui::app::Screen::Cert;
        app.focus = crate::tui::app::Focus::Form;
        app
    }

    #[test]
    fn renders_title_and_core_labels() {
        let app = cert_app();
        let out = render_to_string(&app);
        assert!(out.contains("Certificate"));
        assert!(out.contains("id"));
        assert!(out.contains("key type"));
        assert!(out.contains("usage"));
    }

    #[test]
    fn shows_typed_id_value() {
        let mut app = cert_app();
        app.cert_mut().id = "server-1".to_string();
        let out = render_to_string(&app);
        assert!(out.contains("server-1"), "id buffer should render");
    }

    #[test]
    fn usage_toggles_render_with_marks() {
        let mut app = cert_app();
        app.cert_mut().usage[0] = true;
        let out = render_to_string(&app);
        assert!(out.contains("[x]"), "an enabled usage flag shows [x]");
        assert!(out.contains("[ ]"), "a disabled usage flag shows [ ]");
    }

    #[test]
    fn usage_renders_every_option_so_none_are_hidden() {
        let app = cert_app();
        let out = render_to_string(&app);
        for opt in USAGE_OPTIONS {
            assert!(
                out.contains(&format!("{opt:?}")),
                "usage option {opt:?} must be visible (one per row)"
            );
        }
    }

    #[test]
    fn key_length_is_cycler_for_rsa_and_na_otherwise() {
        // RSA (default index 0) -> a fixed-option cycler showing the bit length.
        let app = cert_app();
        let out = render_sized(&app, 70, 40);
        assert!(out.contains("key length"));
        assert!(
            out.contains(&RSA_KEY_LENGTH_OPTIONS[0].to_string()),
            "RSA shows a selectable key length"
        );

        // Ed25519 -> key length is not applicable.
        let mut app = cert_app();
        app.cert_mut().key_type = KEY_TYPE_OPTIONS
            .iter()
            .position(|k| format!("{k:?}") == "Ed25519")
            .expect("Ed25519 present");
        let out = render_sized(&app, 70, 40);
        assert!(
            out.contains("n/a"),
            "non-RSA key length should render as not-applicable"
        );
    }

    #[test]
    fn usage_shows_cursor_marker_when_focused() {
        let mut app = cert_app();
        app.cert_mut().field = 6; // focus the usage group
        let out = render_to_string(&app);
        assert!(
            out.contains("> "),
            "the highlighted usage option shows a '>' cursor marker"
        );
    }

    #[test]
    fn signer_key_pem_row_renders() {
        // Tall enough that the whole form (incl. the bottom signer rows) is
        // visible without relying on scroll-to-active.
        let app = cert_app();
        let out = render_sized(&app, 60, 40);
        assert!(out.contains("cert pem"), "signer cert pem row renders");
        assert!(
            out.contains("key pem"),
            "signer key pem row (field 13) renders"
        );
    }

    #[test]
    fn shows_typed_signer_key_value() {
        let mut app = cert_app();
        app.cert_mut().signer.private_key_pem_file = "ca.key".to_string();
        let out = render_sized(&app, 60, 40);
        assert!(out.contains("ca.key"), "signer key buffer should render");
    }

    #[test]
    fn entries_sublist_shows_ids_and_count() {
        let mut app = cert_app();
        app.cert_mut().id = "root".to_string();
        app.cert_mut().ca = true;
        app.update(crate::tui::app::Message::AddRow); // index 1
        app.cert_mut().id = "leaf".to_string();
        app.cert_mut().parent = "root".to_string();
        let out = render_to_string(&app);
        assert!(out.contains("Certificates (2)"), "shows the entry count");
        assert!(out.contains("root"), "shows the first entry id");
        assert!(out.contains("leaf"), "shows the second entry id");
        assert!(out.contains("(CA)"), "CA entry shows the (CA) tag");
        assert!(
            out.contains("parent: root"),
            "child entry shows its parent tag"
        );
    }

    #[test]
    fn unnamed_entry_renders_placeholder() {
        let app = cert_app();
        let out = render_to_string(&app);
        assert!(
            out.contains("(unnamed)"),
            "an entry with an empty id shows the placeholder"
        );
    }

    #[test]
    fn editing_header_shows_index_over_total() {
        let mut app = cert_app();
        app.update(crate::tui::app::Message::AddRow); // 2 entries, index 1
        app.cert_index = 0;
        let out = render_to_string(&app);
        assert!(
            out.contains("editing 1/2"),
            "form title shows 1-based editing i/N"
        );
    }

    #[test]
    fn browse_hint_shows_on_focused_path_field() {
        let mut app = cert_app();
        app.cert_mut().field = 13; // signer key pem (path)
        let out = render_to_string(&app);
        assert!(
            out.contains("Ctrl+O"),
            "focused path row shows the browse hint"
        );
    }

    #[test]
    fn browse_hint_absent_on_non_path_field() {
        let mut app = cert_app();
        app.cert_mut().field = 0; // id (not a path)
        let out = render_to_string(&app);
        assert!(
            !out.contains("Ctrl+O"),
            "non-path rows do not show the browse hint"
        );
    }

    #[test]
    fn degenerate_area_does_not_panic() {
        let app = cert_app();
        let theme = Theme::dark();
        let backend = TestBackend::new(1, 1);
        let mut terminal = Terminal::new(backend).expect("backend");
        terminal
            .draw(|frame| render(frame, frame.area(), app.cert(), &app, &theme))
            .expect("draw");
    }
}
