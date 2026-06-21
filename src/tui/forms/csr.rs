//! CSR form renderer (mirrors [`crate::config::Csr`] plus the optional
//! [`crate::config::SigningRequest`] sign-existing-CSR mode).
//!
//! Fields follow the **exact** order the reducer in [`crate::tui::app`] expects:
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
//! | 7   | sign mode        | boolean toggle                  |
//! | 8   | alt names        | text input (comma-separated)    |
//! | 9   | csr pem file     | text input (sign mode)          |
//! | 10  | valid to         | text input (sign mode, optional)|
//! | 11  | CA               | boolean toggle (sign mode)      |
//! | 12  | key length       | text input (RSA only)           |
//! | 13  | signer cert pem  | text input (sign mode, path)    |
//! | 14  | signer key pem   | text input (sign mode, path)    |
//! | 15  | policies         | multi-select (sign mode)        |

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, ListState};

use super::widgets::{
    cycler_row, header, multiselect_rows, note_row, optional_text_row, render_form, text_row,
    toggle_row,
};
use crate::tui::app::{
    App, CsrForm, Focus, HASH_ALG_OPTIONS, KEY_TYPE_OPTIONS, POLICY_OPTIONS,
    RSA_KEY_LENGTH_OPTIONS, USAGE_OPTIONS,
};
use crate::tui::theme::Theme;

/// Maximum number of rows the CSR sub-list grows to before scrolling; the form
/// keeps the rest (the sub-list shrinks first on short terminals).
const ENTRIES_MAX_ROWS: u16 = 6;
/// Minimum rows the sub-list aims for (plus its top/bottom border).
const ENTRIES_MIN_ROWS: u16 = 1;

/// Renders the CSR screen into `area`: a CSR sub-list on top, the form for the
/// active entry (`form`) below.
///
/// `form` is the active entry resolved by the caller (`app.csr()`);
/// `app.csr_list` / `app.csr_index` drive the sub-list. The sub-list takes a
/// small `Length` (capped at [`ENTRIES_MAX_ROWS`] content rows) that shrinks
/// before the form on short terminals; the form takes the remaining `Min(0)`
/// and keeps its existing scroll behavior. Mirrors `cert.rs::render`.
pub fn render(frame: &mut Frame, area: Rect, form: &CsrForm, app: &App, theme: &Theme) {
    // Sub-list height: one row per entry (capped), plus the two border rows,
    // but never so tall it would crowd out the form on a short pane.
    let count = app.csr_list.len() as u16;
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

/// Renders the CSR sub-list (entry ids + a sign/generate indicator). Mirrors
/// `cert.rs::render_entries`.
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

    let title = format!(" CSR ({}) — a add · d delete ", app.csr_list.len());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(border_type)
        .border_style(border_style)
        .title(Line::from(title).style(theme.title()))
        .style(theme.base());

    let items: Vec<ListItem> = app
        .csr_list
        .iter()
        .map(|c| ListItem::new(Line::from(entry_label(c))))
        .collect();

    let list = List::new(items)
        .block(block)
        .style(theme.base())
        .highlight_style(theme.selected())
        .highlight_symbol("> ");

    let mut state = ListState::default();
    let idx = app.csr_index.min(app.csr_list.len().saturating_sub(1));
    state.select(Some(idx));
    frame.render_stateful_widget(list, area, &mut state);
}

/// One sub-list row: a label for the entry plus a kind indicator. Generate-mode
/// entries (`csrs`) read their id; sign-mode entries (`signing_request`s) carry
/// no id, so fall back to the `csr_pem_file` stem. Either way the kind is shown
/// as `(sign)` or `(generate)` so it is always visible.
fn entry_label(c: &CsrForm) -> String {
    let label = if !c.id.is_empty() {
        c.id.clone()
    } else if c.sign_mode && !c.csr_pem_file.is_empty() {
        std::path::Path::new(&c.csr_pem_file)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("(unnamed)")
            .to_string()
    } else {
        "(unnamed)".to_string()
    };
    let kind = if c.sign_mode {
        " (sign)"
    } else {
        " (generate)"
    };
    format!("{label}{kind}")
}

/// Renders the form for the active entry into `area`, with an `editing i/N`
/// title and the browse hint on focused path rows. Mirrors
/// `cert.rs::render_form_pane`.
fn render_form_pane(frame: &mut Frame, area: Rect, form: &CsrForm, app: &App, theme: &Theme) {
    let f = form.field;
    let selected_key = &KEY_TYPE_OPTIONS[form.key_type % KEY_TYPE_OPTIONS.len()];
    let key_type = format!("{selected_key:?}");
    let hash_alg = format!(
        "{:?}",
        HASH_ALG_OPTIONS[form.hash_alg % HASH_ALG_OPTIONS.len()]
    );
    let usage_opts: Vec<String> = USAGE_OPTIONS.iter().map(|o| format!("{o:?}")).collect();
    let usage_len = usage_opts.len();
    let policy_opts: Vec<String> = POLICY_OPTIONS.iter().map(|o| format!("{o:?}")).collect();
    let policy_len = policy_opts.len();

    // `hash alg` only applies to RSA/ECDSA; for Ed25519 and PQC keys show that it
    // is not used (convert leaves it unset so it is omitted from saved YAML).
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

    // `key length` is a fixed-option cycler for RSA only; not applicable otherwise.
    let key_length_row = if selected_key.uses_rsa_key_length() {
        let bits = RSA_KEY_LENGTH_OPTIONS[form.key_length % RSA_KEY_LENGTH_OPTIONS.len()];
        cycler_row("key length", &bits.to_string(), f == 12, theme)
    } else {
        note_row(
            "key length",
            &format!("n/a — not used for {key_type} keys"),
            f == 12,
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
        toggle_row(
            "sign mode",
            form.sign_mode,
            "sign existing CSR",
            f == 7,
            theme,
        ),
        text_row("alt names", &form.altnames, f == 8, theme),
        key_length_row,
        Line::from(""),
        header("Signing request (sign mode)", theme),
        optional_text_row("csr pem", &form.csr_pem_file, f == 9, theme),
        optional_text_row("valid to", &form.valid_to, f == 10, theme),
        toggle_row("CA", form.ca, "is CA", f == 11, theme),
        path_row(
            "signer cert pem",
            &form.signer.cert_pem_file,
            f == 13,
            theme,
        ),
        path_row(
            "signer key pem",
            &form.signer.private_key_pem_file,
            f == 14,
            theme,
        ),
        Line::from(""),
        header("Certificate policies (sign mode)", theme),
    ]);
    let policy_start = lines.len();
    lines.extend(multiselect_rows(
        "policies",
        &policy_opts,
        &form.policies,
        form.policies_cursor,
        f == 15,
        theme,
    ));

    // Line index of the focused field (see cert.rs). Rows after the usage group
    // are, in order: sign mode (7), alt names (8), key length (12), blank,
    // header, csr pem (9), valid to (10), CA (11), signer cert pem (13),
    // signer key pem (14), blank, header, then the policies group (15) tracked
    // by `policy_start`.
    let active_line = match f {
        0..=5 => f,
        6 => usage_start + form.usage_cursor.min(usage_len.saturating_sub(1)),
        7 => after_usage,      // sign mode
        8 => after_usage + 1,  // alt names
        12 => after_usage + 2, // key length
        9 => after_usage + 5,  // csr pem (after blank + header)
        10 => after_usage + 6, // valid to
        11 => after_usage + 7, // CA
        13 => after_usage + 8, // signer cert pem
        14 => after_usage + 9, // signer key pem
        _ => policy_start + form.policies_cursor.min(policy_len.saturating_sub(1)),
    };

    let total = app.csr_list.len();
    let current = app.csr_index.min(total.saturating_sub(1)) + 1;
    let title = format!("CSR — editing {current}/{total}");
    render_form(frame, area, &title, lines, active_line, app, theme);
}

/// A path-input row: an [`optional_text_row`] with a right-side muted
/// `(Ctrl+O to browse)` hint appended only when the row is focused, so the user
/// learns the browse affordance exactly when it applies. The hint is built from
/// `theme.muted()` (no literal colors). Mirrors `cert.rs::path_row`.
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
            .draw(|frame| render(frame, frame.area(), app.csr(), app, &theme))
            .expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    fn csr_app() -> App {
        let mut app = App::new("./out".to_string());
        app.screen = crate::tui::app::Screen::Csr;
        app.focus = crate::tui::app::Focus::Form;
        app
    }

    #[test]
    fn renders_title_and_sign_mode_toggle() {
        let app = csr_app();
        let out = render_to_string(&app);
        assert!(out.contains("CSR"));
        assert!(out.contains("sign mode"));
        assert!(out.contains("key type"));
    }

    #[test]
    fn shows_typed_csr_pem_path() {
        let mut app = csr_app();
        app.csr_mut().csr_pem_file = "req.pem".to_string();
        let out = render_to_string(&app);
        assert!(out.contains("req.pem"));
    }

    #[test]
    fn signer_cert_and_key_pem_rows_render() {
        // Tall enough that the bottom signer rows are visible without relying
        // on scroll-to-active.
        let app = csr_app();
        let out = render_sized(&app, 60, 40);
        assert!(
            out.contains("signer cert pem"),
            "signer cert pem row (field 13) renders"
        );
        assert!(
            out.contains("signer key pem"),
            "signer key pem row (field 14) renders"
        );
    }

    #[test]
    fn shows_typed_signer_key_value() {
        let mut app = csr_app();
        app.csr_mut().signer.private_key_pem_file = "ca.key".to_string();
        let out = render_sized(&app, 60, 40);
        assert!(
            out.contains("ca.key"),
            "signer key buffer (field 14) should render"
        );
    }

    #[test]
    fn policies_section_renders_every_option() {
        // Tall enough that the bottom policies section is visible.
        let app = csr_app();
        let out = render_sized(&app, 60, 48);
        assert!(
            out.contains("Certificate policies"),
            "policies header renders"
        );
        for opt in POLICY_OPTIONS {
            assert!(
                out.contains(&format!("{opt:?}")),
                "policy option {opt:?} must be visible (one per row)"
            );
        }
    }

    #[test]
    fn browse_hint_shows_on_focused_signer_key_field() {
        let mut app = csr_app();
        app.csr_mut().field = 14; // signer key pem (path)
        let out = render_sized(&app, 60, 40);
        assert!(
            out.contains("Ctrl+O"),
            "focused signer path row shows the browse hint"
        );
    }

    #[test]
    fn browse_hint_absent_on_non_path_field() {
        let mut app = csr_app();
        app.csr_mut().field = 0; // id (not a path)
        let out = render_sized(&app, 60, 40);
        assert!(
            !out.contains("Ctrl+O"),
            "non-path rows do not show the browse hint"
        );
    }

    #[test]
    fn entries_sublist_shows_labels_and_count() {
        let mut app = csr_app();
        app.csr_mut().id = "csr1".to_string();
        app.update(crate::tui::app::Message::AddRow); // index 1
        app.csr_mut().id = "csr2".to_string();
        let out = render_to_string(&app);
        assert!(out.contains("CSR (2)"), "shows the entry count");
        assert!(out.contains("csr1"), "shows the first entry id");
        assert!(out.contains("csr2"), "shows the second entry id");
        assert!(out.contains("> "), "shows the selection marker");
        assert!(out.contains("a add"), "shows the add/delete hint");
    }

    #[test]
    fn generate_entry_shows_generate_indicator() {
        let mut app = csr_app();
        app.csr_mut().id = "csr1".to_string();
        app.csr_mut().sign_mode = false;
        let out = render_to_string(&app);
        assert!(
            out.contains("csr1 (generate)"),
            "a generate-mode entry shows the (generate) indicator"
        );
    }

    #[test]
    fn sign_mode_entry_shows_sign_indicator() {
        let mut app = csr_app();
        app.csr_mut().id = "tosign".to_string();
        app.csr_mut().sign_mode = true;
        let out = render_to_string(&app);
        assert!(
            out.contains("tosign (sign)"),
            "a sign-mode entry shows the (sign) indicator"
        );
    }

    #[test]
    fn sign_mode_entry_without_id_falls_back_to_pem_stem() {
        let mut app = csr_app();
        app.csr_mut().id = String::new();
        app.csr_mut().sign_mode = true;
        app.csr_mut().csr_pem_file = "/tmp/req.pem".to_string();
        let out = render_to_string(&app);
        assert!(
            out.contains("req (sign)"),
            "a sign-mode entry with no id labels from the csr_pem_file stem"
        );
    }

    #[test]
    fn unnamed_entry_renders_placeholder() {
        let app = csr_app();
        let out = render_to_string(&app);
        assert!(
            out.contains("(unnamed) (generate)"),
            "an entry with an empty id shows the placeholder"
        );
    }

    #[test]
    fn editing_header_shows_index_over_total() {
        let mut app = csr_app();
        app.update(crate::tui::app::Message::AddRow); // 2 entries, index 1
        app.csr_index = 0;
        let out = render_to_string(&app);
        assert!(
            out.contains("editing 1/2"),
            "form title shows 1-based editing i/N"
        );
    }

    #[test]
    fn degenerate_area_does_not_panic() {
        let app = csr_app();
        let theme = Theme::dark();
        let backend = TestBackend::new(1, 1);
        let mut terminal = Terminal::new(backend).expect("backend");
        terminal
            .draw(|frame| render(frame, frame.area(), app.csr(), &app, &theme))
            .expect("draw");
    }
}
