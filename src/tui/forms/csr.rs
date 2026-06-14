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

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};

use super::widgets::{
    cycler_row, header, multiselect_rows, note_row, optional_text_row, render_form, text_row,
    toggle_row,
};
use crate::tui::app::{
    App, CsrForm, HASH_ALG_OPTIONS, KEY_TYPE_OPTIONS, RSA_KEY_LENGTH_OPTIONS, USAGE_OPTIONS,
};
use crate::tui::theme::Theme;

/// Renders the CSR form into `area`.
pub fn render(frame: &mut Frame, area: Rect, form: &CsrForm, app: &App, theme: &Theme) {
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
    ]);

    // Line index of the focused field (see cert.rs). Rows after the usage group
    // are, in order: sign mode (7), alt names (8), key length (12), blank,
    // header, csr pem (9), valid to (10), CA (11), signer cert pem (13),
    // signer key pem (14).
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
        _ => after_usage + 9,  // field 14 (signer key pem)
    };

    render_form(frame, area, "CSR", lines, active_line, app, theme);
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
            .draw(|frame| render(frame, frame.area(), &app.csr, app, &theme))
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
        app.csr.csr_pem_file = "req.pem".to_string();
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
        app.csr.signer.private_key_pem_file = "ca.key".to_string();
        let out = render_sized(&app, 60, 40);
        assert!(
            out.contains("ca.key"),
            "signer key buffer (field 14) should render"
        );
    }

    #[test]
    fn browse_hint_shows_on_focused_signer_key_field() {
        let mut app = csr_app();
        app.csr.field = 14; // signer key pem (path)
        let out = render_sized(&app, 60, 40);
        assert!(
            out.contains("Ctrl+O"),
            "focused signer path row shows the browse hint"
        );
    }

    #[test]
    fn browse_hint_absent_on_non_path_field() {
        let mut app = csr_app();
        app.csr.field = 0; // id (not a path)
        let out = render_sized(&app, 60, 40);
        assert!(
            !out.contains("Ctrl+O"),
            "non-path rows do not show the browse hint"
        );
    }
}
