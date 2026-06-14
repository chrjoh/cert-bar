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

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;

use super::widgets::{
    cycler_row, header, multiselect_rows, note_row, optional_text_row, render_form, text_row,
    toggle_row,
};
use crate::tui::app::{App, CsrForm, HASH_ALG_OPTIONS, KEY_TYPE_OPTIONS, USAGE_OPTIONS};
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
        text_row("key length", &form.key_length, f == 12, theme),
        text_row("alt names", &form.altnames, f == 8, theme),
        toggle_row(
            "sign mode",
            form.sign_mode,
            "sign existing CSR",
            f == 7,
            theme,
        ),
        Line::from(""),
        header("Signing request (sign mode)", theme),
        optional_text_row("csr pem", &form.csr_pem_file, f == 9, theme),
        optional_text_row("valid to", &form.valid_to, f == 10, theme),
        toggle_row("CA", form.ca, "is CA", f == 11, theme),
    ]);

    // Line index of the focused field (see cert.rs). Rows after the usage group
    // are: key length, alt names, sign mode, blank, header, csr pem, valid to, CA.
    let active_line = match f {
        0..=5 => f,
        6 => usage_start + form.usage_cursor.min(usage_len.saturating_sub(1)),
        12 => after_usage,     // key length
        8 => after_usage + 1,  // alt names
        7 => after_usage + 2,  // sign mode
        9 => after_usage + 5,  // csr pem (after blank + header)
        10 => after_usage + 6, // valid to
        _ => after_usage + 7,  // field 11 (CA)
    };

    render_form(frame, area, "CSR", lines, active_line, app, theme);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render_to_string(app: &App) -> String {
        let theme = Theme::dark();
        let backend = TestBackend::new(60, 24);
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
}
