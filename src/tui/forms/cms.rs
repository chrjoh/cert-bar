//! CMS form renderer (mirrors [`crate::config::Cms`]).
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
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};

use super::widgets::{header, optional_text_row, render_form, text_row, toggle_row};
use crate::tui::app::{App, CmsForm};
use crate::tui::theme::Theme;

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

/// Renders the CMS form into `area`.
pub fn render(frame: &mut Frame, area: Rect, form: &CmsForm, app: &App, theme: &Theme) {
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
    render_form(frame, area, "CMS", lines, f, app, theme);
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
            .draw(|frame| render(frame, frame.area(), &app.cms, app, &theme))
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
        app.cms.detached = true;
        let out = render_to_string(&app);
        assert!(out.contains("[x]"), "detached on should show [x]");
    }

    #[test]
    fn browse_hint_shown_on_focused_path_row() {
        let mut app = cms_app();
        // Field 1 is the `data file` path row.
        app.cms.field = 1;
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
        app.cms.field = 0;
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
            app.cms.field = field;
            let out = render_to_string(&app);
            assert!(
                out.contains("Ctrl+O"),
                "focused signer path row {field} should show the browse hint"
            );
        }
    }
}
