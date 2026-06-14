//! CRL form renderer (mirrors [`crate::config::Crl`] with editable revoked rows).
//!
//! Fields follow the **exact** order the reducer in [`crate::tui::app`] expects:
//!
//! | idx | field          | widget     |
//! | --- | -------------- | ---------- |
//! | 0   | crl file       | text input |
//! | 1   | signer cert    | text input |
//! | 2   | signer key     | text input |
//!
//! Below the fixed fields a `Table` lists the revoked rows (`serial` hex +
//! `reason`, an enum cycler reading [`REASON_OPTIONS`]); `a`/`d` add/remove rows
//! and the selected row is highlighted with `> ` + a reversed style so it reads
//! without color. `←`/`→` cycle the selected row's reason.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, TableState};

use super::widgets::{form_block, text_row};
use crate::tui::app::{App, CrlForm, Focus, REASON_OPTIONS};
use crate::tui::theme::Theme;

/// Renders the CRL form into `area`: fixed fields on top, revoked-row table
/// below.
pub fn render(frame: &mut Frame, area: Rect, form: &CrlForm, app: &App, theme: &Theme) {
    // Split the pane: fixed fields (header + 3 rows) and the revoked table.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    let f = form.field;
    let field_lines: Vec<Line<'static>> = vec![
        text_row("crl file", &form.crl_file, f == 0, theme),
        text_row("signer cert", &form.signer.cert_pem_file, f == 1, theme),
        text_row(
            "signer key",
            &form.signer.private_key_pem_file,
            f == 2,
            theme,
        ),
    ];
    let fields = Paragraph::new(field_lines)
        .block(form_block("CRL", app, theme))
        .style(theme.base());
    frame.render_widget(fields, chunks[0]);

    render_revoked_table(frame, chunks[1], form, app, theme);
}

/// Renders the editable revoked-certificate table.
fn render_revoked_table(frame: &mut Frame, area: Rect, form: &CrlForm, app: &App, theme: &Theme) {
    let focused = app.focus == Focus::Form;
    let (border_type, border_style) = if focused {
        (BorderType::Thick, theme.focused_border())
    } else {
        (BorderType::Plain, theme.border())
    };

    let title = format!(" Revoked ({}) — a add · d delete ", form.revoked.len());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(border_type)
        .border_style(border_style)
        .title(Line::from(title).style(theme.title()))
        .style(theme.base());

    if form.revoked.is_empty() {
        let hint = Paragraph::new("No revoked entries. Press 'a' to add one.")
            .block(block)
            .style(theme.muted());
        frame.render_widget(hint, area);
        return;
    }

    let header = Row::new(vec![Cell::from("serial (hex)"), Cell::from("reason")])
        .style(theme.active_label());

    let rows: Vec<Row> = form
        .revoked
        .iter()
        .map(|r| {
            let reason = format!("{:?}", REASON_OPTIONS[r.reason % REASON_OPTIONS.len()]);
            let serial = if r.serial.is_empty() {
                "(empty)".to_string()
            } else {
                r.serial.clone()
            };
            Row::new(vec![
                Cell::from(serial),
                Cell::from(format!("< {reason} ▸ >")),
            ])
        })
        .collect();

    let widths = [Constraint::Percentage(60), Constraint::Percentage(40)];
    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .style(theme.base())
        .row_highlight_style(theme.selected())
        .highlight_symbol("> ");

    let mut state = TableState::default();
    if let Some(idx) = form.selected_row {
        state.select(Some(idx.min(form.revoked.len().saturating_sub(1))));
    }
    frame.render_stateful_widget(table, area, &mut state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::RevokedRow;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render_to_string(app: &App) -> String {
        let theme = Theme::dark();
        let backend = TestBackend::new(70, 24);
        let mut terminal = Terminal::new(backend).expect("backend");
        terminal
            .draw(|frame| render(frame, frame.area(), &app.crl, app, &theme))
            .expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    /// Renders and returns the buffer as one `String` per terminal row, so a
    /// test can assert which physical line carries the `> ` selection marker.
    fn render_to_lines(app: &App) -> Vec<String> {
        let theme = Theme::dark();
        let w = 70u16;
        let h = 24u16;
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).expect("backend");
        terminal
            .draw(|frame| render(frame, frame.area(), &app.crl, app, &theme))
            .expect("draw");
        let content: Vec<String> = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol().to_string())
            .collect();
        content.chunks(w as usize).map(|row| row.concat()).collect()
    }

    fn crl_app() -> App {
        let mut app = App::new("./out".to_string());
        app.screen = crate::tui::app::Screen::Crl;
        app.focus = Focus::Form;
        app
    }

    #[test]
    fn renders_fields_and_empty_revoked_hint() {
        let app = crl_app();
        let out = render_to_string(&app);
        assert!(out.contains("CRL"));
        assert!(out.contains("crl file"));
        assert!(out.contains("Revoked"));
        assert!(out.contains("add"), "should prompt to add a revoked row");
    }

    #[test]
    fn renders_revoked_rows_with_reason() {
        let mut app = crl_app();
        app.crl.revoked.push(RevokedRow {
            serial: "ab:cd".to_string(),
            reason: 1,
        });
        app.crl.selected_row = Some(0);
        let out = render_to_string(&app);
        assert!(out.contains("ab:cd"), "serial should render");
        assert!(out.contains('>'), "selected row marker should render");
    }

    #[test]
    fn highlights_a_non_last_selected_row() {
        // Two revoked rows with the FIRST selected proves earlier rows (not just
        // the most-recently-added last row) can be the highlighted/selected row.
        let mut app = crl_app();
        app.crl.revoked.push(RevokedRow {
            serial: "aa:aa".to_string(),
            reason: 0,
        });
        app.crl.revoked.push(RevokedRow {
            serial: "bb:bb".to_string(),
            reason: 0,
        });
        app.crl.selected_row = Some(0);

        let lines = render_to_lines(&app);
        let first = lines
            .iter()
            .find(|l| l.contains("aa:aa"))
            .expect("first revoked row should render");
        let second = lines
            .iter()
            .find(|l| l.contains("bb:bb"))
            .expect("second revoked row should render");

        assert!(
            first.contains("> aa:aa"),
            "the selected (first) row carries the '> ' marker, got: {first:?}"
        );
        assert!(
            !second.contains("> bb:bb"),
            "the non-selected (second) row has no marker, got: {second:?}"
        );
    }
}
