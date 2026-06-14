//! Right-hand **Form** pane for the cert-bar TUI.
//!
//! The outer vertical layout (title / body / footer), the title bar, the footer
//! help line, the confirm dialog and the global "terminal too small" guard are
//! all owned by [`crate::tui`] (`mod.rs`). This module is handed only the
//! already-split **form pane** [`Rect`] (the right `Constraint::Min(0)` column
//! of the body) and dispatches on [`App::screen`] to the per-screen renderer.
//!
//! Rendering is a pure function of [`App`] state: each submodule reads the
//! matching form struct (`CertForm` / `CsrForm` / `CrlForm` / `CmsForm`) and
//! draws labeled inputs, option cyclers, toggles and list panes. The focused
//! field comes from the form's `field` index, laid out in the exact order the
//! reducer in [`crate::tui::app`] expects so navigation and highlight line up.
//!
//! All colors and emphasis come from the [`Theme`] accessors — there are no
//! literal `Color`/`.fg()`/`.bg()` values in this module tree, so the
//! `NO_COLOR` fallback keeps the forms legible on a monochrome terminal.

pub mod browser;
mod cert;
mod cms;
mod crl;
mod csr;

mod widgets;

use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::widgets::Paragraph;

use crate::tui::app::{App, Screen};
use crate::tui::theme::Theme;

/// Renders the active form into `area`.
///
/// `area` is the form column the parent ([`crate::tui::view`]) split off the
/// body — this fn does not perform the outer layout itself. It dispatches on
/// [`App::screen`]: each of `Cert` / `Csr` / `Crl` / `Cms` delegates to its
/// submodule, while the `Menu` screen (no form active yet) shows a short hint.
pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    // Defensive guard for a degenerate pane (the global 80x24 guard lives in
    // the parent view). A bordered Block needs at least 2x2 to draw its frame.
    if area.width < 2 || area.height < 2 {
        let hint = Paragraph::new("…")
            .style(theme.muted())
            .alignment(Alignment::Center);
        frame.render_widget(hint, area);
        return;
    }

    match app.screen {
        Screen::Cert => cert::render(frame, area, app.cert(), app, theme),
        Screen::Csr => csr::render(frame, area, app.csr(), app, theme),
        Screen::Crl => crl::render(frame, area, &app.crl, app, theme),
        Screen::Cms => cms::render(frame, area, app.cms(), app, theme),
        Screen::Menu => render_hint(frame, area, theme),
    }
}

/// Hint shown in the form pane while still on the Menu screen: there is no
/// active form yet, so we prompt the user to pick one.
fn render_hint(frame: &mut Frame, area: Rect, theme: &Theme) {
    let hint = Paragraph::new("Select a config type from the menu, then press Enter.")
        .style(theme.muted())
        .alignment(Alignment::Center);
    frame.render_widget(hint, area);
}
