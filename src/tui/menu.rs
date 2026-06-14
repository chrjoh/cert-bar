//! Left-hand **Menu** pane for the cert-bar TUI.
//!
//! The outer vertical layout (title / body / footer), the title bar, the footer
//! help line, the confirm dialog and the global "terminal too small" guard are
//! all owned by [`crate::tui`] (`mod.rs`). This module is handed only the
//! already-split **menu pane** [`Rect`] (the left `Constraint::Length(18)`
//! column of the body) and renders the `Certificate / CSR / CRL / CMS`
//! selector into it.
//!
//! Rendering is a pure function of [`App`] state: the selected entry comes from
//! [`App::menu_index`] and the focus highlight from [`App::focus`]. No model
//! mutation happens here.
//!
//! All colors and emphasis come from the [`Theme`] accessors (`focused_border`,
//! `border`, `selected`, `title`, `base`, `muted`) — there are no literal
//! `Color`/`.fg()`/`.bg()` values in this file, so the `NO_COLOR` fallback in
//! [`Theme::no_color`] keeps the pane legible on a monochrome terminal.

use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph};

use crate::tui::app::{App, Focus, MENU_ITEMS};
use crate::tui::theme::Theme;

/// Renders the Menu pane into `area`.
///
/// `area` is the menu column the parent ([`crate::tui::view`]) split off the
/// body — this fn does not perform the outer layout itself. The pane is drawn
/// as a bordered [`Block`] titled `Menu` containing a [`List`] of
/// [`MENU_ITEMS`]; the entry at [`App::menu_index`] is highlighted with a
/// `> ` marker and the theme's reversed [`selected`](Theme::selected) style so
/// the selection reads even without color.
///
/// When the menu pane currently holds focus ([`Focus::Menu`]) the block uses a
/// [`BorderType::Thick`] border in the focused-border style, distinguishable by
/// weight alone; otherwise a plain border in the muted border style is used.
pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    // Defensive guard for a degenerate pane (the global 80x24 guard lives in
    // the parent view). A bordered Block needs at least 2x2 to draw its frame;
    // anything smaller would clip silently, so show a hint instead.
    if area.width < 2 || area.height < 2 {
        let hint = Paragraph::new("…")
            .style(theme.muted())
            .alignment(Alignment::Center);
        frame.render_widget(hint, area);
        return;
    }

    let focused = app.focus == Focus::Menu;

    let (border_type, border_style) = if focused {
        (BorderType::Thick, theme.focused_border())
    } else {
        (BorderType::Plain, theme.border())
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(border_type)
        .border_style(border_style)
        .title(Line::from(" Menu ").style(theme.title()))
        .style(theme.base());

    let items: Vec<ListItem> = MENU_ITEMS
        .iter()
        .map(|label| ListItem::new(Line::from(*label)))
        .collect();

    let list = List::new(items)
        .block(block)
        .style(theme.base())
        .highlight_symbol("> ")
        .highlight_style(theme.selected());

    // Selection is driven entirely by `app`; the immediate-mode `ListState` is
    // rebuilt each frame from `menu_index` so no widget state persists.
    let mut state = ListState::default();
    state.select(Some(app.menu_index.min(MENU_ITEMS.len().saturating_sub(1))));

    frame.render_stateful_widget(list, area, &mut state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render_to_buffer(app: &App, theme: &Theme, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal
            .draw(|frame| render(frame, frame.area(), app, theme))
            .expect("draw");
        let buffer = terminal.backend().buffer().clone();
        buffer
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    mod render {
        use super::*;

        #[test]
        fn shows_all_menu_items() {
            // Setup
            let app = App::new("./out".to_string());
            let theme = Theme::dark();

            // Invoke
            let rendered = render_to_buffer(&app, &theme, 18, 10);

            // Expect every canonical entry is present.
            for item in MENU_ITEMS {
                assert!(
                    rendered.contains(item),
                    "menu should render {item}, got: {rendered}"
                );
            }
        }

        #[test]
        fn marks_selected_item_with_symbol() {
            // Setup
            let mut app = App::new("./out".to_string());
            app.menu_index = 1; // CSR
            let theme = Theme::dark();

            // Invoke
            let rendered = render_to_buffer(&app, &theme, 18, 10);

            // Expect the highlight marker is drawn.
            assert!(
                rendered.contains('>'),
                "selected row should show the highlight symbol"
            );
        }

        #[test]
        fn renders_title() {
            let app = App::new("./out".to_string());
            let theme = Theme::dark();
            let rendered = render_to_buffer(&app, &theme, 18, 10);
            assert!(rendered.contains("Menu"), "pane should be titled Menu");
        }

        #[test]
        fn degenerate_area_does_not_panic() {
            // A 1-cell pane must not panic or clip the bordered block silently.
            let app = App::new("./out".to_string());
            let theme = Theme::dark();
            render_to_buffer(&app, &theme, 1, 1);
        }

        #[test]
        fn out_of_range_index_is_clamped() {
            // Defensive: an index past the last entry must not panic.
            let mut app = App::new("./out".to_string());
            app.menu_index = 99;
            let theme = Theme::dark();
            render_to_buffer(&app, &theme, 18, 10);
        }
    }
}
