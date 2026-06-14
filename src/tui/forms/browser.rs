//! Reusable file-browser overlay renderer for the cert-bar TUI.
//!
//! Rendering is a pure function of [`FileBrowser`] state (held by `App.browser`):
//! this module draws a centered, thick-bordered modal listing the current
//! directory and lets the user navigate to a path. Reading the directory and all
//! navigation logic live in the reducer / event loop (`app.rs` + `mod.rs`); this
//! module only draws.
//!
//! All colors and emphasis come from the [`Theme`] accessors — there are no
//! literal `Color`/`.fg()`/`.bg()` values here, so the `NO_COLOR` fallback keeps
//! the overlay legible on a monochrome terminal. Meaning is carried by non-color
//! cues: `[D]`/`[F]` type markers and a trailing `/` on directories survive
//! `NO_COLOR`, and selection is shown with `highlight_symbol("> ")` plus
//! `Modifier::REVERSED` (via [`Theme::selected`]) rather than color alone.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph};

use crate::tui::app::FileBrowser;
use crate::tui::theme::Theme;

/// Footer hint shown inside the popup.
const FOOTER_HINT: &str = "↑↓ move · Enter open/select · Del/c clear · Backspace up · Esc cancel";

/// Message shown when the popup is too small to host the listing.
const TOO_SMALL: &str = "Terminal too small to browse — type the path instead";

/// Renders the file-browser overlay over `area`.
///
/// Draws a centered modal (`Clear` + a `Block` with [`BorderType::Thick`] and
/// [`Theme::focused_border`]) titled with the current directory, a scrollable
/// [`List`] of `browser.entries`, and a muted footer hint. If the popup inner
/// area is too small to host the list, a single muted fallback line is rendered
/// instead so a tiny terminal never panics.
pub fn render(frame: &mut Frame, area: Rect, browser: &FileBrowser, theme: &Theme) {
    // Size the popup as a ratio of the area (~70% × ~60%), centered, so it
    // scales with the terminal.
    let popup = centered_ratio_rect(70, 60, area);
    frame.render_widget(Clear, popup);

    let title = browser_title(browser, popup.width);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(theme.focused_border())
        .title(Line::from(title).style(theme.title()))
        .style(theme.popup());

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    // Too-small guard: a usable listing needs a body row plus the footer hint.
    // Below that, show a single muted fallback line inside the popup.
    if inner.height < 3 || inner.width < 1 {
        let note = Paragraph::new(TOO_SMALL)
            .style(theme.muted())
            .alignment(Alignment::Center);
        frame.render_widget(note, inner);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(inner);
    let body = chunks[0];
    let footer = chunks[1];

    let items: Vec<ListItem> = browser
        .entries
        .iter()
        .map(|entry| entry_item(&entry.name, entry.is_dir, theme))
        .collect();

    let list = List::new(items)
        .highlight_style(theme.selected())
        .highlight_symbol("> ");

    let selected = if browser.entries.is_empty() {
        None
    } else {
        Some(browser.selected.min(browser.entries.len() - 1))
    };
    let mut state = ListState::default();
    state.select(selected);
    frame.render_stateful_widget(list, body, &mut state);

    let hint = Paragraph::new(FOOTER_HINT).style(theme.muted());
    frame.render_widget(hint, footer);
}

/// Builds a single list row: a non-color `[D]`/`[F]` type marker (dir marker in
/// `accent`, file marker in body text), then the name, with a trailing `/` on
/// directories. Markers and the `/` carry the type without relying on color.
fn entry_item<'a>(name: &str, is_dir: bool, theme: &Theme) -> ListItem<'a> {
    let (marker, marker_style, suffix) = if is_dir {
        ("[D] ", theme.accent(), "/")
    } else {
        ("[F] ", theme.popup(), "")
    };
    // `..` reads as `[D] ..` with no trailing slash (it is already a directory
    // reference, not a named child).
    let suffix = if name == ".." { "" } else { suffix };
    ListItem::new(Line::from(vec![
        Span::styled(marker.to_string(), marker_style),
        Span::styled(format!("{name}{suffix}"), theme.popup()),
    ]))
}

/// Builds the popup title ` Browse — <current dir> `, truncating long paths from
/// the left (keeping the tail) so the directory you are in stays visible.
fn browser_title(browser: &FileBrowser, popup_width: u16) -> String {
    let dir = browser.current_dir.to_string_lossy();
    // Budget = popup width minus the thick borders (2) and the fixed
    // ` Browse —  ` chrome around the path.
    let prefix = " Browse — ";
    let chrome = prefix.chars().count() + 1 /* trailing space */ + 2 /* borders */;
    let budget = (popup_width as usize).saturating_sub(chrome);
    let dir = truncate_left(&dir, budget);
    format!("{prefix}{dir} ")
}

/// Truncates `s` from the left to at most `max` characters, prefixing an `…`
/// when truncated so the visible tail (the deepest path component) is kept.
fn truncate_left(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if max == 0 || count <= max {
        return s.to_string();
    }
    // Reserve one column for the ellipsis.
    let keep = max.saturating_sub(1);
    let tail: String = s.chars().skip(count - keep).collect();
    format!("…{tail}")
}

/// Computes a rectangle `width_pct` × `height_pct` of `area`, centered. The
/// percentages scale the popup with the terminal rather than using fixed cells.
fn centered_ratio_rect(width_pct: u16, height_pct: u16, area: Rect) -> Rect {
    let w = (area.width.saturating_mul(width_pct) / 100).min(area.width);
    let h = (area.height.saturating_mul(height_pct) / 100).min(area.height);
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect {
        x,
        y,
        width: w,
        height: h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::{BrowseTarget, FileEntry, Screen};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::path::PathBuf;

    fn browser_with(dir: &str, entries: Vec<FileEntry>, selected: usize) -> FileBrowser {
        FileBrowser {
            current_dir: PathBuf::from(dir),
            entries,
            selected,
            target: BrowseTarget {
                screen: Screen::Cert,
                field: 12,
            },
        }
    }

    fn entry(name: &str, is_dir: bool) -> FileEntry {
        FileEntry {
            name: name.to_string(),
            is_dir,
        }
    }

    /// Renders the overlay into a `TestBackend` of the given size and returns the
    /// flattened buffer text (all cells concatenated row by row).
    fn render_to_string(width: u16, height: u16, browser: &FileBrowser) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test backend");
        let theme = Theme::dark();
        terminal
            .draw(|frame| render(frame, frame.area(), browser, &theme))
            .expect("draw");
        let buffer = terminal.backend().buffer().clone();
        buffer
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect()
    }

    #[test]
    fn renders_markers_and_dir_suffix() {
        let browser = browser_with(
            "/home/user/certs",
            vec![
                entry("..", true),
                entry("ca", true),
                entry("root_cert.pem", false),
            ],
            0,
        );
        let text = render_to_string(80, 20, &browser);
        assert!(text.contains("[D]"), "dir marker present: {text}");
        assert!(text.contains("[F]"), "file marker present: {text}");
        assert!(text.contains("ca/"), "dir name has trailing slash: {text}");
        assert!(text.contains("root_cert.pem"), "file name rendered: {text}");
        // `..` keeps no trailing slash.
        assert!(
            !text.contains("../"),
            "parent has no trailing slash: {text}"
        );
    }

    #[test]
    fn renders_current_dir_in_title() {
        let browser = browser_with("/home/user/certs", vec![entry("..", true)], 0);
        let text = render_to_string(80, 20, &browser);
        assert!(text.contains("Browse"), "title prefix present: {text}");
        assert!(
            text.contains("/home/user/certs"),
            "current dir in title: {text}"
        );
    }

    #[test]
    fn selected_entry_shows_marker() {
        let browser = browser_with("/tmp", vec![entry("..", true), entry("file.pem", false)], 1);
        // Use a wide terminal so the footer hint is not truncated by the popup
        // width before we assert on it.
        let text = render_to_string(120, 20, &browser);
        assert!(text.contains("> "), "selection marker present: {text}");
        assert!(text.contains(FOOTER_HINT), "footer hint present: {text}");
        // The footer must advertise the clear/none affordance (Del or `c`).
        assert!(
            text.contains("Del/c clear"),
            "clear hint present in footer: {text}"
        );
    }

    #[test]
    fn tiny_area_shows_fallback_without_panic() {
        let browser = browser_with("/tmp", vec![entry("a", true)], 0);
        // A 40x8 area yields a popup whose inner height (~3 rows minus borders)
        // is below the guard, exercising the fallback path with room to draw it.
        let text = render_to_string(40, 8, &browser);
        // The full message is wider than the popup and so is clipped; assert on
        // a leading substring that fits, and confirm the list row is suppressed.
        assert!(
            text.contains("Terminal too small"),
            "fallback message present: {text}"
        );
        assert!(
            !text.contains("[D]"),
            "list is suppressed in the fallback: {text}"
        );
    }

    #[test]
    fn empty_entries_does_not_panic() {
        let browser = browser_with("/tmp", vec![], 0);
        let _ = render_to_string(80, 20, &browser);
    }
}
