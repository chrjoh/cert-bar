//! Interactive ratatui TUI front-end for cert-bar.
//!
//! This module owns the **impure** shell around the pure Elm-style model in
//! [`app`]: terminal setup/teardown (crossterm raw mode + alternate screen),
//! the event loop, crossterm-key -> [`app::Message`] mapping, per-frame
//! rendering (delegated to [`menu`] / [`forms`]), and the generate / save-YAML
//! side effects (delegated to [`convert`] + the existing generation fns).
//!
//! The terminal is **always** restored on normal exit, on error, and on panic:
//! a [`TerminalGuard`] RAII type restores on `Drop`, and a panic hook restores
//! before the default hook prints the panic.
//!
//! ## Sibling modules
//!
//! The submodules below are declared here but authored by later tasks. Until
//! those files exist, building with `--features tui` will fail with
//! "file not found for module" / unresolved-import errors for `theme`, `menu`,
//! `forms` and `convert`. That is expected and intentional: this task only
//! provides `app` and this `mod.rs`, and references the siblings' planned
//! public API so the other agents can match it exactly.
//!
//! Expected public API of the siblings (see the task report):
//!
//! * `theme::Theme` — palette struct; `Theme::from_env()` honors `NO_COLOR`.
//! * `menu::render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme)`.
//! * `forms::render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme)`.
//! * `convert` — `*_from_form` builders returning `Result<_, String>` used by
//!   both the generate and save-YAML paths.

pub mod app;
pub mod convert;
pub mod forms;
pub mod menu;
pub mod theme;

use std::io::{self, Stdout, Write};
use std::panic;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{ExecutableCommand, cursor};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};

use app::{App, Effect, Message, Screen, StatusKind};
use theme::Theme;

/// RAII guard that restores the terminal to its normal state on drop.
///
/// Disables raw mode, leaves the alternate screen and re-shows the cursor.
/// Errors during teardown are deliberately swallowed (best-effort) because a
/// guard runs on the unwinding path where returning an error is not possible —
/// we still attempt every restore step.
struct TerminalGuard;

impl TerminalGuard {
    /// Enters raw mode and the alternate screen, returning a guard that will
    /// restore both on drop.
    ///
    /// # Errors
    ///
    /// Returns an error if raw mode cannot be enabled or the alternate screen
    /// cannot be entered.
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        stdout.execute(EnterAlternateScreen)?;
        stdout.execute(cursor::Hide)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort restore on every path (normal, error, unwind). Each step
        // is attempted independently so one failure does not skip the rest.
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = stdout.execute(LeaveAlternateScreen);
        let _ = stdout.execute(cursor::Show);
        let _ = stdout.flush();
    }
}

/// Launches the interactive TUI, returning when the user quits.
///
/// `output_dir` pre-fills the output-path prompt for generate / save actions.
/// The terminal is restored before this function returns, whether it returns
/// `Ok`, returns `Err`, or the process panics inside the loop.
///
/// # Errors
///
/// Returns an error if the terminal cannot be initialized or if a fatal draw /
/// input error occurs during the event loop. Generation and validation errors
/// are surfaced in-pane and do **not** abort the loop.
pub fn run(output_dir: impl Into<String>) -> Result<(), Box<dyn std::error::Error>> {
    install_panic_hook();

    let _guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let theme = Theme::from_env();
    let mut app = App::new(output_dir.into());

    event_loop(&mut terminal, &mut app, &theme)?;

    // `_guard` drops here, restoring the terminal.
    Ok(())
}

/// Installs a panic hook that restores the terminal before delegating to the
/// previously installed hook. This guarantees a readable backtrace even if a
/// panic unwinds past the [`TerminalGuard`] (e.g. during terminal init).
fn install_panic_hook() {
    let previous = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = stdout.execute(LeaveAlternateScreen);
        let _ = stdout.execute(cursor::Show);
        previous(info);
    }));
}

/// The core loop: draw, wait for input, map to a [`Message`], reduce, and run
/// any returned [`Effect`]. Exits when [`App::should_quit`] is set.
fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    theme: &Theme,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|frame| view(frame, app, theme))?;

        // Poll so the loop can stay responsive; only act on key presses.
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && let Some(msg) = map_key(key, app)
        {
            if let Some(effect) = app.update(msg) {
                run_effect(app, effect);
            }
            if app.should_quit {
                break;
            }
        }
    }
    Ok(())
}

/// Maximum width of the form column on wide terminals. Wide enough to show long
/// absolute file paths (selected certificate / key / data paths) without
/// truncation, while still leaving a right margin so fields don't stretch
/// edge-to-edge on an ultra-wide terminal.
const FORM_MAX_WIDTH: u16 = 120;

/// Renders one frame. Pure with respect to `app`; performs no model mutation.
///
/// Layout: title bar (1 line), body (menu + form), footer (2 lines). Below the
/// 80x24 minimum a single "terminal too small" guard is drawn instead.
fn view(frame: &mut ratatui::Frame, app: &App, theme: &Theme) {
    let area = frame.area();
    if area.width < 80 || area.height < 24 {
        let msg = Paragraph::new("Terminal too small (min 80x24)").alignment(Alignment::Center);
        frame.render_widget(msg, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(2),
        ])
        .split(area);

    render_title(frame, chunks[0], theme);

    // Menu keeps a fixed `Length(18)`; the form is capped at `FORM_MAX_WIDTH` so
    // fields don't stretch full-width on ultra-wide terminals, while still being
    // wide enough to show long absolute file paths (e.g. a selected certificate
    // path). The trailing `Min(0)` absorbs any width beyond the cap as a right
    // margin. The cap only bites when more than `FORM_MAX_WIDTH` columns remain:
    // at 80x24 the form gets 62 cols (< cap, spacer empty); on a wide terminal it
    // is held to `FORM_MAX_WIDTH` and the spacer takes the rest.
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(18),
            Constraint::Max(FORM_MAX_WIDTH),
            Constraint::Min(0),
        ])
        .split(chunks[1]);

    // Sibling render fns (authored by ui-designer). They read `app` + `theme`.
    menu::render(frame, body[0], app, theme);
    forms::render(frame, body[1], app, theme);

    render_footer(frame, chunks[2], app, theme);

    // Overlays draw last, over the form/menu/footer. Exactly one overlay is ever
    // visible, mirroring the reducer's precedence: the error popup owns the
    // screen first (a failure must be acknowledged before anything else), then
    // the file browser, then the confirm dialog. Each renderer Clears and
    // centers its own popup over the whole frame.
    if let Some(msg) = &app.error_popup {
        render_error_popup(frame, area, msg, theme);
    } else if let Some(browser) = &app.browser {
        crate::tui::forms::browser::render(frame, frame.area(), browser, theme);
    } else if app.dialog.is_some() {
        render_dialog(frame, area, app, theme);
    }
}

fn render_title(frame: &mut ratatui::Frame, area: Rect, theme: &Theme) {
    // Title bar: BOLD + text-primary on bg-secondary (design "Visual Hierarchy").
    // Style the whole area so the bar background fills its width.
    let title = Paragraph::new(" cert-bar")
        .style(theme.title())
        .block(Block::default().borders(Borders::NONE));
    frame.render_widget(title, area);
}

fn render_footer(frame: &mut ratatui::Frame, area: Rect, app: &App, theme: &Theme) {
    let help = "Tab · ↑↓ field · ←→ option · Space toggle · Enter · \
                Del clear field · Ctrl+O browse · Ctrl+L load · Ctrl+R clear · \
                Ctrl+Shift+R clear all · g generate · s save · a/d row · Esc back · q quit";

    // First line: muted/dim help line.
    let help_line = Line::from(Span::styled(help, theme.muted()));

    // Second line: right-aligned status/error slot. Meaning never depends on
    // color alone — each kind carries a symbol:
    //   * error   -> `[!]` + `theme.error()`
    //   * success -> the message already carries `✓`; styled `theme.success()`
    //   * info    -> muted chrome style
    let status_span = if let Some(err) = app.error.as_deref() {
        Span::styled(format!("[!] {err}"), theme.error())
    } else if let Some(status) = app.status.as_deref() {
        let style = match app.status_kind() {
            StatusKind::Success => theme.success(),
            StatusKind::Info => theme.muted(),
        };
        Span::styled(status.to_string(), style)
    } else {
        Span::raw("")
    };
    let status_line = Line::from(status_span).alignment(Alignment::Right);

    let footer = Paragraph::new(vec![help_line, status_line]);
    frame.render_widget(footer, area);
}

fn render_dialog(frame: &mut ratatui::Frame, area: Rect, app: &App, theme: &Theme) {
    use app::{ConfirmAction, Dialog};
    let Some(Dialog::Confirm { action, path }) = &app.dialog else {
        return;
    };

    // Per-action copy: a heading, a labeled field, and a hint, so the user sees
    // exactly what the editable path field means (issue #3).
    let (heading, field_label, hint) = match action {
        ConfirmAction::Generate => (
            "Generate",
            "Output directory:",
            "Generated files are written here.",
        ),
        ConfirmAction::SaveYaml => (
            "Save YAML",
            "File name:",
            "Path to the .yaml config to write.",
        ),
    };

    // Grow the popup to fit the heading + labeled field + hint + prompt rows.
    let popup = centered_rect(60, 9, area);
    frame.render_widget(Clear, popup);

    // Popup background (bg-elevated) + themed thick border so the dialog reads as
    // the active overlay, distinct from the content behind the `Clear`.
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(theme.focused_border())
        .title(" Confirm ")
        .style(theme.popup());

    // The path renders as an obviously-editable bordered field `[ … ]` with a
    // trailing block cursor `█`, mirroring `widgets::text_row`, so it does not
    // read as a static path.
    let lines = vec![
        Line::from(Span::styled(
            heading,
            theme.accent().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(field_label, theme.active_label())),
        Line::from(Span::styled(format!("[{path}█]"), theme.popup())),
        Line::from(""),
        Line::from(Span::styled(hint, theme.muted())),
        Line::from(Span::styled("Enter confirm · Esc cancel", theme.muted())),
    ];

    frame.render_widget(Paragraph::new(lines).block(block), popup);
}

/// Renders the dismissable error popup (the most prominent overlay) when
/// `app.error_popup` is set. A centered, `Clear`ed, thick-bordered modal styled
/// with the error palette; the message word-wraps so long cert-helper/CMS errors
/// are shown in full, and the last interior line carries a muted
/// `Esc / Enter to dismiss` hint.
///
/// The `[!]` prefix carries the "error" meaning without relying on color
/// (monochrome / `NO_COLOR` safe), matching the footer status marker.
fn render_error_popup(frame: &mut ratatui::Frame, area: Rect, msg: &str, theme: &Theme) {
    // Size generously for a long message: ~70% of the width and up to ~12 rows
    // tall, clamped to the area by `centered_rect`. The `view` guard already
    // ensures this only ever runs at >= 80x24, so the popup always fits and the
    // wrapped body uses the available width.
    let width = (area.width * 7 / 10).clamp(1, area.width);
    let popup = centered_rect(width, 12, area);
    frame.render_widget(Clear, popup);

    // Error-themed thick border so the failure reads as an error at a glance and
    // the popup is distinguished as the active overlay by border weight alone.
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(theme.error())
        .title(" Error ")
        .title_style(theme.error())
        .style(theme.popup());

    // Split the interior into a word-wrapped message body and a reserved muted
    // hint line at the bottom, so the hint never scrolls off with a long body.
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(inner);

    let body = Paragraph::new(format!("[!] {msg}"))
        .style(theme.error())
        .wrap(Wrap { trim: false });
    frame.render_widget(body, rows[0]);

    let hint = Paragraph::new(Span::styled("Esc / Enter to dismiss", theme.muted()));
    frame.render_widget(hint, rows[1]);
}

/// Computes a centered rectangle `width` x `height` within `area`, clamped to
/// fit.
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect {
        x,
        y,
        width: w,
        height: h,
    }
}

/// Maps a crossterm key event to a [`Message`]. All key interpretation lives
/// here (and nowhere in render code), per the Elm-style separation.
///
/// When a text field is focused, printable characters become [`Message::Char`]
/// so they can be typed into buffers; the single-letter shortcuts (`g`, `s`,
/// `a`, `d`, `q`) still apply when the focus is **not** a free-text field, or
/// when a dialog is open and editing a path.
fn map_key(key: KeyEvent, app: &App) -> Option<Message> {
    // Ctrl combos are intercepted before text-context handling: they are never
    // consumed as typed characters, so they work whether or not a free-text
    // field is focused. Shift changes the reported char case, so the letter is
    // matched case-insensitively.
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && let KeyCode::Char(c) = key.code
    {
        let lower = c.to_ascii_lowercase();
        match lower {
            'c' => return Some(Message::Quit),
            'o' => return Some(Message::OpenBrowser),
            // Ctrl+L opens the file browser in "load a config" mode. Like the
            // other Ctrl combos it fires regardless of text context; the
            // reducer makes it a no-op on the menu (no active config type).
            'l' => return Some(Message::LoadConfig),
            // Ctrl+Shift+R clears everything; plain Ctrl+R clears the current
            // form. The reducer treats `OpenBrowser`/`ClearForm`/`ClearAll` as
            // no-ops where they do not apply.
            'r' => {
                return Some(if key.modifiers.contains(KeyModifiers::SHIFT) {
                    Message::ClearAll
                } else {
                    Message::ClearForm
                });
            }
            _ => {}
        }
    }

    let typing = is_text_context(app);

    match key.code {
        KeyCode::Up => Some(Message::Up),
        KeyCode::Down => Some(Message::Down),
        KeyCode::Left => Some(Message::Left),
        KeyCode::Right => Some(Message::Right),
        KeyCode::Tab => Some(Message::FocusNext),
        KeyCode::BackTab => Some(Message::FocusPrev),
        KeyCode::Enter => Some(Message::Confirm),
        KeyCode::Esc => Some(Message::Back),
        KeyCode::Backspace => Some(Message::Backspace),
        // `Delete` always clears the focused field (issue #3): unconditional
        // like the arrow keys, it does not collide with `Backspace`
        // (delete-left). In a form the reducer empties the focused text buffer;
        // while the browser is open it clears the target path and closes.
        KeyCode::Delete => Some(Message::ClearField),
        // `c`/`C` clears-and-closes only while the browser is open; everywhere
        // else it must remain a normally typed character, so the mapping is
        // gated on `app.browser.is_some()` (not on `typing`).
        KeyCode::Char('c' | 'C') if app.browser.is_some() => Some(Message::ClearField),
        KeyCode::Char(' ') if !typing => Some(Message::Toggle),
        KeyCode::Char('q') if !typing => Some(Message::Quit),
        KeyCode::Char('g') if !typing => Some(Message::RequestGenerate),
        KeyCode::Char('s') if !typing => Some(Message::RequestSaveYaml),
        KeyCode::Char('a') if !typing => Some(Message::AddRow),
        KeyCode::Char('d') if !typing => Some(Message::DeleteRow),
        KeyCode::Char(c) => Some(Message::Char(c)),
        _ => None,
    }
}

/// Whether the current focus accepts free-text input (so letter shortcuts
/// should be treated as typed characters). True while editing a dialog path,
/// or while a free-text form field is focused.
fn is_text_context(app: &App) -> bool {
    // While any overlay owns the keys, treat the context as "typing" so stray
    // printable keys are not emitted as `Char` shortcuts against the form
    // underneath:
    //   * the confirm dialog edits a path buffer,
    //   * the browser passes navigation through (the reducer ignores the rest),
    //   * the error popup only accepts Esc/Enter to dismiss (issue #2) — its
    //     keys are inert, so suppressing shortcuts keeps the mapper consistent.
    if app.dialog.is_some() || app.browser.is_some() || app.error_popup.is_some() {
        return true;
    }
    if app.screen == Screen::Menu || app.focus == app::Focus::Menu {
        return false;
    }
    app.focused_field_is_text()
}

/// Executes a side-effecting [`Effect`] returned by the reducer, then records
/// the outcome on the model. All I/O (generation, YAML writing) happens here,
/// never inside [`App::update`].
fn run_effect(app: &mut App, effect: Effect) {
    match effect {
        Effect::Generate { screen, path } => match generate(app, screen, &path) {
            Ok(()) => {
                let what = generate_summary(app, screen);
                app.set_success(format!("✓ Generated {what} to {path}"));
            }
            // Route the full, possibly multi-line error into the dismissable
            // popup (issue #2) rather than truncating it into the 1-line footer.
            Err(e) => app.set_error_popup(format!("Generate failed: {e}")),
        },
        Effect::SaveYaml { screen, path } => match save_yaml(app, screen, &path) {
            Ok(()) => app.set_success(format!("✓ Saved YAML to {path}")),
            // Save failures also surface in the error popup (issue #2).
            Err(e) => app.set_error_popup(format!("Save failed: {e}")),
        },
        Effect::ReadDir { path, purpose } => read_dir_into_browser(app, path, purpose),
        Effect::LoadConfig { screen, path } => load_config_into_app(app, screen, &path),
    }
}

/// A human-readable, count-bearing description of what a successful generate
/// produced, for the success status line.
fn generate_summary(app: &App, screen: Screen) -> String {
    match screen {
        Screen::Cert => {
            let n = app.cert_list.len();
            format!("{n} certificate(s)")
        }
        Screen::Csr => "CSR(s)".to_string(),
        Screen::Crl => "CRL".to_string(),
        Screen::Cms => "CMS message".to_string(),
        Screen::Menu => "nothing".to_string(),
    }
}

/// Executes an [`Effect::ReadDir`]: the single impure directory read for the
/// file browser. Resolves `path` (which may contain a literal `..`) via
/// [`std::fs::canonicalize`], reads it, and builds a [`FileEntry`] listing
/// sorted directories-first then files (each group alphabetical) with a
/// synthesized `..` entry unless at a filesystem root. On any I/O error it fails
/// closed: it records an error and closes the browser rather than panicking the
/// terminal.
fn read_dir_into_browser(app: &mut App, path: PathBuf, purpose: app::BrowsePurpose) {
    // The path may contain a literal `..` (e.g. `/a/b/..`); canonicalize to a
    // clean absolute directory. Fall back to the joined path if canonicalize
    // fails (e.g. a not-yet-existing component), so a real read error is still
    // surfaced below with a readable path.
    let resolved = std::fs::canonicalize(&path).unwrap_or(path);

    let read = match std::fs::read_dir(&resolved) {
        Ok(read) => read,
        Err(e) => {
            // Fail closed: surface a readable message and close the browser so
            // the user can keep typing the path. Never panic the terminal.
            app.browser = None;
            app.set_error(format!("Cannot read {}: {e}", resolved.display()));
            return;
        }
    };

    let mut dirs: Vec<app::FileEntry> = Vec::new();
    let mut files: Vec<app::FileEntry> = Vec::new();
    for entry in read.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // `file_type()` can fail (e.g. a broken symlink); treat that as a file.
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let item = app::FileEntry { name, is_dir };
        if is_dir { &mut dirs } else { &mut files }.push(item);
    }
    dirs.sort_by(|a, b| a.name.cmp(&b.name));
    files.sort_by(|a, b| a.name.cmp(&b.name));

    let mut entries = Vec::with_capacity(dirs.len() + files.len() + 1);
    // Synthesize a leading `..` entry unless we are at a filesystem root.
    if resolved.parent().is_some() {
        entries.push(app::FileEntry {
            name: "..".to_string(),
            is_dir: true,
        });
    }
    entries.extend(dirs);
    entries.extend(files);

    app.set_browser_entries(resolved, entries, purpose);
}

/// Executes an [`Effect::LoadConfig`]: the impure read that parses `path` as
/// `screen`'s config type, reverse-maps it into form state and installs it on
/// the model. Mirrors [`read_dir_into_browser`]'s fail-closed style, but load
/// failures (read/parse errors, wrong-shape files, empty configs) route a clear
/// message into the **error popup** rather than the transient footer, and never
/// produce a false success. Never panics and never writes to stdout/stderr
/// (which would corrupt the alternate screen).
fn load_config_into_app(app: &mut App, screen: Screen, path: &str) {
    match screen {
        Screen::Cert => match crate::config::read_certificate_config(path) {
            Ok(certs) => {
                if certs.is_empty() {
                    app.set_error_popup("Certificate config has no entries");
                    return;
                }
                let n = certs.len();
                // Detect any RSA key length the {2048,4096} selector cannot
                // represent *before* the forward mapper silently coerces it to
                // index 0 (R2). The detector only reports; the warning is folded
                // into the success line below so the user sees the load
                // succeeded but is told the value will change on regenerate.
                let coerced = certs
                    .iter()
                    .find_map(|cert| convert::coerced_rsa_keylength(&cert.keytype, cert.keylength));
                let forms: Vec<app::CertForm> = certs.iter().map(convert::cert_to_form).collect();
                app.load_cert_list(forms);
                let base = format!("Loaded {n} certificate(s) from {path}");
                // Fold the warning into the success status (a visible footer
                // surface) rather than the transient `set_error` slot, so the
                // load-succeeded context is preserved alongside the warning.
                app.set_success(with_rsa_coercion_warning(base, coerced));
            }
            Err(e) => app.set_error_popup(format!("Not a valid certificate config: {e}")),
        },
        Screen::Csr => match crate::config::read_csr_config(path) {
            Ok(data) => {
                let total = data.csrs.len() + data.to_sign.len();
                if total == 0 {
                    app.set_error_popup("CSR config has no entries");
                    return;
                }
                // Only the generate-mode entry carries a key length; sign-mode
                // signing requests have none. Detect a coercion on the loaded
                // generate csr (R2).
                let coerced = data
                    .csrs
                    .first()
                    .and_then(|csr| convert::coerced_rsa_keylength(&csr.keytype, csr.keylength));
                let form = if let Some(csr) = data.csrs.first() {
                    convert::csr_to_form(csr)
                } else {
                    // `total > 0` and `csrs` is empty, so `to_sign` is non-empty.
                    convert::signing_request_to_form(&data.to_sign[0])
                };
                app.load_csr(form);
                let base = format!("Loaded 1 of {total} CSR entries from {path}");
                app.set_success(with_rsa_coercion_warning(base, coerced));
            }
            Err(e) => app.set_error_popup(format!("Not a valid CSR config: {e}")),
        },
        Screen::Crl => match crate::config::read_crl_config(path) {
            Ok(crl) => {
                let revoked = crl.revoked.len();
                let form = convert::crl_to_form(&crl);
                app.load_crl(form);
                app.set_success(format!("Loaded CRL ({revoked} revoked) from {path}"));
            }
            Err(e) => app.set_error_popup(format!("Not a valid CRL config: {e}")),
        },
        Screen::Cms => match crate::config::read_cms_config(path) {
            Ok(cmss) => {
                if cmss.is_empty() {
                    app.set_error_popup("CMS config has no entries");
                    return;
                }
                let n = cmss.len();
                let form = convert::cms_to_form(&cmss[0]);
                app.load_cms(form);
                app.set_success(format!("Loaded 1 of {n} CMS entries from {path}"));
            }
            Err(e) => app.set_error_popup(format!("Not a valid CMS config: {e}")),
        },
        // The browser is never opened in load mode on the menu, so this is
        // unreachable in practice; treat as a no-op for totality.
        Screen::Menu => {}
    }
}

/// Appends a visible RSA key-length coercion warning to a load success message
/// when `coerced` is `Some(original_len)`.
///
/// The RSA length selector is a fixed `{2048, 4096}` cycler (the first option,
/// 2048, is the coerced default). A loaded length outside that set would be
/// silently downgraded by the reverse mapper, so this surfaces the data loss to
/// the user (R2) instead of letting it happen silently. The base success line is
/// kept verbatim when there is nothing to warn about, so the no-coercion path is
/// byte-for-byte unchanged.
fn with_rsa_coercion_warning(base: String, coerced: Option<u32>) -> String {
    match coerced {
        Some(original) => {
            let default = app::RSA_KEY_LENGTH_OPTIONS[0];
            format!(
                "{base} — warning: RSA key length {original} is not selectable; \
                 it will be saved/regenerated as {default}"
            )
        }
        None => base,
    }
}

/// Converts every entry in `app.cert_list` into a [`crate::config::Certificate`],
/// preserving order so `parent`/`signer` references resolve in the pipeline.
///
/// # Errors
///
/// Returns an error naming the offending entry (its `id`, or `entry N` when the
/// id is blank) if any entry fails to convert, so a chain build stops with a
/// pointed message rather than silently dropping a cert.
fn certs_from_list(app: &App) -> Result<Vec<crate::config::Certificate>, String> {
    let mut all_certs = Vec::with_capacity(app.cert_list.len());
    for (n, form) in app.cert_list.iter().enumerate() {
        let cert = convert::cert_from_form(form).map_err(|e| {
            let label = if form.id.trim().is_empty() {
                format!("entry {}", n + 1)
            } else {
                format!("'{}'", form.id.trim())
            };
            format!("cert {label}: {e}")
        })?;
        all_certs.push(cert);
    }
    Ok(all_certs)
}

/// Converts the active form to its config struct(s) and runs the matching
/// generation pipeline.
fn generate(app: &App, screen: Screen, output_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    match screen {
        Screen::Cert => {
            let all_certs = certs_from_list(app)?;
            crate::certificate::create(all_certs, output_dir)?;
        }
        Screen::Csr => {
            let data = convert::csr_from_form(&app.csr)?;
            crate::csr::create_csr(data.csrs, output_dir)?;
            crate::csr::sign_requests(data.to_sign, output_dir)?;
        }
        Screen::Crl => {
            let crl = convert::crl_from_form(&app.crl)?;
            crate::crl::handle(crl, output_dir)?;
        }
        Screen::Cms => {
            let cms = convert::cms_from_form(&app.cms)?;
            crate::cms::handle(vec![cms], output_dir)?;
        }
        Screen::Menu => {}
    }
    Ok(())
}

/// Converts the active form to its config struct(s) and writes a replayable
/// YAML config to `path` via the `write_*_config` helpers.
fn save_yaml(app: &App, screen: Screen, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    match screen {
        Screen::Cert => {
            let all_certs = certs_from_list(app)?;
            crate::config::write_certificate_config(all_certs, path)?;
        }
        Screen::Csr => {
            let data = convert::csr_from_form(&app.csr)?;
            crate::config::write_csr_config(data, path)?;
        }
        Screen::Crl => {
            let crl = convert::crl_from_form(&app.crl)?;
            crate::config::write_crl_config(crl, path)?;
        }
        Screen::Cms => {
            let cms = convert::cms_from_form(&app.cms)?;
            crate::config::write_cms_config(vec![cms], path)?;
        }
        Screen::Menu => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use app::{BrowsePurpose, BrowseTarget, ConfirmAction, Dialog, Focus};
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::style::Modifier;

    /// Builds a `KeyEvent` for a Ctrl(+Shift) char, as crossterm would deliver
    /// it. Shift uppercases the reported char, mirroring real terminals.
    fn ctrl_key(c: char, shift: bool) -> KeyEvent {
        let mut mods = KeyModifiers::CONTROL;
        let code = if shift {
            mods |= KeyModifiers::SHIFT;
            KeyCode::Char(c.to_ascii_uppercase())
        } else {
            KeyCode::Char(c)
        };
        KeyEvent::new(code, mods)
    }

    /// Renders `view` against a `TestBackend` of the given size and returns the
    /// resulting buffer for both text and style assertions.
    fn render_view(app: &App, theme: &Theme, width: u16, height: u16) -> Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal
            .draw(|frame| view(frame, app, theme))
            .expect("draw");
        terminal.backend().buffer().clone()
    }

    /// Flattens a buffer's cell symbols into a single string for `contains`
    /// assertions.
    fn buffer_text(buffer: &Buffer) -> String {
        buffer
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    /// Returns the text of a single row, trimmed of trailing blanks.
    fn row_text(buffer: &Buffer, y: u16) -> String {
        let area = *buffer.area();
        (area.left()..area.right())
            .map(|x| buffer[(x, y)].symbol())
            .collect::<String>()
    }

    mod too_small_guard {
        use super::*;

        #[test]
        fn shows_guard_below_minimum_size() {
            // Setup: a terminal smaller than the 80x24 minimum.
            let app = App::new("./out".to_string());
            let theme = Theme::dark();

            // Invoke
            let buffer = render_view(&app, &theme, 79, 23);
            let text = buffer_text(&buffer);

            // Expect: the guard text appears, and the normal chrome does not.
            assert!(
                text.contains("Terminal too small"),
                "guard text should appear, got: {text}"
            );
            assert!(
                !text.contains("cert-bar"),
                "the normal title bar must not render below minimum size"
            );
            assert!(
                !text.contains("generate"),
                "the footer help must not render below minimum size"
            );
        }

        #[test]
        fn guard_below_minimum_width_only() {
            // Width below 80 but height at the minimum still triggers the guard.
            let app = App::new("./out".to_string());
            let theme = Theme::dark();
            let text = buffer_text(&render_view(&app, &theme, 79, 24));
            assert!(text.contains("Terminal too small"));
        }
    }

    mod title_bar {
        use super::*;

        #[test]
        fn renders_app_title() {
            // Setup
            let app = App::new("./out".to_string());
            let theme = Theme::dark();

            // Invoke
            let buffer = render_view(&app, &theme, 80, 24);

            // Expect: the title text is on the first row.
            assert!(
                row_text(&buffer, 0).contains("cert-bar"),
                "title row should contain the app name, got: {}",
                row_text(&buffer, 0)
            );
        }

        #[test]
        fn title_row_carries_themed_style() {
            // Setup: the dark theme gives the title BOLD text on bg-secondary.
            let app = App::new("./out".to_string());
            let theme = Theme::dark();

            // Invoke
            let buffer = render_view(&app, &theme, 80, 24);
            let cell = &buffer[(1, 0)]; // first column of " cert-bar"

            // Expect: not a plain unstyled paragraph — bold + the themed bg.
            assert!(
                cell.modifier.contains(Modifier::BOLD),
                "title cells should be BOLD"
            );
            assert_eq!(
                cell.bg, theme.bg_secondary,
                "title bar should carry the secondary background"
            );
        }
    }

    mod footer {
        use super::*;

        #[test]
        fn renders_keybinding_help() {
            // Setup
            let app = App::new("./out".to_string());
            let theme = Theme::dark();

            // Invoke: render wide enough that the full single-line help fits
            // (it is ~170 chars and is truncated, not wrapped, at narrower
            // widths, so the trailing `q quit` would be clipped below ~165).
            let text = buffer_text(&render_view(&app, &theme, 200, 50));

            // Expect: representative keybinding hints are present.
            assert!(text.contains("generate"), "footer should list 'g generate'");
            assert!(text.contains("quit"), "footer should list 'q quit'");
            assert!(
                text.contains("Ctrl+O"),
                "footer should list 'Ctrl+O browse'"
            );
            assert!(text.contains("Ctrl+L"), "footer should list 'Ctrl+L load'");
            assert!(text.contains("Ctrl+R"), "footer should list 'Ctrl+R clear'");
            assert!(
                text.contains("Ctrl+Shift+R"),
                "footer should list 'Ctrl+Shift+R clear all'"
            );
        }

        #[test]
        fn error_shows_bang_marker_and_error_style() {
            // Setup: an error set on the model.
            let mut app = App::new("./out".to_string());
            app.set_error("boom happened");
            let theme = Theme::dark();

            // Invoke
            let buffer = render_view(&app, &theme, 120, 40);
            let text = buffer_text(&buffer);

            // Find: the status row is the last footer line.
            let status_row = row_text(&buffer, 39);

            // Expect: the `[!]` marker and the error text are present.
            assert!(
                text.contains("[!]"),
                "error status should carry the [!] prefix, got: {text}"
            );
            assert!(
                text.contains("boom happened"),
                "error text should appear in the footer"
            );

            // Expect: the rendered marker carries the themed error foreground.
            let bang_x = status_row
                .char_indices()
                .find(|(_, c)| *c == '[')
                .map(|(i, _)| i as u16)
                .expect("status row should contain the [!] marker");
            let cell = &buffer[(bang_x, 39)];
            assert_eq!(
                cell.fg, theme.error_fg,
                "the [!] marker should carry the error foreground style"
            );
        }

        #[test]
        fn status_text_appears_without_error() {
            // Setup: a plain status, no error.
            let mut app = App::new("./out".to_string());
            app.set_status("Generated to ./out");
            let theme = Theme::dark();

            // Invoke
            let text = buffer_text(&render_view(&app, &theme, 120, 40));

            // Expect: the status text shows and no error marker is drawn.
            assert!(
                text.contains("Generated to ./out"),
                "status text should appear, got: {text}"
            );
            assert!(
                !text.contains("[!]"),
                "no error marker should be drawn for a plain status"
            );
        }

        #[test]
        fn success_status_renders_check_and_success_style() {
            // Setup: a success status (the message already carries `✓`).
            let mut app = App::new("./out".to_string());
            app.set_success("✓ Generated 1 certificate(s) to ./out");
            let theme = Theme::dark();

            // Invoke
            let buffer = render_view(&app, &theme, 120, 40);
            let text = buffer_text(&buffer);

            // Expect: the success message (with `✓`) renders and no error marker.
            assert!(
                text.contains("✓ Generated 1 certificate(s) to ./out"),
                "success status text should appear, got: {text}"
            );
            assert!(!text.contains("[!]"), "a success status is not an error");

            // Expect: the rendered `✓` carries the themed success foreground.
            // Locate it by scanning cells (one cell == one symbol) rather than
            // byte offsets, since `✓` is multibyte.
            let area = *buffer.area();
            let check_x = (area.left()..area.right())
                .find(|&x| buffer[(x, 39)].symbol() == "✓")
                .expect("status row should contain the ✓ marker");
            let cell = &buffer[(check_x, 39)];
            assert_eq!(
                cell.fg, theme.success_fg,
                "the ✓ marker should carry the success foreground style"
            );
        }
    }

    mod dialog {
        use super::*;

        #[test]
        fn confirm_dialog_renders_action_and_path_over_content() {
            // Setup: a Generate confirm dialog open with a known path.
            let mut app = App::new("./certs".to_string());
            app.dialog = Some(Dialog::Confirm {
                action: ConfirmAction::Generate,
                path: "./certs".to_string(),
            });
            let theme = Theme::dark();

            // Invoke
            let buffer = render_view(&app, &theme, 80, 24);
            let text = buffer_text(&buffer);

            // Expect: the action label, the path, and the confirm prompt render.
            assert!(
                text.contains("Generate"),
                "dialog should render the Generate action label, got: {text}"
            );
            assert!(
                text.contains("./certs"),
                "dialog should render the output path"
            );
            assert!(
                text.contains("Output directory:"),
                "Generate dialog should show its per-action field label, got: {text}"
            );
            assert!(
                text.contains("█"),
                "the editable path field should show a block cursor, got: {text}"
            );
            assert!(
                text.contains("Confirm"),
                "dialog should carry its 'Confirm' title"
            );
            assert!(
                text.contains("Esc cancel"),
                "dialog should show the cancel prompt"
            );
        }

        #[test]
        fn save_yaml_dialog_renders_its_label() {
            // Setup
            let mut app = App::new("./out".to_string());
            app.dialog = Some(Dialog::Confirm {
                action: ConfirmAction::SaveYaml,
                path: "config.yaml".to_string(),
            });
            let theme = Theme::dark();

            // Invoke
            let text = buffer_text(&render_view(&app, &theme, 120, 40));

            // Expect
            assert!(
                text.contains("Save YAML"),
                "dialog should render the Save YAML action label, got: {text}"
            );
            assert!(
                text.contains("File name:"),
                "Save YAML dialog should show its per-action field label, got: {text}"
            );
            assert!(text.contains("config.yaml"), "dialog should show the path");
        }

        #[test]
        fn popup_interior_carries_elevated_background() {
            // Setup
            let mut app = App::new("./out".to_string());
            app.dialog = Some(Dialog::Confirm {
                action: ConfirmAction::Generate,
                path: "./out".to_string(),
            });
            let theme = Theme::dark();

            // Invoke: a centered 60x7 popup sits in the middle of the 80x24 area.
            let buffer = render_view(&app, &theme, 80, 24);
            let center = &buffer[(40, 12)];

            // Expect: the popup style (bg-elevated) overrides the content behind.
            assert_eq!(
                center.bg, theme.bg_elevated,
                "the popup interior should carry the elevated background"
            );
        }
    }

    mod browser_overlay {
        use super::*;
        use app::{FileBrowser, FileEntry};

        #[test]
        fn open_browser_renders_overlay_over_the_form() {
            // Setup: a Cert form with the file browser open on a known dir.
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cert;
            app.focus = Focus::Form;
            app.browser = Some(FileBrowser {
                current_dir: std::path::PathBuf::from("/home/user/certs"),
                entries: vec![
                    FileEntry {
                        name: "..".to_string(),
                        is_dir: true,
                    },
                    FileEntry {
                        name: "root_cert.pem".to_string(),
                        is_dir: false,
                    },
                ],
                selected: 0,
                purpose: BrowsePurpose::FillField(BrowseTarget {
                    screen: Screen::Cert,
                    field: 12,
                }),
            });
            let theme = Theme::dark();

            // Invoke
            let text = buffer_text(&render_view(&app, &theme, 120, 40));

            // Expect: the browser overlay (title + an entry) draws over the form.
            assert!(
                text.contains("Browse"),
                "browser overlay title should render, got: {text}"
            );
            assert!(
                text.contains("root_cert.pem"),
                "browser overlay should list its entries, got: {text}"
            );
        }

        #[test]
        fn browser_takes_precedence_over_confirm_dialog() {
            // Both could apply; the browser overlay wins (it owns the keys).
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cert;
            app.focus = Focus::Form;
            app.dialog = Some(Dialog::Confirm {
                action: ConfirmAction::Generate,
                path: "./out".to_string(),
            });
            app.browser = Some(FileBrowser {
                current_dir: std::path::PathBuf::from("/tmp"),
                entries: vec![FileEntry {
                    name: "thing.pem".to_string(),
                    is_dir: false,
                }],
                selected: 0,
                purpose: BrowsePurpose::FillField(BrowseTarget {
                    screen: Screen::Cert,
                    field: 12,
                }),
            });
            let theme = Theme::dark();

            let text = buffer_text(&render_view(&app, &theme, 120, 40));
            assert!(
                text.contains("thing.pem"),
                "the browser overlay should render when both are set, got: {text}"
            );
            assert!(
                !text.contains("Output directory:"),
                "the confirm dialog must not draw underneath the browser overlay"
            );
        }
    }

    mod sizes {
        use super::*;

        #[test]
        fn renders_at_all_design_sizes_without_panic() {
            // Setup: every size listed in the design doc.
            let app = App::new("./out".to_string());
            let theme = Theme::from_env();

            // Invoke + Expect: no panic at any size.
            for (w, h) in [(80u16, 24u16), (120, 40), (160, 50)] {
                let text = buffer_text(&render_view(&app, &theme, w, h));
                assert!(
                    text.contains("cert-bar"),
                    "the {w}x{h} layout should render the title bar"
                );
            }
        }

        /// Recomputes the body split exactly as `view` does, returning the
        /// menu / form / right-margin rects for a given terminal size. Keeps the
        /// width assertion below independent of the sibling form renderer.
        fn body_rects(width: u16, height: u16) -> [Rect; 3] {
            let area = Rect {
                x: 0,
                y: 0,
                width,
                height,
            };
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Min(0),
                    Constraint::Length(2),
                ])
                .split(area);
            let body = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Length(18),
                    Constraint::Max(FORM_MAX_WIDTH),
                    Constraint::Min(0),
                ])
                .split(chunks[1]);
            [body[0], body[1], body[2]]
        }

        #[test]
        fn form_column_capped_on_wide_terminals() {
            // Wide terminal: the form pane is capped at `FORM_MAX_WIDTH`, leaving
            // the remainder as a right margin, while the menu stays at Length(18).
            // Use a width comfortably beyond menu + cap so the cap bites.
            let [menu, form, margin] = body_rects(FORM_MAX_WIDTH + 60, 50);
            assert_eq!(menu.width, 18, "menu stays at Length(18)");
            assert!(
                form.width <= FORM_MAX_WIDTH,
                "form column must be capped at FORM_MAX_WIDTH on wide terminals, got {}",
                form.width
            );
            assert!(
                margin.width > 0,
                "extra width beyond the cap should become a right margin, got {}",
                margin.width
            );
        }

        #[test]
        fn form_column_fills_remaining_width_when_narrow() {
            // 80x24 (minimum): the cap must NOT bite — the form fills all width
            // left after the menu (62 cols) with no right margin.
            let [menu, form, margin] = body_rects(80, 24);
            assert_eq!(menu.width, 18, "menu stays at Length(18)");
            assert_eq!(
                form.width, 62,
                "at the 80x24 minimum the form should fill the remaining width"
            );
            assert_eq!(margin.width, 0, "no right margin at the minimum size");
        }
    }

    mod ctrl_keys {
        use super::*;

        fn cert_form_app() -> App {
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cert;
            app.focus = Focus::Form;
            app
        }

        #[test]
        fn ctrl_o_maps_to_open_browser_on_path_field() {
            // Setup: focus a Cert signer path field (index 12).
            let mut app = cert_form_app();
            app.cert_mut().field = 12;
            assert!(app.focused_field_is_path(), "field 12 should be a path");

            // Invoke & expect: Ctrl+O opens the browser, even though path fields
            // are a text context.
            let msg = map_key(ctrl_key('o', false), &app);
            assert_eq!(msg, Some(Message::OpenBrowser));
        }

        #[test]
        fn ctrl_o_maps_to_open_browser_uppercase() {
            // Some terminals report Ctrl combos with the bare char; ensure the
            // case-insensitive match holds regardless.
            let mut app = cert_form_app();
            app.cert_mut().field = 0; // OpenBrowser is a no-op here, mapping still emits.
            let msg = map_key(ctrl_key('O', false), &app);
            assert_eq!(msg, Some(Message::OpenBrowser));
        }

        #[test]
        fn ctrl_r_maps_to_clear_form() {
            let app = cert_form_app();
            assert_eq!(
                map_key(ctrl_key('r', false), &app),
                Some(Message::ClearForm)
            );
        }

        #[test]
        fn ctrl_shift_r_maps_to_clear_all() {
            let app = cert_form_app();
            assert_eq!(map_key(ctrl_key('r', true), &app), Some(Message::ClearAll));
        }

        #[test]
        fn ctrl_combos_fire_while_typing_a_text_field() {
            // A free-text field is focused (text context), yet Ctrl combos are
            // not consumed as typed chars.
            let mut app = cert_form_app();
            app.cert_mut().field = 0; // `id` text field
            assert!(is_text_context(&app));
            assert_eq!(
                map_key(ctrl_key('r', false), &app),
                Some(Message::ClearForm)
            );
            assert_eq!(
                map_key(ctrl_key('o', false), &app),
                Some(Message::OpenBrowser)
            );
        }

        #[test]
        fn ctrl_c_still_quits() {
            let app = cert_form_app();
            assert_eq!(map_key(ctrl_key('c', false), &app), Some(Message::Quit));
        }
    }

    mod multicert_generate {
        use super::*;

        #[test]
        fn certs_from_list_converts_every_entry_in_order() {
            // Setup: two valid cert entries (a root and a leaf referencing it).
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cert;
            app.cert_list[0].id = "root".to_string();
            app.cert_list[0].common_name = "Root".to_string();
            app.cert_list[0].ca = true;
            app.cert_list.push(app::CertForm::default());
            app.cert_list[1].id = "leaf".to_string();
            app.cert_list[1].common_name = "Leaf".to_string();
            app.cert_list[1].parent = "root".to_string();

            // Invoke
            let certs = certs_from_list(&app).expect("both entries convert");

            // Expect: every entry converted, order preserved.
            assert_eq!(certs.len(), 2);
            assert_eq!(certs[0].id, "root");
            assert_eq!(certs[1].id, "leaf");
        }

        #[test]
        fn certs_from_list_names_offending_entry_by_id() {
            // Setup: a valid first entry and a second entry missing its id.
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cert;
            app.cert_list[0].id = "root".to_string();
            app.cert_list[0].common_name = "Root".to_string();
            app.cert_list.push(app::CertForm::default());
            // Second entry has a blank id but a common name -> id error.
            app.cert_list[1].common_name = "Leaf".to_string();

            // Invoke
            let err = certs_from_list(&app).unwrap_err();

            // Expect: the message points at the blank-id entry by position.
            assert!(
                err.contains("entry 2"),
                "blank-id entry should be named by position, got: {err}"
            );
        }

        #[test]
        fn certs_from_list_names_offending_entry_by_id_when_set() {
            // Setup: a second entry with an id but no common name -> CN error.
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cert;
            app.cert_list[0].id = "root".to_string();
            app.cert_list[0].common_name = "Root".to_string();
            app.cert_list.push(app::CertForm::default());
            app.cert_list[1].id = "leaf".to_string();

            let err = certs_from_list(&app).unwrap_err();
            assert!(
                err.contains("'leaf'"),
                "named entry should be referenced by id, got: {err}"
            );
        }

        #[test]
        fn generate_cert_writes_all_entries_via_pipeline() {
            // Use a real temp dir; the pipeline writes the cert files. We assert
            // a file per entry is produced rather than mocking the saver.
            let tmp = tempfile::tempdir().expect("temp dir");
            let mut app = App::new(tmp.path().to_string_lossy().into_owned());
            app.screen = Screen::Cert;
            app.cert_list[0].id = "root".to_string();
            app.cert_list[0].common_name = "Root".to_string();
            app.cert_list[0].ca = true;
            app.cert_list.push(app::CertForm::default());
            app.cert_list[1].id = "second".to_string();
            app.cert_list[1].common_name = "Second".to_string();
            app.cert_list[1].ca = true;

            let dir = tmp.path().to_string_lossy().into_owned();
            generate(&app, Screen::Cert, &dir).expect("generate over the whole list");

            // Expect: each entry produced its cert PEM.
            let count = std::fs::read_dir(tmp.path())
                .expect("read out dir")
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".pem"))
                .count();
            assert!(
                count >= 2,
                "both certs should be written; found {count} pem files"
            );
        }

        #[test]
        fn generate_summary_uses_cert_list_count() {
            let mut app = App::new("./out".to_string());
            app.cert_list.push(app::CertForm::default());
            app.cert_list.push(app::CertForm::default());
            assert_eq!(generate_summary(&app, Screen::Cert), "3 certificate(s)");
        }
    }

    mod read_dir_effect {
        use super::*;

        fn purpose() -> BrowsePurpose {
            BrowsePurpose::FillField(BrowseTarget {
                screen: Screen::Cert,
                field: 12,
            })
        }

        #[test]
        fn lists_dirs_first_then_files_with_parent_synthesized() {
            // Setup: a temp dir with one subdir and one file.
            let tmp = tempfile::tempdir().expect("temp dir");
            std::fs::create_dir(tmp.path().join("subdir")).expect("mkdir");
            std::fs::write(tmp.path().join("file.txt"), b"x").expect("write file");

            let mut app = App::new("./out".to_string());

            // Invoke the impure effect handler directly.
            read_dir_into_browser(&mut app, tmp.path().to_path_buf(), purpose());

            // Find: the installed browser listing.
            let browser = app.browser.expect("browser installed on success");
            let names: Vec<&str> = browser.entries.iter().map(|e| e.name.as_str()).collect();

            // Expect: `..` first, then the dir, then the file.
            assert_eq!(
                names.first().copied(),
                Some(".."),
                "parent synthesized first"
            );
            assert!(browser.entries[0].is_dir, ".. entry should be a directory");
            let subdir_pos = names.iter().position(|n| *n == "subdir").expect("subdir");
            let file_pos = names.iter().position(|n| *n == "file.txt").expect("file");
            assert!(
                subdir_pos < file_pos,
                "directories sort before files, got: {names:?}"
            );
        }

        #[test]
        fn resolves_literal_dotdot_in_path() {
            // A path containing `/sub/..` should resolve back to the temp dir.
            let tmp = tempfile::tempdir().expect("temp dir");
            std::fs::create_dir(tmp.path().join("sub")).expect("mkdir");
            let with_dotdot = tmp.path().join("sub").join("..");

            let mut app = App::new("./out".to_string());
            read_dir_into_browser(&mut app, with_dotdot, purpose());

            let browser = app.browser.expect("browser installed");
            // canonicalize collapses the `..`, so the listing is the temp dir's.
            assert!(
                browser.entries.iter().any(|e| e.name == "sub" && e.is_dir),
                "resolved dir should list the `sub` subdirectory"
            );
        }

        #[test]
        fn fails_closed_on_unreadable_path() {
            // A non-existent path: the handler records an error and leaves the
            // browser closed rather than panicking.
            let mut app = App::new("./out".to_string());
            read_dir_into_browser(
                &mut app,
                PathBuf::from("/this/path/does/not/exist/at/all"),
                purpose(),
            );
            assert!(app.browser.is_none(), "browser stays closed on I/O error");
            assert!(app.error.is_some(), "an error message is recorded");
        }

        #[test]
        fn read_dir_failure_uses_footer_error_not_popup() {
            // The browse miss is transient and short — it stays in the footer
            // `error` slot (issue #2), never the popup.
            let mut app = App::new("./out".to_string());
            read_dir_into_browser(
                &mut app,
                PathBuf::from("/this/path/does/not/exist/either"),
                purpose(),
            );
            assert!(app.error.is_some(), "directory-read errors use the footer");
            assert!(
                app.error_popup.is_none(),
                "a transient browse miss must not open the error popup"
            );
        }
    }

    mod clear_field_mapping {
        use super::*;

        fn key(code: KeyCode) -> KeyEvent {
            KeyEvent::new(code, KeyModifiers::NONE)
        }

        fn cert_form_app() -> App {
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cert;
            app.focus = Focus::Form;
            app
        }

        #[test]
        fn delete_maps_to_clear_field_in_a_text_context() {
            // A free-text field is focused (text context); Delete still fires.
            let mut app = cert_form_app();
            app.cert_mut().field = 0; // `id` text field
            assert!(is_text_context(&app));
            assert_eq!(
                map_key(key(KeyCode::Delete), &app),
                Some(Message::ClearField)
            );
        }

        #[test]
        fn delete_maps_to_clear_field_outside_a_text_context() {
            // On the menu (no text context), Delete maps the same way.
            let app = App::new("./out".to_string());
            assert!(!is_text_context(&app));
            assert_eq!(
                map_key(key(KeyCode::Delete), &app),
                Some(Message::ClearField)
            );
        }

        #[test]
        fn c_clears_only_while_browsing() {
            use app::{BrowseTarget, FileBrowser};

            // Without a browser open, `c` is a normal typed character.
            let mut app = cert_form_app();
            app.cert_mut().field = 0;
            assert_eq!(
                map_key(key(KeyCode::Char('c')), &app),
                Some(Message::Char('c')),
                "c is a typed char when no browser is open"
            );

            // With the browser open, `c` (and `C`) clears-and-closes.
            app.browser = Some(FileBrowser {
                current_dir: std::path::PathBuf::from("/tmp"),
                entries: Vec::new(),
                selected: 0,
                purpose: BrowsePurpose::FillField(BrowseTarget {
                    screen: Screen::Cert,
                    field: 12,
                }),
            });
            assert_eq!(
                map_key(key(KeyCode::Char('c')), &app),
                Some(Message::ClearField),
                "c clears while browsing"
            );
            assert_eq!(
                map_key(key(KeyCode::Char('C')), &app),
                Some(Message::ClearField),
                "uppercase C also clears while browsing"
            );
        }

        #[test]
        fn text_context_true_while_error_popup_open() {
            // The typing guard suppresses shortcuts under the popup (issue #2).
            let mut app = cert_form_app();
            app.cert_mut().field = 4; // a cycler field — normally not a text context
            assert!(!is_text_context(&app), "cycler alone is not a text context");
            app.set_error_popup("boom");
            assert!(
                is_text_context(&app),
                "the open error popup makes the context 'typing'"
            );
        }
    }

    mod generate_failure_routing {
        use super::*;

        #[test]
        fn generate_failure_opens_error_popup_not_footer() {
            // Setup: a Cert entry that fails to convert (blank id with a CN),
            // mirroring the `certs_from_list` error tests, so `generate`
            // returns `Err`.
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cert;
            app.cert_list[0].common_name = "Leaf".to_string();
            // (id left blank -> conversion error)

            // Invoke the effect runner directly.
            run_effect(
                &mut app,
                Effect::Generate {
                    screen: Screen::Cert,
                    path: "./out".to_string(),
                },
            );

            // Expect: the full error is routed into the popup, the footer status
            // is cleared, and the short footer `error` slot is untouched.
            let popup = app.error_popup.as_deref().expect("popup should be set");
            assert!(
                popup.starts_with("Generate failed:"),
                "popup should carry the generate-failure text, got: {popup}"
            );
            assert!(app.status.is_none(), "status is cleared on failure");
            assert!(
                app.error.is_none(),
                "the footer error slot is not used for a generate failure"
            );
        }
    }

    mod error_popup {
        use super::*;
        use app::{FileBrowser, FileEntry};

        const LONG_MSG: &str = "Generate failed: the certificate helper rejected the request \
            because the supplied signer key does not match the signer certificate; verify the \
            paths and try again.";

        #[test]
        fn renders_title_wrapped_message_and_dismiss_hint() {
            // Setup: a long, multi-word error that must word-wrap inside the popup.
            let mut app = App::new("./out".to_string());
            app.set_error_popup(LONG_MSG);
            let theme = Theme::dark();

            // Invoke
            let text = buffer_text(&render_view(&app, &theme, 120, 40));

            // Expect: the title, the `[!]` marker, a chunk of the wrapped message,
            // and the dismiss hint are all present.
            assert!(
                text.contains("Error"),
                "popup should carry the ` Error ` title, got: {text}"
            );
            assert!(
                text.contains("[!]"),
                "popup body should carry the [!] marker, got: {text}"
            );
            assert!(
                text.contains("Generate failed:"),
                "popup should show the start of the message, got: {text}"
            );
            assert!(
                text.contains("signer key does not match"),
                "popup should show a wrapped chunk of the long message, got: {text}"
            );
            assert!(
                text.contains("Esc / Enter to dismiss"),
                "popup should show the dismiss hint, got: {text}"
            );
        }

        #[test]
        fn bang_marker_carries_error_foreground() {
            // Mirror the footer `[!]` style assertion: the interior marker must
            // render with the themed error foreground.
            let mut app = App::new("./out".to_string());
            app.set_error_popup("boom");
            let theme = Theme::dark();

            let buffer = render_view(&app, &theme, 120, 40);
            let area = *buffer.area();

            // Find the first `[` cell anywhere in the buffer (the popup marker).
            let pos = (area.top()..area.bottom())
                .flat_map(|y| (area.left()..area.right()).map(move |x| (x, y)))
                .find(|&(x, y)| buffer[(x, y)].symbol() == "[")
                .expect("popup should contain the [!] marker");
            assert_eq!(
                buffer[pos].fg, theme.error_fg,
                "the [!] marker should carry the error foreground style"
            );
        }

        #[test]
        fn takes_precedence_over_browser_and_dialog() {
            // All three overlays are set; the error popup must win exclusively.
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cert;
            app.focus = Focus::Form;
            app.dialog = Some(Dialog::Confirm {
                action: ConfirmAction::Generate,
                path: "./out".to_string(),
            });
            app.browser = Some(FileBrowser {
                current_dir: std::path::PathBuf::from("/tmp"),
                entries: vec![FileEntry {
                    name: "thing.pem".to_string(),
                    is_dir: false,
                }],
                selected: 0,
                purpose: BrowsePurpose::FillField(BrowseTarget {
                    screen: Screen::Cert,
                    field: 12,
                }),
            });
            app.set_error_popup("Generate failed: boom");
            let theme = Theme::dark();

            let text = buffer_text(&render_view(&app, &theme, 120, 40));

            // Expect: the error popup renders and neither the browser nor the
            // dialog draws underneath it.
            assert!(
                text.contains("Generate failed: boom"),
                "the error popup should render over everything, got: {text}"
            );
            assert!(
                !text.contains("thing.pem"),
                "the browser must not draw underneath the error popup"
            );
            assert!(
                !text.contains("Output directory:"),
                "the confirm dialog must not draw underneath the error popup"
            );
        }
    }

    mod load_config_mapping {
        use super::*;

        fn cert_form_app() -> App {
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cert;
            app.focus = Focus::Form;
            app
        }

        #[test]
        fn ctrl_l_maps_to_load_config() {
            let app = cert_form_app();
            assert_eq!(
                map_key(ctrl_key('l', false), &app),
                Some(Message::LoadConfig)
            );
        }

        #[test]
        fn ctrl_l_maps_to_load_config_uppercase() {
            // Case-insensitive, like the other Ctrl combos.
            let app = cert_form_app();
            assert_eq!(
                map_key(ctrl_key('L', false), &app),
                Some(Message::LoadConfig)
            );
        }

        #[test]
        fn ctrl_l_fires_while_typing_a_text_field() {
            // A free-text field is focused (text context); Ctrl+L is still not
            // consumed as a typed character.
            let mut app = cert_form_app();
            app.cert_mut().field = 0; // `id` text field
            assert!(is_text_context(&app));
            assert_eq!(
                map_key(ctrl_key('l', false), &app),
                Some(Message::LoadConfig)
            );
        }
    }

    // Test fixtures build form structs field-by-field for readability; the
    // struct-update alternative is noisier here.
    #[allow(clippy::field_reassign_with_default)]
    mod load_config_effect {
        use super::*;
        use crate::config;

        /// Builds a one-line certificate config (a CA root) via the forward
        /// mapper and writes it to `path` so the load path reads a real file.
        fn write_one_cert(path: &std::path::Path, id: &str) {
            let mut form = app::CertForm::default();
            form.id = id.to_string();
            form.common_name = id.to_string();
            form.ca = true;
            let cert = convert::cert_from_form(&form).expect("forward map");
            config::write_certificate_config(vec![cert], path).expect("write cert config");
        }

        #[test]
        fn cert_loads_all_entries_and_sets_success() {
            // Setup: a two-entry certificate config written to a temp file.
            let tmp = tempfile::tempdir().expect("temp dir");
            let yaml = tmp.path().join("certs.yaml");
            let mut root = app::CertForm::default();
            root.id = "root".to_string();
            root.common_name = "Root".to_string();
            root.ca = true;
            let mut leaf = app::CertForm::default();
            leaf.id = "leaf".to_string();
            leaf.common_name = "Leaf".to_string();
            leaf.parent = "root".to_string();
            let certs = vec![
                convert::cert_from_form(&root).expect("root maps"),
                convert::cert_from_form(&leaf).expect("leaf maps"),
            ];
            config::write_certificate_config(certs, &yaml).expect("write");

            let mut app = App::new("./out".to_string());
            let path = yaml.to_string_lossy().into_owned();

            // Invoke
            load_config_into_app(&mut app, Screen::Cert, &path);

            // Expect: both entries loaded, focused, success status with count.
            assert_eq!(app.cert_list.len(), 2, "every entry is loaded");
            assert_eq!(app.cert_list[0].id, "root");
            assert_eq!(app.cert_list[1].id, "leaf");
            assert_eq!(app.cert_index, 0);
            assert_eq!(app.screen, Screen::Cert);
            assert_eq!(app.focus, Focus::Form);
            assert!(app.error_popup.is_none(), "no error on a valid config");
            let status = app.status.as_deref().expect("success status set");
            assert_eq!(status, &format!("Loaded 2 certificate(s) from {path}"));
            assert_eq!(app.status_kind(), StatusKind::Success);
        }

        #[test]
        fn csr_with_csr_and_signing_request_loads_first_csr_in_generate_mode() {
            // Setup: a CSR config holding one generate csr AND one signing request.
            let tmp = tempfile::tempdir().expect("temp dir");
            let yaml = tmp.path().join("csr.yaml");

            let mut gen_form = app::CsrForm::default();
            gen_form.id = "web".to_string();
            gen_form.common_name = "web.example".to_string();
            let csr = convert::csr_from_form(&gen_form)
                .expect("gen csr maps")
                .csrs;

            let mut sign = app::CsrForm::default();
            sign.sign_mode = true;
            sign.csr_pem_file = "req.pem".to_string();
            sign.signer.cert_pem_file = "ca.pem".to_string();
            sign.signer.private_key_pem_file = "ca.key".to_string();
            let to_sign = convert::csr_from_form(&sign).expect("sign maps").to_sign;

            config::write_csr_config(config::CsrData { csrs: csr, to_sign }, &yaml).expect("write");

            let mut app = App::new("./out".to_string());
            let path = yaml.to_string_lossy().into_owned();

            // Invoke
            load_config_into_app(&mut app, Screen::Csr, &path);

            // Expect: the first csr loaded in generate mode; status reports 1 of 2.
            assert!(app.error_popup.is_none());
            assert!(!app.csr.sign_mode, "the generate csr is preferred");
            assert_eq!(app.csr.id, "web");
            assert_eq!(app.screen, Screen::Csr);
            let status = app.status.as_deref().expect("success status");
            assert_eq!(status, &format!("Loaded 1 of 2 CSR entries from {path}"));
        }

        #[test]
        fn csr_with_only_signing_requests_loads_sign_mode() {
            // Setup: a CSR config holding only a signing request.
            let tmp = tempfile::tempdir().expect("temp dir");
            let yaml = tmp.path().join("sign.yaml");

            let mut sign = app::CsrForm::default();
            sign.sign_mode = true;
            sign.csr_pem_file = "req.pem".to_string();
            sign.signer.cert_pem_file = "ca.pem".to_string();
            sign.signer.private_key_pem_file = "ca.key".to_string();
            let to_sign = convert::csr_from_form(&sign).expect("sign maps").to_sign;

            config::write_csr_config(
                config::CsrData {
                    csrs: Vec::new(),
                    to_sign,
                },
                &yaml,
            )
            .expect("write");

            let mut app = App::new("./out".to_string());
            let path = yaml.to_string_lossy().into_owned();

            // Invoke
            load_config_into_app(&mut app, Screen::Csr, &path);

            // Expect: the form is in sign mode.
            assert!(app.error_popup.is_none());
            assert!(app.csr.sign_mode, "only signing requests -> sign mode");
            assert_eq!(app.csr.csr_pem_file, "req.pem");
            let status = app.status.as_deref().expect("success status");
            assert_eq!(status, &format!("Loaded 1 of 1 CSR entries from {path}"));
        }

        #[test]
        fn crl_loads_with_revoked_count() {
            // Setup: a CRL config with one revoked row.
            let tmp = tempfile::tempdir().expect("temp dir");
            let yaml = tmp.path().join("crl.yaml");

            let mut form = app::CrlForm::default();
            form.crl_file = "out.crl".to_string();
            form.signer.cert_pem_file = "ca.pem".to_string();
            form.signer.private_key_pem_file = "ca.key".to_string();
            form.revoked.push(app::RevokedRow {
                serial: "abcd".to_string(),
                reason: 0,
            });
            let crl = convert::crl_from_form(&form).expect("crl maps");
            config::write_crl_config(crl, &yaml).expect("write");

            let mut app = App::new("./out".to_string());
            let path = yaml.to_string_lossy().into_owned();

            // Invoke
            load_config_into_app(&mut app, Screen::Crl, &path);

            // Expect: the CRL loaded, status reports the revoked count.
            assert!(app.error_popup.is_none());
            assert_eq!(app.screen, Screen::Crl);
            assert_eq!(app.crl.revoked.len(), 1);
            let status = app.status.as_deref().expect("success status");
            assert_eq!(status, &format!("Loaded CRL (1 revoked) from {path}"));
        }

        #[test]
        fn cms_loads_first_entry_with_count() {
            // Setup: a CMS config with one entry.
            let tmp = tempfile::tempdir().expect("temp dir");
            let yaml = tmp.path().join("cms.yaml");

            let mut form = app::CmsForm::default();
            form.id = "msg".to_string();
            form.data_file = "data.bin".to_string();
            // A CMS entry now needs at least one output mode (R4); give it a
            // recipient so the fixture is valid without changing the test's
            // intent (loading the first entry and reporting the count).
            form.recipient = "rcpt.pem".to_string();
            let cms = convert::cms_from_form(&form).expect("cms maps");
            config::write_cms_config(vec![cms], &yaml).expect("write");

            let mut app = App::new("./out".to_string());
            let path = yaml.to_string_lossy().into_owned();

            // Invoke
            load_config_into_app(&mut app, Screen::Cms, &path);

            // Expect
            assert!(app.error_popup.is_none());
            assert_eq!(app.screen, Screen::Cms);
            assert_eq!(app.cms.id, "msg");
            let status = app.status.as_deref().expect("success status");
            assert_eq!(status, &format!("Loaded 1 of 1 CMS entries from {path}"));
        }

        #[test]
        fn wrong_shape_file_routes_to_error_popup_without_false_success() {
            // Setup: a valid CMS config loaded on the Cert screen — a mismatched
            // shape. The cert reader must fail, routing to the popup, never a
            // false success, and leaving the form unchanged.
            let tmp = tempfile::tempdir().expect("temp dir");
            let yaml = tmp.path().join("cms.yaml");
            let mut form = app::CmsForm::default();
            form.id = "msg".to_string();
            form.data_file = "data.bin".to_string();
            // Needs an output mode to be a valid CMS entry (R4); a recipient
            // keeps the fixture valid while still exercising the shape mismatch.
            form.recipient = "rcpt.pem".to_string();
            let cms = convert::cms_from_form(&form).expect("cms maps");
            config::write_cms_config(vec![cms], &yaml).expect("write");

            let mut app = App::new("./out".to_string());
            let before = app.cert_list.clone();
            let path = yaml.to_string_lossy().into_owned();

            // Invoke: load the CMS file as a certificate config.
            load_config_into_app(&mut app, Screen::Cert, &path);

            // Expect: error popup, no success, form unchanged.
            let popup = app.error_popup.as_deref().expect("popup set on mismatch");
            assert!(
                popup.starts_with("Not a valid certificate config:"),
                "mismatched file should report a clear parse error, got: {popup}"
            );
            assert!(app.status.is_none(), "no false success on a parse error");
            assert_eq!(
                app.cert_list.len(),
                before.len(),
                "the form is left unchanged on failure"
            );
        }

        #[test]
        fn empty_certificate_config_routes_to_error_popup() {
            // Setup: a valid YAML certificate config with zero entries.
            let tmp = tempfile::tempdir().expect("temp dir");
            let yaml = tmp.path().join("empty.yaml");
            config::write_certificate_config(Vec::new(), &yaml).expect("write empty");

            let mut app = App::new("./out".to_string());
            let path = yaml.to_string_lossy().into_owned();

            // Invoke
            load_config_into_app(&mut app, Screen::Cert, &path);

            // Expect: the empty config is an error, not a silent success.
            let popup = app.error_popup.as_deref().expect("popup on empty config");
            assert_eq!(popup, "Certificate config has no entries");
            assert!(app.status.is_none(), "no success for an empty config");
        }

        #[test]
        fn cert_with_unsupported_rsa_keylength_warns_on_load() {
            // Setup: a valid RSA certificate config whose key length (3072) is
            // not in the {2048,4096} selector. `cert_to_form` would silently
            // coerce it to index 0, so the load must surface a visible warning.
            let tmp = tempfile::tempdir().expect("temp dir");
            let yaml = tmp.path().join("rsa3072.yaml");
            let mut form = app::CertForm::default(); // defaults to RSA
            form.id = "rsa".to_string();
            form.common_name = "RSA".to_string();
            let mut cert = convert::cert_from_form(&form).expect("forward map");
            cert.keytype = config::KeyType::RSA;
            cert.keylength = Some(3072);
            config::write_certificate_config(vec![cert], &yaml).expect("write");

            let mut app = App::new("./out".to_string());
            let path = yaml.to_string_lossy().into_owned();

            // Invoke
            load_config_into_app(&mut app, Screen::Cert, &path);

            // Expect: the load succeeds (no popup) but the success line carries a
            // visible warning naming 3072 and the coerced default (2048).
            assert!(
                app.error_popup.is_none(),
                "an out-of-range length is not a hard error"
            );
            let status = app.status.as_deref().expect("success status set");
            assert!(
                status.starts_with(&format!("Loaded 1 certificate(s) from {path}")),
                "the load-succeeded text is preserved, got: {status}"
            );
            assert!(
                status.contains("3072") && status.contains("2048"),
                "the warning should name the loaded length and the coerced default, got: {status}"
            );
            assert!(
                status.contains("not selectable"),
                "the warning should explain the value is not selectable, got: {status}"
            );
            assert_eq!(app.status_kind(), StatusKind::Success);
        }

        #[test]
        fn cert_with_supported_rsa_keylength_has_no_warning() {
            // A 4096 length is in the selector, so the message is the plain
            // success line with no warning suffix (no-coercion path unchanged).
            let tmp = tempfile::tempdir().expect("temp dir");
            let yaml = tmp.path().join("rsa4096.yaml");
            let mut form = app::CertForm::default();
            form.id = "rsa".to_string();
            form.common_name = "RSA".to_string();
            form.key_length = app::RSA_KEY_LENGTH_OPTIONS
                .iter()
                .position(|&n| n == 4096)
                .expect("4096 is a selectable option");
            let cert = convert::cert_from_form(&form).expect("forward map");
            config::write_certificate_config(vec![cert], &yaml).expect("write");

            let mut app = App::new("./out".to_string());
            let path = yaml.to_string_lossy().into_owned();

            load_config_into_app(&mut app, Screen::Cert, &path);

            let status = app.status.as_deref().expect("success status set");
            assert_eq!(status, &format!("Loaded 1 certificate(s) from {path}"));
            assert!(
                !status.contains("warning"),
                "a supported length must not produce a warning, got: {status}"
            );
        }

        #[test]
        fn csr_with_unsupported_rsa_keylength_warns_on_load() {
            // Setup: a generate-mode CSR config with an out-of-range RSA length.
            let tmp = tempfile::tempdir().expect("temp dir");
            let yaml = tmp.path().join("csr1024.yaml");
            let mut form = app::CsrForm::default(); // defaults to RSA, generate mode
            form.id = "web".to_string();
            form.common_name = "web.example".to_string();
            let mut data = convert::csr_from_form(&form).expect("forward map");
            data.csrs[0].keytype = config::KeyType::RSA;
            data.csrs[0].keylength = Some(1024);
            config::write_csr_config(data, &yaml).expect("write");

            let mut app = App::new("./out".to_string());
            let path = yaml.to_string_lossy().into_owned();

            // Invoke
            load_config_into_app(&mut app, Screen::Csr, &path);

            // Expect: a visible warning naming 1024 and the coerced default 2048.
            assert!(app.error_popup.is_none());
            let status = app.status.as_deref().expect("success status set");
            assert!(
                status.starts_with(&format!("Loaded 1 of 1 CSR entries from {path}")),
                "the load-succeeded text is preserved, got: {status}"
            );
            assert!(
                status.contains("1024") && status.contains("2048"),
                "the warning should name the loaded length and the coerced default, got: {status}"
            );
        }
    }

    mod footer_clear_field {
        use super::*;

        #[test]
        fn footer_help_lists_del_clear_field() {
            let app = App::new("./out".to_string());
            let theme = Theme::dark();

            // Render wide so the full single-line help fits (it is truncated, not
            // wrapped, at narrower widths).
            let text = buffer_text(&render_view(&app, &theme, 200, 50));

            assert!(
                text.contains("Del clear field"),
                "footer should list 'Del clear field', got: {text}"
            );
        }
    }
}
