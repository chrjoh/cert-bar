//! Centralized color/style palette for the cert-bar TUI.
//!
//! The [`Theme`] struct is the single source of truth for every color and
//! emphasis used by the TUI widgets. Widgets reference these fields and the
//! convenience [`Style`] accessors below — no raw `Color`/`Style` literals
//! should appear in widget code.
//!
//! Two constructors are provided:
//! - [`Theme::dark`] — the full-color dark theme (truecolor `Color::Rgb`).
//! - [`Theme::no_color`] — a monochrome fallback that relies on `Modifier`s
//!   (BOLD/REVERSED/DIM) so meaning survives on a terminal without color.
//!
//! [`Theme::from_env`] picks between the two based on the `NO_COLOR`
//! environment variable (any non-empty value disables color, per the
//! `NO_COLOR` informal standard).

use ratatui::style::{Color, Modifier, Style};

/// Palette + emphasis used across the TUI.
///
/// Fields map directly to the roles in the design doc's Color Palette tables.
/// Semantic roles carry both a foreground and a background color so paired
/// status indicators (e.g. `[!]`, `✓`) remain legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    // --- Base colors ---
    /// Main background.
    pub bg_primary: Color,
    /// Title bar / inactive panes background.
    pub bg_secondary: Color,
    /// Selected row / popup background.
    pub bg_elevated: Color,
    /// Body text, active labels.
    pub text_primary: Color,
    /// Hints, inactive labels, chrome.
    pub text_muted: Color,
    /// Unfocused pane borders.
    pub border: Color,
    /// Focused pane border.
    pub border_focused: Color,
    /// Highlights, selection marker.
    pub accent: Color,

    // --- Semantic colors (fg + bg) ---
    /// Error foreground.
    pub error_fg: Color,
    /// Error background.
    pub error_bg: Color,
    /// Warning foreground.
    pub warning_fg: Color,
    /// Warning background.
    pub warning_bg: Color,
    /// Success foreground.
    pub success_fg: Color,
    /// Success background.
    pub success_bg: Color,
    /// Info foreground.
    pub info_fg: Color,
    /// Info background.
    pub info_bg: Color,
}

impl Theme {
    /// Full-color dark theme (truecolor). Values come verbatim from the design
    /// doc's Color Palette tables.
    #[must_use]
    pub const fn dark() -> Self {
        Self {
            // Base
            bg_primary: Color::Rgb(27, 27, 31),
            bg_secondary: Color::Rgb(40, 40, 48),
            bg_elevated: Color::Rgb(55, 55, 65),
            text_primary: Color::Rgb(230, 230, 230),
            // Lightened from #9696A0 so `text_muted` clears WCAG AA (4.5:1) on
            // the elevated popup background (#373741): #AAAAB4 yields ~5.11:1
            // there, and stays well above AA on the darker bg-primary
            // (#1B1B1F, ~7.46:1) and bg-secondary (#282830, ~6.35:1).
            text_muted: Color::Rgb(170, 170, 180),
            border: Color::Rgb(90, 90, 100),
            border_focused: Color::Rgb(100, 180, 255),
            accent: Color::Rgb(100, 180, 255),
            // Semantic
            error_fg: Color::Rgb(255, 110, 110),
            error_bg: Color::Rgb(60, 20, 20),
            warning_fg: Color::Rgb(255, 200, 90),
            warning_bg: Color::Rgb(55, 45, 15),
            success_fg: Color::Rgb(120, 220, 120),
            success_bg: Color::Rgb(20, 55, 20),
            info_fg: Color::Rgb(120, 190, 255),
            info_bg: Color::Rgb(20, 35, 60),
        }
    }

    /// Monochrome fallback for `NO_COLOR` / 16-color / themed terminals.
    ///
    /// Every field resolves to [`Color::Reset`] so the terminal's own
    /// foreground/background is used. Distinctions between roles are then
    /// carried by `Modifier`s in the [`Style`] accessors (BOLD/REVERSED/DIM),
    /// never by color alone.
    #[must_use]
    pub const fn no_color() -> Self {
        Self {
            bg_primary: Color::Reset,
            bg_secondary: Color::Reset,
            bg_elevated: Color::Reset,
            text_primary: Color::Reset,
            text_muted: Color::Reset,
            border: Color::Reset,
            border_focused: Color::Reset,
            accent: Color::Reset,
            error_fg: Color::Reset,
            error_bg: Color::Reset,
            warning_fg: Color::Reset,
            warning_bg: Color::Reset,
            success_fg: Color::Reset,
            success_bg: Color::Reset,
            info_fg: Color::Reset,
            info_bg: Color::Reset,
        }
    }

    /// Choose a theme based on the environment.
    ///
    /// Honors the `NO_COLOR` informal standard: if `NO_COLOR` is set to any
    /// non-empty value, the monochrome [`Theme::no_color`] is returned;
    /// otherwise the full-color [`Theme::dark`].
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var_os("NO_COLOR") {
            Some(v) if !v.is_empty() => Self::no_color(),
            _ => Self::dark(),
        }
    }

    /// Whether this theme is the monochrome fallback (no truecolor).
    #[must_use]
    pub fn is_monochrome(&self) -> bool {
        *self == Self::no_color()
    }

    // --- Base style accessors ---

    /// Default body style: primary text on the primary background.
    #[must_use]
    pub fn base(&self) -> Style {
        Style::default().fg(self.text_primary).bg(self.bg_primary)
    }

    /// Title bar style: bold primary text on the secondary background.
    #[must_use]
    pub fn title(&self) -> Style {
        Style::default()
            .fg(self.text_primary)
            .bg(self.bg_secondary)
            .add_modifier(Modifier::BOLD)
    }

    /// Muted chrome (hints, inactive labels, optional markers).
    ///
    /// No `Modifier::DIM`: DIM is terminal-dependent and is **not** counted by
    /// the WCAG contrast formula, so it only lowers the effective contrast of
    /// muted text on the elevated popup background without adding any reliable
    /// signal. Legibility is carried entirely by the `text_muted` color, which
    /// is chosen to clear AA on every background it is drawn over.
    #[must_use]
    pub fn muted(&self) -> Style {
        Style::default().fg(self.text_muted)
    }

    /// Disabled / optional-empty element style.
    #[must_use]
    pub fn disabled(&self) -> Style {
        self.muted()
    }

    /// Active form-field label (bold so it survives without color).
    #[must_use]
    pub fn active_label(&self) -> Style {
        Style::default()
            .fg(self.text_primary)
            .add_modifier(Modifier::BOLD)
    }

    /// Inactive form-field label.
    #[must_use]
    pub fn inactive_label(&self) -> Style {
        Style::default().fg(self.text_muted)
    }

    /// Accent style for highlights / selection markers.
    #[must_use]
    pub fn accent(&self) -> Style {
        Style::default().fg(self.accent)
    }

    // --- Border styles ---

    /// Unfocused pane border.
    #[must_use]
    pub fn border(&self) -> Style {
        Style::default().fg(self.border)
    }

    /// Focused pane border (bold so weight reads on monochrome terminals; pair
    /// with `BorderType::Thick` on the `Block`).
    #[must_use]
    pub fn focused_border(&self) -> Style {
        Style::default()
            .fg(self.border_focused)
            .add_modifier(Modifier::BOLD)
    }

    // --- Selection ---

    /// Selected row / list highlight. Uses `Modifier::REVERSED` so the
    /// selection is visible even without color.
    #[must_use]
    pub fn selected(&self) -> Style {
        Style::default()
            .bg(self.bg_elevated)
            .add_modifier(Modifier::REVERSED)
    }

    // --- Popup / overlay ---

    /// Popup / overlay background style.
    #[must_use]
    pub fn popup(&self) -> Style {
        Style::default().fg(self.text_primary).bg(self.bg_elevated)
    }

    // --- Semantic styles (paired with a symbol/label in widget code) ---

    /// Error style; bold so it stands out on monochrome terminals.
    #[must_use]
    pub fn error(&self) -> Style {
        Style::default()
            .fg(self.error_fg)
            .bg(self.error_bg)
            .add_modifier(Modifier::BOLD)
    }

    /// Warning style; bold so it stands out on monochrome terminals.
    #[must_use]
    pub fn warning(&self) -> Style {
        Style::default()
            .fg(self.warning_fg)
            .bg(self.warning_bg)
            .add_modifier(Modifier::BOLD)
    }

    /// Success style.
    #[must_use]
    pub fn success(&self) -> Style {
        Style::default().fg(self.success_fg).bg(self.success_bg)
    }

    /// Info style.
    #[must_use]
    pub fn info(&self) -> Style {
        Style::default().fg(self.info_fg).bg(self.info_bg)
    }
}

impl Default for Theme {
    /// Defaults to the environment-aware theme (honors `NO_COLOR`).
    fn default() -> Self {
        Self::from_env()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod dark {
        use super::*;

        #[test]
        fn base_colors_match_design_doc() {
            let t = Theme::dark();
            assert_eq!(t.bg_primary, Color::Rgb(27, 27, 31));
            assert_eq!(t.bg_secondary, Color::Rgb(40, 40, 48));
            assert_eq!(t.bg_elevated, Color::Rgb(55, 55, 65));
            assert_eq!(t.text_primary, Color::Rgb(230, 230, 230));
            assert_eq!(t.text_muted, Color::Rgb(170, 170, 180));
            assert_eq!(t.border, Color::Rgb(90, 90, 100));
            assert_eq!(t.border_focused, Color::Rgb(100, 180, 255));
            assert_eq!(t.accent, Color::Rgb(100, 180, 255));
        }

        #[test]
        fn semantic_colors_have_fg_and_bg() {
            let t = Theme::dark();
            assert_eq!(t.error_fg, Color::Rgb(255, 110, 110));
            assert_eq!(t.error_bg, Color::Rgb(60, 20, 20));
            assert_eq!(t.warning_fg, Color::Rgb(255, 200, 90));
            assert_eq!(t.warning_bg, Color::Rgb(55, 45, 15));
            assert_eq!(t.success_fg, Color::Rgb(120, 220, 120));
            assert_eq!(t.success_bg, Color::Rgb(20, 55, 20));
            assert_eq!(t.info_fg, Color::Rgb(120, 190, 255));
            assert_eq!(t.info_bg, Color::Rgb(20, 35, 60));
        }
    }

    mod no_color {
        use super::*;

        #[test]
        fn every_field_resets_to_terminal_default() {
            let t = Theme::no_color();
            assert_eq!(t.bg_primary, Color::Reset);
            assert_eq!(t.text_primary, Color::Reset);
            assert_eq!(t.border_focused, Color::Reset);
            assert_eq!(t.error_fg, Color::Reset);
            assert_eq!(t.success_bg, Color::Reset);
            assert!(t.is_monochrome());
        }

        #[test]
        fn meaning_survives_via_modifiers() {
            let t = Theme::no_color();
            // Selection must be visible without color.
            assert!(t.selected().add_modifier.contains(Modifier::REVERSED));
            // Focus must read by weight.
            assert!(t.focused_border().add_modifier.contains(Modifier::BOLD));
            // Errors/warnings emphasized by weight.
            assert!(t.error().add_modifier.contains(Modifier::BOLD));
            assert!(t.warning().add_modifier.contains(Modifier::BOLD));
        }
    }

    mod contrast {
        use super::*;

        /// Relative luminance per WCAG 2.1 (sRGB), for `Color::Rgb` only.
        fn luminance(color: Color) -> f64 {
            let Color::Rgb(r, g, b) = color else {
                panic!("contrast check expects truecolor");
            };
            let chan = |c: u8| {
                let c = f64::from(c) / 255.0;
                if c <= 0.03928 {
                    c / 12.92
                } else {
                    ((c + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)
        }

        /// WCAG 2.1 contrast ratio between two truecolor colors.
        fn ratio(fg: Color, bg: Color) -> f64 {
            let (l1, l2) = (luminance(fg), luminance(bg));
            let (hi, lo) = if l1 >= l2 { (l1, l2) } else { (l2, l1) };
            (hi + 0.05) / (lo + 0.05)
        }

        #[test]
        fn muted_text_meets_aa_on_every_background_it_is_drawn_over() {
            let t = Theme::dark();
            // The popup/overlay (bg-elevated) is the tightest case and the one
            // that previously failed at 4.01:1.
            assert!(
                ratio(t.text_muted, t.bg_elevated) >= 4.5,
                "text_muted on bg_elevated must clear AA, got {:.3}:1",
                ratio(t.text_muted, t.bg_elevated)
            );
            // The form footer/hints draw muted text on the darker base/title bars.
            assert!(ratio(t.text_muted, t.bg_primary) >= 4.5);
            assert!(ratio(t.text_muted, t.bg_secondary) >= 4.5);
        }

        #[test]
        fn muted_style_does_not_dim_below_its_contrast() {
            // DIM is terminal-dependent and uncounted by WCAG, so the popup
            // hint style must not carry it (it would only lower the effective
            // contrast of the AA-safe muted color).
            let t = Theme::dark();
            assert!(!t.muted().add_modifier.contains(Modifier::DIM));
        }
    }

    mod from_env {
        use super::*;

        #[test]
        fn dark_is_not_monochrome() {
            assert!(!Theme::dark().is_monochrome());
        }
    }
}
