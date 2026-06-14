//! Elm-style application model for the cert-bar TUI.
//!
//! This module is pure state: an [`App`] model, a [`Message`] enum describing
//! input intents, and a pure [`App::update`] reducer that performs **no I/O**.
//! Terminal setup, event reading, rendering and the generate/save side effects
//! all live in [`crate::tui`] (`mod.rs`); the form-state -> config conversions
//! live in [`crate::tui::convert`].
//!
//! Form-state option sets for enum fields are **not** redefined here: they reuse
//! the canonical config enums via the `*_OPTIONS` slices below
//! ([`KEY_TYPE_OPTIONS`], [`HASH_ALG_OPTIONS`], [`USAGE_OPTIONS`],
//! [`REASON_OPTIONS`]).

use crate::config::{HashAlg, KeyType, Reason, Usage};

/// The four top-level forms plus the menu, mirroring the CLI subcommands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Top-level Certificate / CSR / CRL / CMS selector.
    Menu,
    /// Certificate form (mirrors [`crate::config::Certificate`]).
    Cert,
    /// CSR form (mirrors [`crate::config::Csr`] + [`crate::config::SigningRequest`]).
    Csr,
    /// CRL form (mirrors [`crate::config::Crl`] + revoked rows).
    Crl,
    /// CMS form (mirrors [`crate::config::Cms`]).
    Cms,
}

/// Which pane currently has keyboard focus.
///
/// On most screens focus toggles between [`Focus::Menu`] and [`Focus::Form`].
/// The Cert screen additionally has an [`Focus::Entries`] target (the
/// multi-certificate sub-list), so Tab cycles **Menu → Entries → Form** there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    /// The left-hand menu list.
    Menu,
    /// The Cert-screen multi-certificate sub-list (`cert_list`). Only reachable
    /// on [`Screen::Cert`]. `Up`/`Down` change the selected entry, `a` adds an
    /// entry, `d` deletes the current one, and `Enter` moves focus into the
    /// form to edit the selected entry.
    Entries,
    /// The right-hand form for the active [`Screen`].
    Form,
}

/// Canonical menu entries, in display order. Index maps to a [`Screen`].
pub const MENU_ITEMS: [&str; 4] = ["Certificate", "CSR", "CRL", "CMS"];

/// Option set for the key-type cycler. Reuses [`KeyType`] — never redefined.
///
/// PQC variants are included only when the `pqc` feature is enabled, matching
/// the config enum definition.
pub const KEY_TYPE_OPTIONS: &[KeyType] = &[
    KeyType::RSA,
    KeyType::P224,
    KeyType::P256,
    KeyType::P384,
    KeyType::P521,
    KeyType::Ed25519,
    #[cfg(feature = "pqc")]
    KeyType::MlDsa44,
    #[cfg(feature = "pqc")]
    KeyType::MlDsa65,
    #[cfg(feature = "pqc")]
    KeyType::MlDsa87,
    #[cfg(feature = "pqc")]
    KeyType::SlhDsaSha2_128s,
    #[cfg(feature = "pqc")]
    KeyType::SlhDsaSha2_192s,
    #[cfg(feature = "pqc")]
    KeyType::SlhDsaSha2_256s,
];

/// Option set for the hash-algorithm cycler. Reuses [`HashAlg`].
pub const HASH_ALG_OPTIONS: &[HashAlg] = &[
    HashAlg::SHA256,
    HashAlg::SHA384,
    HashAlg::SHA512,
    HashAlg::SHA1,
];

/// Option set for the usage multi-select. Reuses [`Usage`].
pub const USAGE_OPTIONS: &[Usage] = &[
    Usage::serverauth,
    Usage::clientauth,
    Usage::certsign,
    Usage::crlsign,
    Usage::encipherment,
    Usage::signature,
    Usage::contentcommitment,
];

/// Option set for the CRL revocation-reason cycler. Reuses [`Reason`].
pub const REASON_OPTIONS: &[Reason] = &[
    Reason::Unspecified,
    Reason::KeyCompromise,
    Reason::CaCompromise,
];

/// Selectable RSA key lengths (bits). Only applies when the key type is RSA;
/// other key types have no selectable length (see [`KeyType::uses_rsa_key_length`]).
/// Mirrors the lengths the generation backend maps.
pub const RSA_KEY_LENGTH_OPTIONS: &[u32] = &[2048, 4096];

/// A `cert_pem_file` / `private_key_pem_file` pair, mirroring
/// [`crate::config::Signer`]. Stored as text buffers; left empty when the
/// optional signer is unset.
#[derive(Debug, Clone, Default)]
pub struct SignerState {
    /// Path to the signer certificate PEM file.
    pub cert_pem_file: String,
    /// Path to the signer private key PEM file.
    pub private_key_pem_file: String,
}

/// Form state mirroring [`crate::config::Certificate`].
///
/// Free-text fields are plain `String` buffers; enum fields hold a selected
/// index into the corresponding `*_OPTIONS` slice; multi-selects hold a `bool`
/// per option; booleans hold a toggle. `altnames` is held as a single
/// comma-separated buffer and split during conversion.
#[derive(Debug, Clone)]
pub struct CertForm {
    /// Certificate `id`.
    pub id: String,
    /// `pkix.commonname`.
    pub common_name: String,
    /// `pkix.country`.
    pub country: String,
    /// `pkix.organization`.
    pub organization: String,
    /// Index into [`KEY_TYPE_OPTIONS`].
    pub key_type: usize,
    /// Index into [`RSA_KEY_LENGTH_OPTIONS`] (only used when key type is RSA).
    pub key_length: usize,
    /// Index into [`HASH_ALG_OPTIONS`].
    pub hash_alg: usize,
    /// One toggle per [`USAGE_OPTIONS`] entry.
    pub usage: Vec<bool>,
    /// Highlighted option within the usage multi-select (moved with ←→; the
    /// option under it is toggled with Space).
    pub usage_cursor: usize,
    /// Comma-separated alt-names buffer.
    pub altnames: String,
    /// `ca` toggle.
    pub ca: bool,
    /// `validto` date buffer (optional; empty means unset).
    pub valid_to: String,
    /// Optional `parent` certificate id (empty means unset).
    pub parent: String,
    /// Optional inline signer (used when `parent` is empty).
    pub signer: SignerState,
    /// Currently focused field index within the form.
    pub field: usize,
}

impl Default for CertForm {
    fn default() -> Self {
        Self {
            id: String::new(),
            common_name: String::new(),
            country: String::new(),
            organization: String::new(),
            key_type: 0,
            key_length: 0,
            hash_alg: 0,
            usage: vec![false; USAGE_OPTIONS.len()],
            usage_cursor: 0,
            altnames: String::new(),
            ca: false,
            valid_to: String::new(),
            parent: String::new(),
            signer: SignerState::default(),
            field: 0,
        }
    }
}

/// Form state mirroring [`crate::config::Csr`] plus the optional
/// [`crate::config::SigningRequest`] (sign-existing-CSR) mode.
#[derive(Debug, Clone)]
pub struct CsrForm {
    /// CSR `id`.
    pub id: String,
    /// `pkix.commonname`.
    pub common_name: String,
    /// `pkix.country`.
    pub country: String,
    /// `pkix.organization`.
    pub organization: String,
    /// Index into [`KEY_TYPE_OPTIONS`].
    pub key_type: usize,
    /// Index into [`RSA_KEY_LENGTH_OPTIONS`] (only used when key type is RSA).
    pub key_length: usize,
    /// Index into [`HASH_ALG_OPTIONS`].
    pub hash_alg: usize,
    /// One toggle per [`USAGE_OPTIONS`] entry.
    pub usage: Vec<bool>,
    /// Highlighted option within the usage multi-select (moved with ←→; the
    /// option under it is toggled with Space).
    pub usage_cursor: usize,
    /// Comma-separated alt-names buffer.
    pub altnames: String,
    /// When `true`, the form describes a [`crate::config::SigningRequest`]
    /// (sign an existing CSR) rather than generating a new CSR.
    pub sign_mode: bool,
    /// `csr_pem_file` for sign mode.
    pub csr_pem_file: String,
    /// Signer for sign mode.
    pub signer: SignerState,
    /// `validto` for sign mode (optional).
    pub valid_to: String,
    /// `ca` toggle for sign mode.
    pub ca: bool,
    /// Currently focused field index.
    pub field: usize,
}

impl Default for CsrForm {
    fn default() -> Self {
        Self {
            id: String::new(),
            common_name: String::new(),
            country: String::new(),
            organization: String::new(),
            key_type: 0,
            key_length: 0,
            hash_alg: 0,
            usage: vec![false; USAGE_OPTIONS.len()],
            usage_cursor: 0,
            altnames: String::new(),
            sign_mode: false,
            csr_pem_file: String::new(),
            signer: SignerState::default(),
            valid_to: String::new(),
            ca: false,
            field: 0,
        }
    }
}

/// A single revoked-certificate row, mirroring [`crate::config::CertInfo`].
#[derive(Debug, Clone, Default)]
pub struct RevokedRow {
    /// Hex serial buffer (colons allowed; stripped during conversion).
    pub serial: String,
    /// Index into [`REASON_OPTIONS`].
    pub reason: usize,
}

/// Form state mirroring [`crate::config::Crl`] with editable revoked rows.
#[derive(Debug, Clone, Default)]
pub struct CrlForm {
    /// `crl_file` path.
    pub crl_file: String,
    /// CRL signer (required).
    pub signer: SignerState,
    /// Editable list of revoked entries.
    pub revoked: Vec<RevokedRow>,
    /// Currently focused field index.
    pub field: usize,
    /// Currently selected revoked row, if any.
    pub selected_row: Option<usize>,
}

/// Form state mirroring [`crate::config::Cms`].
#[derive(Debug, Clone, Default)]
pub struct CmsForm {
    /// CMS `id`.
    pub id: String,
    /// `data_file` path.
    pub data_file: String,
    /// Optional signer (empty buffers mean unset).
    pub signer: SignerState,
    /// Optional `recipient` cert path (empty means unset).
    pub recipient: String,
    /// `detached` toggle.
    pub detached: bool,
    /// Currently focused field index.
    pub field: usize,
}

/// A pending confirm dialog, prompting for an action and an output path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dialog {
    /// "Generate / Save YAML / Cancel" prompt with an output-path buffer.
    Confirm {
        /// Which action the prompt will perform.
        action: ConfirmAction,
        /// Output path / directory buffer being edited.
        path: String,
    },
}

/// The action a [`Dialog::Confirm`] will perform on accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAction {
    /// Run the generation pipeline now.
    Generate,
    /// Write a replayable YAML config.
    SaveYaml,
}

/// How the transient status line should be styled by the renderer.
///
/// Errors are tracked separately (in [`App::error`]); this only distinguishes a
/// plain informational status from a success confirmation so the footer can
/// render success with a `✓` marker and the success theme style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StatusKind {
    /// A plain, transient informational hint (muted style).
    #[default]
    Info,
    /// A success confirmation (e.g. a completed generate/save), rendered with
    /// a `✓` marker and the success theme style.
    Success,
}

/// Identifies a focusable file-path field that the file browser can fill.
///
/// The compact `{ screen, field }` shape lets the browser (developer-03) write
/// a chosen path back into the matching text buffer via the same field-index
/// routing used by [`App::active_text_field_mut`]. It is produced by
/// [`App::focused_path_field`] only for fields that are genuine browseable
/// paths (signer cert/key, data/recipient/csr files).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowseTarget {
    /// The screen whose form owns the path field.
    pub screen: Screen,
    /// The focused field index within that form.
    pub field: usize,
}

/// Why the file-browser overlay is open.
///
/// The browser serves two distinct intents, modeled as a single sum type so the
/// [`FileBrowser`] is always exactly one purpose and the file-confirm arm of
/// [`App::update_browser`] is one exhaustive `match`:
///
/// - [`BrowsePurpose::FillField`] — write the chosen path into a form path field
///   (the `Ctrl+O` behavior). Carries the [`BrowseTarget`] to write back into.
/// - [`BrowsePurpose::LoadConfig`] — parse the chosen file as `screen`'s config
///   type and load it into the form(s) (the `Ctrl+L` behavior). Carries the
///   [`Screen`] whose config type the file is parsed as.
///
/// The purpose is preserved across directory re-listings by threading it through
/// [`Effect::ReadDir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowsePurpose {
    /// Write the chosen path into the form path field identified by the target
    /// (today's `Ctrl+O` behavior).
    FillField(BrowseTarget),
    /// Parse the chosen file as the given screen's config type and load it into
    /// the form(s) (the `Ctrl+L` behavior).
    LoadConfig(Screen),
}

/// A single directory listing row held by the [`FileBrowser`].
///
/// Produced by the directory reader in `mod.rs` (the impure `std::fs::read_dir`
/// effect): the reader sorts directories first then files and synthesizes a
/// `..` parent entry (`name == ".."`, `is_dir == true`) unless the current
/// directory is a filesystem root. The reducer treats the listing as given and
/// never touches the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// The entry's file name (just the final path component; `..` for parent).
    pub name: String,
    /// Whether this entry is a directory (descendable on `Enter`).
    pub is_dir: bool,
}

/// State for the reusable file-browser overlay.
///
/// Held by [`App::browser`] as an `Option`, orthogonal to the confirm
/// [`Dialog`]. Opened with `Ctrl+O` while a browseable path field is focused
/// (see [`App::focused_path_field`]) to fill that field, or with `Ctrl+L` to
/// load a config file; which one is recorded in [`FileBrowser::purpose`].
///
/// The directory contents in [`FileBrowser::entries`] are loaded by the impure
/// `Effect::ReadDir` handler in `mod.rs`, which calls back
/// [`App::set_browser_entries`]. The reducer only navigates this loaded
/// listing; descending into a directory (or going up) is modeled by returning a
/// fresh [`Effect::ReadDir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBrowser {
    /// The directory currently being listed.
    pub current_dir: std::path::PathBuf,
    /// The loaded entries for `current_dir` (dirs-first, `..` synthesized by
    /// the reader). Empty until the first `set_browser_entries` callback.
    pub entries: Vec<FileEntry>,
    /// The highlighted entry index, clamped to `entries`.
    pub selected: usize,
    /// Why the browser is open (fill a path field, or load a config file).
    pub purpose: BrowsePurpose,
}

/// The complete TUI model. Rendering reads this; [`App::update`] mutates it.
#[derive(Debug, Clone)]
pub struct App {
    /// Which screen/form is active.
    pub screen: Screen,
    /// Which pane has focus.
    pub focus: Focus,
    /// Selected menu index (into [`MENU_ITEMS`]).
    pub menu_index: usize,
    /// Certificate form entries. Invariant: never empty — [`App::new`] seeds a
    /// single [`CertForm::default`]. The Cert screen edits one entry at a time
    /// (`cert_list[cert_index]`); a chain of certs (CA → intermediate → leaf)
    /// is built by adding entries and referencing each other's `id` via
    /// `parent`. Reach the active entry through [`App::cert`] / [`App::cert_mut`].
    pub cert_list: Vec<CertForm>,
    /// Index of the certificate entry currently being edited. Always a valid
    /// index into `cert_list` (clamped on add/delete/select).
    pub cert_index: usize,
    /// CSR form entries. Invariant: never empty — [`App::new`] seeds a single
    /// [`CsrForm::default`]. The CSR screen edits one entry at a time
    /// (`csr_list[csr_index]`); each entry's `sign_mode` records whether it is a
    /// generate-mode CSR or a sign-existing-CSR request. Reach the active entry
    /// through [`App::csr`] / [`App::csr_mut`].
    pub csr_list: Vec<CsrForm>,
    /// Index of the CSR entry currently being edited. Always a valid index into
    /// `csr_list` (clamped on add/delete/select).
    pub csr_index: usize,
    /// CRL form state.
    pub crl: CrlForm,
    /// CMS form entries. Invariant: never empty — [`App::new`] seeds a single
    /// [`CmsForm::default`]. The CMS screen edits one entry at a time
    /// (`cms_list[cms_index]`). Reach the active entry through [`App::cms`] /
    /// [`App::cms_mut`].
    pub cms_list: Vec<CmsForm>,
    /// Index of the CMS entry currently being edited. Always a valid index into
    /// `cms_list` (clamped on add/delete/select).
    pub cms_index: usize,
    /// Active confirm dialog, if any.
    pub dialog: Option<Dialog>,
    /// Active file-browser overlay, if any. Orthogonal to [`App::dialog`];
    /// opened via [`Message::OpenBrowser`] (`Ctrl+O`) when a browseable path
    /// field is focused. While `Some`, browser navigation takes precedence over
    /// normal form keys in [`App::update`].
    pub browser: Option<FileBrowser>,
    /// Active error popup, if any. A centered, word-wrapped, dismissable modal
    /// holding the full text of a failed [`Effect`] (set via
    /// [`App::set_error_popup`] by the event loop). Orthogonal to [`App::dialog`]
    /// and [`App::browser`]; when `Some`, it takes precedence over every other
    /// overlay in [`App::update`] and is dismissed with `Esc`/`Enter`. Distinct
    /// from the transient footer [`App::error`] slot, which is kept for short
    /// messages.
    pub error_popup: Option<String>,
    /// Transient status / success line shown in the footer.
    pub status: Option<String>,
    /// How [`App::status`] should be styled (info vs success).
    pub status_kind: StatusKind,
    /// Transient error line shown in the footer.
    pub error: Option<String>,
    /// Default output directory used to pre-fill the confirm dialog.
    pub output_dir: String,
    /// Set to `true` by [`Message::Quit`]; the event loop exits when seen.
    pub should_quit: bool,
}

impl App {
    /// Creates a new model with empty forms and the given default output dir.
    #[must_use]
    pub fn new(output_dir: String) -> Self {
        Self {
            screen: Screen::Menu,
            focus: Focus::Menu,
            menu_index: 0,
            cert_list: vec![CertForm::default()],
            cert_index: 0,
            csr_list: vec![CsrForm::default()],
            csr_index: 0,
            crl: CrlForm::default(),
            cms_list: vec![CmsForm::default()],
            cms_index: 0,
            dialog: None,
            browser: None,
            error_popup: None,
            status: None,
            status_kind: StatusKind::Info,
            error: None,
            output_dir,
            should_quit: false,
        }
    }

    /// The in-range index of the active certificate entry.
    ///
    /// `cert_list` is never empty; this clamps a stale `cert_index` to `0`
    /// rather than ever pointing past the end.
    fn active_cert_index(&self) -> usize {
        if self.cert_index < self.cert_list.len() {
            self.cert_index
        } else {
            0
        }
    }

    /// Shared reference to the certificate entry currently being edited
    /// (`cert_list[cert_index]`).
    ///
    /// `cert_list` is never empty (invariant maintained by [`App::new`] and the
    /// add/delete reducer arms) and [`App::active_cert_index`] clamps any stale
    /// index into range, so the indexing is always valid and never panics.
    #[must_use]
    pub fn cert(&self) -> &CertForm {
        let idx = self.active_cert_index();
        &self.cert_list[idx]
    }

    /// Mutable reference to the certificate entry currently being edited.
    ///
    /// See [`App::cert`] for the never-empty invariant.
    pub fn cert_mut(&mut self) -> &mut CertForm {
        let idx = self.active_cert_index();
        &mut self.cert_list[idx]
    }

    /// The in-range index of the active CSR entry.
    ///
    /// `csr_list` is never empty; this clamps a stale `csr_index` to `0` rather
    /// than ever pointing past the end (mirrors [`App::active_cert_index`]).
    fn active_csr_index(&self) -> usize {
        if self.csr_index < self.csr_list.len() {
            self.csr_index
        } else {
            0
        }
    }

    /// Shared reference to the CSR entry currently being edited
    /// (`csr_list[csr_index]`).
    ///
    /// `csr_list` is never empty (invariant maintained by [`App::new`] and the
    /// add/delete reducer arms) and [`App::active_csr_index`] clamps any stale
    /// index into range, so the indexing is always valid and never panics.
    #[must_use]
    pub fn csr(&self) -> &CsrForm {
        let idx = self.active_csr_index();
        &self.csr_list[idx]
    }

    /// Mutable reference to the CSR entry currently being edited.
    ///
    /// See [`App::csr`] for the never-empty invariant.
    pub fn csr_mut(&mut self) -> &mut CsrForm {
        let idx = self.active_csr_index();
        &mut self.csr_list[idx]
    }

    /// The in-range index of the active CMS entry.
    ///
    /// `cms_list` is never empty; this clamps a stale `cms_index` to `0` rather
    /// than ever pointing past the end (mirrors [`App::active_cert_index`]).
    fn active_cms_index(&self) -> usize {
        if self.cms_index < self.cms_list.len() {
            self.cms_index
        } else {
            0
        }
    }

    /// Shared reference to the CMS entry currently being edited
    /// (`cms_list[cms_index]`).
    ///
    /// `cms_list` is never empty (invariant maintained by [`App::new`] and the
    /// add/delete reducer arms) and [`App::active_cms_index`] clamps any stale
    /// index into range, so the indexing is always valid and never panics.
    #[must_use]
    pub fn cms(&self) -> &CmsForm {
        let idx = self.active_cms_index();
        &self.cms_list[idx]
    }

    /// Mutable reference to the CMS entry currently being edited.
    ///
    /// See [`App::cms`] for the never-empty invariant.
    pub fn cms_mut(&mut self) -> &mut CmsForm {
        let idx = self.active_cms_index();
        &mut self.cms_list[idx]
    }

    /// Whether `screen` carries a multi-entry sub-list (Cert / Csr / Cms), as
    /// opposed to a single form (Crl) or no form (Menu). Drives the 3-way Tab
    /// cycle and the entry add/delete/navigation handlers so they don't need to
    /// special-case each entry-bearing screen individually.
    fn screen_has_entries(screen: Screen) -> bool {
        matches!(screen, Screen::Cert | Screen::Csr | Screen::Cms)
    }

    /// Maps the selected menu index to its [`Screen`].
    #[must_use]
    pub fn menu_screen(&self) -> Screen {
        match self.menu_index {
            1 => Screen::Csr,
            2 => Screen::Crl,
            3 => Screen::Cms,
            _ => Screen::Cert,
        }
    }

    /// The number of focusable fields in the active form. Used to clamp
    /// up/down navigation. Returns `0` while on the menu.
    fn active_field_count(&self) -> usize {
        match self.screen {
            // Field counts are intentionally generous bounds matching the
            // render order chosen by the forms module; clamping keeps the
            // selection in range even if a form grows.
            // Cert: 14 fields (0..=13), including the new signer key pem at 13.
            Screen::Cert => 14,
            // Csr: 15 fields (0..=14). 0..=12 unchanged; 13 = signer cert pem,
            // 14 = signer private-key pem (mirrors Cert's 12/13). These make
            // sign-mode CSR signers reachable by Up/Down, typing and Ctrl+O.
            Screen::Csr => 15,
            // Crl: the 3 fixed text fields are `field` 0..=2. Revoked rows are
            // *not* counted here; they are addressed by `selected_row` and
            // reached by stepping past field 2 (see `move_down`/`move_up`).
            Screen::Crl => 3,
            Screen::Cms => 5,
            Screen::Menu => 0,
        }
    }

    /// Mutable access to the active form's focused-field index, if a form is
    /// active. Returns `None` on the menu screen.
    fn active_field_mut(&mut self) -> Option<&mut usize> {
        match self.screen {
            Screen::Cert => Some(&mut self.cert_mut().field),
            Screen::Csr => Some(&mut self.csr_mut().field),
            Screen::Crl => Some(&mut self.crl.field),
            Screen::Cms => Some(&mut self.cms_mut().field),
            Screen::Menu => None,
        }
    }
}

/// Input intents produced from crossterm key events by the input mapper in
/// `mod.rs`. The reducer is driven exclusively by these — it never reads the
/// terminal itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Move selection/field up.
    Up,
    /// Move selection/field down.
    Down,
    /// Cycle the active option to the previous value.
    Left,
    /// Cycle the active option to the next value.
    Right,
    /// Move focus to the next pane (Tab).
    FocusNext,
    /// Move focus to the previous pane (Shift+Tab).
    FocusPrev,
    /// Toggle the active checkbox / multi-select flag (Space).
    Toggle,
    /// Confirm: enter a form from the menu, or open the confirm dialog.
    Confirm,
    /// Append a character to the active text field (or dialog path).
    Char(char),
    /// Delete the last character of the active text field (or dialog path).
    Backspace,
    /// Add a row in a list-based form (`a`).
    AddRow,
    /// Delete the selected row in a list-based form (`d`).
    DeleteRow,
    /// Request generate-now: opens a confirm dialog (`g`). The actual
    /// generation side effect is handled by the event loop, not the reducer.
    RequestGenerate,
    /// Request save-YAML: opens a confirm dialog (`s`).
    RequestSaveYaml,
    /// Back: leave a dialog, or return from a form to the menu (Esc).
    Back,
    /// Quit the application (`q` / Ctrl+C).
    Quit,
    /// Clear the transient status/error slots (e.g. on next keypress).
    ClearStatus,
    /// Clear the currently focused field. In a form this empties the focused
    /// **text** buffer (a no-op on cyclers/toggles/lists/menu — those are reset
    /// via `Ctrl+R`). While the file browser is open it instead clears the
    /// target path field and closes the browser ("clear / none"). Mapped to
    /// `Delete` (and `c` inside the browser) by mod.rs.
    ClearField,
    /// Reset the active screen's *current* form to its default. On the Cert
    /// screen this resets only `cert_list[cert_index]`; sibling entries are
    /// preserved. Other screens reset their single form. Also clears
    /// status/error. (Mapped to `Ctrl+R` by mod.rs.)
    ClearForm,
    /// Wipe the active screen entirely. On the Cert screen this replaces
    /// `cert_list` with a single default entry and resets `cert_index = 0`;
    /// other screens behave identically to [`Message::ClearForm`] (one form
    /// each). Also clears status/error. (Mapped to `Ctrl+Shift+R`.)
    ClearAll,
    /// Open the file-browser overlay for the currently focused path field.
    /// A no-op unless [`App::focused_path_field`] returns a target. Because
    /// reading the directory is impure, the reducer returns an
    /// [`Effect::ReadDir`] so the event loop reads the entries and calls back
    /// [`App::set_browser_entries`]. (Mapped to `Ctrl+O` by mod.rs.)
    OpenBrowser,
    /// Open the file-browser overlay to pick a YAML config file to load into the
    /// active screen's form(s). A no-op on [`Screen::Menu`] (no active config
    /// type). Like [`Message::OpenBrowser`] the directory read is impure, so the
    /// reducer returns an [`Effect::ReadDir`] carrying a
    /// [`BrowsePurpose::LoadConfig`]; the eventual file selection yields an
    /// [`Effect::LoadConfig`]. (Mapped to `Ctrl+L` by mod.rs.)
    LoadConfig,
}

/// The outcome of a confirm dialog being accepted, returned by [`App::update`]
/// so the event loop can run the (impure) generate/save side effect and then
/// report the result back via [`App::set_status`] / [`App::set_error`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Run the generation pipeline for `screen`, writing to `path`.
    Generate {
        /// Which form to generate from.
        screen: Screen,
        /// Output directory.
        path: String,
    },
    /// Write a replayable YAML config for `screen` to `path`.
    SaveYaml {
        /// Which form to serialize.
        screen: Screen,
        /// Output file path.
        path: String,
    },
    /// Read the directory `path` for the file browser and call back
    /// [`App::set_browser_entries`] with the sorted listing (dirs first, `..`
    /// synthesized unless at a filesystem root). Requested when the browser
    /// opens or the user descends/ascends a directory. The `std::fs::read_dir`
    /// I/O and fail-closed error handling live in `mod.rs`; the reducer only
    /// models the request.
    ReadDir {
        /// The directory to list.
        path: std::path::PathBuf,
        /// Why the browser is open; preserved across re-listings so the eventual
        /// file selection knows whether to fill a field or load a config.
        purpose: BrowsePurpose,
    },
    /// Parse the file at `path` as `screen`'s config type and install the
    /// resulting form state on the [`App`]. The impure read (`read_*_config`),
    /// the reverse-mapping into form structs and the install via the pure
    /// `App::load_*` setters all live in `mod.rs::run_effect`; the reducer only
    /// models the request (returned when a file is confirmed in
    /// [`BrowsePurpose::LoadConfig`] mode). On a read/parse error or empty
    /// config the handler routes a message to the error popup.
    LoadConfig {
        /// Which screen's config type the file is parsed as.
        screen: Screen,
        /// The config file to read.
        path: String,
    },
}

impl App {
    /// Pure reducer: applies `msg` to the model and returns an optional
    /// [`Effect`] for the event loop to execute. Performs **no I/O**.
    pub fn update(&mut self, msg: Message) -> Option<Effect> {
        // The error popup takes precedence over every other overlay: a failure
        // is always seen and dismissed before anything else can be touched.
        if self.error_popup.is_some() {
            return self.update_error_popup(msg);
        }

        // Dialog handling takes precedence when one is open.
        if self.dialog.is_some() {
            return self.update_dialog(msg);
        }

        // The file-browser overlay takes precedence over normal form keys while
        // open (like the dialog above): it owns Up/Down/Enter/Backspace/Esc.
        if self.browser.is_some() {
            return self.update_browser(msg);
        }

        match msg {
            Message::Quit => self.should_quit = true,
            Message::ClearStatus => {
                self.status = None;
                self.error = None;
            }
            Message::Back => self.go_back(),
            Message::FocusNext | Message::FocusPrev => self.toggle_focus(),
            Message::Up => self.move_up(),
            Message::Down => self.move_down(),
            Message::Left => self.cycle(false),
            Message::Right => self.cycle(true),
            Message::Toggle => self.toggle_active(),
            Message::Confirm => self.confirm(),
            Message::Char(c) => self.input_char(c),
            Message::Backspace => self.input_backspace(),
            Message::AddRow => self.add_row(),
            Message::DeleteRow => self.delete_row(),
            Message::RequestGenerate => self.open_dialog(ConfirmAction::Generate),
            Message::RequestSaveYaml => self.open_dialog(ConfirmAction::SaveYaml),
            Message::ClearField => {
                // Per-field clear: empty the focused text buffer only. A no-op
                // on cyclers/toggles/lists/menu (reset via Ctrl+R instead).
                if let Some(buf) = self.active_text_field_mut() {
                    buf.clear();
                }
            }
            Message::ClearForm => self.clear_form(),
            Message::ClearAll => self.clear_all(),
            Message::OpenBrowser => return self.open_browser(),
            Message::LoadConfig => return self.open_load_browser(),
        }
        None
    }

    fn update_dialog(&mut self, msg: Message) -> Option<Effect> {
        let Some(Dialog::Confirm { action, path }) = self.dialog.as_mut() else {
            return None;
        };
        match msg {
            Message::Char(c) => {
                path.push(c);
                None
            }
            Message::Backspace => {
                path.pop();
                None
            }
            Message::Back | Message::Quit => {
                self.dialog = None;
                None
            }
            Message::Confirm => {
                let action = *action;
                let path = path.clone();
                self.dialog = None;
                let screen = self.screen;
                Some(match action {
                    ConfirmAction::Generate => Effect::Generate { screen, path },
                    ConfirmAction::SaveYaml => Effect::SaveYaml { screen, path },
                })
            }
            _ => None,
        }
    }

    /// Pure reducer for the error popup, dispatched while
    /// `self.error_popup.is_some()`. Mirrors [`App::update_dialog`]'s precedence:
    /// `Back` (Esc) / `Confirm` (Enter) dismiss it (clearing `error_popup`); all
    /// other messages are ignored so the failure cannot be navigated past
    /// without acknowledging it. Never returns an [`Effect`].
    fn update_error_popup(&mut self, msg: Message) -> Option<Effect> {
        match msg {
            Message::Back | Message::Confirm | Message::Quit => {
                self.error_popup = None;
            }
            _ => {}
        }
        None
    }

    /// Opens the file browser for the focused path field, returning an
    /// [`Effect::ReadDir`] so the event loop reads the initial directory. The
    /// initial directory is the dirname of the field's current value when it
    /// looks like a path, otherwise `.`. A no-op (returns `None`) when no
    /// browseable path field is focused.
    ///
    /// The reducer performs no filesystem I/O: it requests the listing via the
    /// effect and installs `self.browser` once the entries arrive through
    /// [`App::set_browser_entries`].
    fn open_browser(&mut self) -> Option<Effect> {
        let target = self.focused_path_field()?;
        let current = self.path_field_value(target);
        let path = initial_browse_dir(current);
        Some(Effect::ReadDir {
            path,
            purpose: BrowsePurpose::FillField(target),
        })
    }

    /// Opens the file browser to pick a config file to **load** into the active
    /// screen's form(s), returning an [`Effect::ReadDir`] carrying a
    /// [`BrowsePurpose::LoadConfig`] so the event loop reads the initial
    /// directory. A no-op (returns `None`) on [`Screen::Menu`], where no config
    /// type is active.
    ///
    /// The initial directory is [`App::output_dir`] itself (a likely place to
    /// find a saved config). Unlike [`App::open_browser`] — which is seeded from
    /// a file-*path* field and so strips the last component — load mode lists the
    /// directory directly. The reducer performs no filesystem I/O: it only
    /// requests the listing.
    fn open_load_browser(&mut self) -> Option<Effect> {
        if self.screen == Screen::Menu {
            return None;
        }
        let dir = self.output_dir.trim();
        let path = if dir.is_empty() {
            std::path::PathBuf::from(".")
        } else {
            std::path::PathBuf::from(dir)
        };
        Some(Effect::ReadDir {
            path,
            purpose: BrowsePurpose::LoadConfig(self.screen),
        })
    }

    /// Pure reducer for browser navigation, dispatched while
    /// `self.browser.is_some()`. Mirrors [`App::update_dialog`]'s precedence: it
    /// handles the navigation keys and ignores everything else.
    ///
    /// - `Up`/`Down` move the selection, clamped to the loaded entries.
    /// - `Confirm` (Enter) on a directory entry (including `..`) requests an
    ///   [`Effect::ReadDir`] for that directory (the reader re-lists it).
    /// - `Confirm` on a file writes its full path (`current_dir.join(name)`)
    ///   into the target field via [`App::apply_path`] and closes the browser.
    /// - `Backspace` requests the parent directory (no-op at a root).
    /// - `Back` (Esc) / `Quit` closes the browser without changing anything and
    ///   does **not** quit the app.
    /// - All other messages are ignored.
    fn update_browser(&mut self, msg: Message) -> Option<Effect> {
        let browser = self.browser.as_mut()?;
        match msg {
            Message::Up => {
                browser.selected = browser.selected.saturating_sub(1);
                None
            }
            Message::Down => {
                let last = browser.entries.len().saturating_sub(1);
                if browser.selected < last {
                    browser.selected += 1;
                }
                None
            }
            Message::Confirm => {
                let purpose = browser.purpose;
                match browser.entries.get(browser.selected) {
                    Some(entry) if entry.is_dir => {
                        // Descend into the selected directory (or `..`). The
                        // reader resolves `..` against `current_dir` and
                        // re-lists; we just request the join, preserving the
                        // purpose across the re-listing.
                        let path = browser.current_dir.join(&entry.name);
                        Some(Effect::ReadDir { path, purpose })
                    }
                    Some(entry) => {
                        // A file: act on it according to the browser's purpose.
                        let path = browser.current_dir.join(&entry.name);
                        let path = path.to_string_lossy().into_owned();
                        self.browser = None;
                        match purpose {
                            // Fill mode: write the path into the target field.
                            BrowsePurpose::FillField(target) => {
                                self.apply_path(target, path);
                                None
                            }
                            // Load mode: request the (impure) config read.
                            BrowsePurpose::LoadConfig(screen) => {
                                Some(Effect::LoadConfig { screen, path })
                            }
                        }
                    }
                    None => None,
                }
            }
            Message::Backspace => {
                let purpose = browser.purpose;
                // Go up one level; no-op at a filesystem root.
                let parent = browser.current_dir.parent()?.to_path_buf();
                Some(Effect::ReadDir {
                    path: parent,
                    purpose,
                })
            }
            Message::Back | Message::Quit => {
                self.browser = None;
                None
            }
            // "Clear / none": pick no file. In fill mode this empties the target
            // path field and closes the browser. In load mode there is no target
            // to clear, so it simply closes. `c` is the letter shortcut;
            // `ClearField` is the Delete mapping (both routed here by mod.rs
            // while browsing).
            Message::ClearField | Message::Char('c') => {
                let purpose = browser.purpose;
                self.browser = None;
                if let BrowsePurpose::FillField(target) = purpose {
                    self.apply_path(target, String::new());
                }
                None
            }
            _ => None,
        }
    }

    /// Installs (or updates) the browser overlay with a freshly read directory
    /// listing and resets the selection to the top. Called by the event loop
    /// after executing an [`Effect::ReadDir`]; the reducer itself never reads
    /// the filesystem.
    pub fn set_browser_entries(
        &mut self,
        dir: std::path::PathBuf,
        entries: Vec<FileEntry>,
        purpose: BrowsePurpose,
    ) {
        self.browser = Some(FileBrowser {
            current_dir: dir,
            entries,
            selected: 0,
            purpose,
        });
    }

    /// Writes a chosen `path` into the text buffer identified by `target`,
    /// using the same field-index routing as the `*_text_field` helpers:
    ///
    /// - **Cert**: 12 `signer.cert_pem_file`, 13 `signer.private_key_pem_file`.
    /// - **Csr**: 9 `csr_pem_file`, 13 `signer.cert_pem_file`,
    ///   14 `signer.private_key_pem_file`.
    /// - **Crl**: 1 `signer.cert_pem_file`, 2 `signer.private_key_pem_file`.
    /// - **Cms**: 1 `data_file`, 2 `recipient`, 3 `signer.cert_pem_file`,
    ///   4 `signer.private_key_pem_file`.
    ///
    /// Unknown `(screen, field)` pairs are ignored.
    fn apply_path(&mut self, target: BrowseTarget, path: String) {
        let buf = match target.screen {
            Screen::Cert => {
                let cert = self.cert_mut();
                match target.field {
                    12 => Some(&mut cert.signer.cert_pem_file),
                    13 => Some(&mut cert.signer.private_key_pem_file),
                    _ => None,
                }
            }
            Screen::Csr => {
                let csr = self.csr_mut();
                match target.field {
                    9 => Some(&mut csr.csr_pem_file),
                    13 => Some(&mut csr.signer.cert_pem_file),
                    14 => Some(&mut csr.signer.private_key_pem_file),
                    _ => None,
                }
            }
            Screen::Crl => match target.field {
                1 => Some(&mut self.crl.signer.cert_pem_file),
                2 => Some(&mut self.crl.signer.private_key_pem_file),
                _ => None,
            },
            Screen::Cms => {
                let cms = self.cms_mut();
                match target.field {
                    1 => Some(&mut cms.data_file),
                    2 => Some(&mut cms.recipient),
                    3 => Some(&mut cms.signer.cert_pem_file),
                    4 => Some(&mut cms.signer.private_key_pem_file),
                    _ => None,
                }
            }
            Screen::Menu => None,
        };
        if let Some(buf) = buf {
            *buf = path;
        }
    }

    /// The current text value of the path field identified by `target`, used to
    /// seed the browser's initial directory. Returns an empty string for
    /// unknown pairs.
    fn path_field_value(&self, target: BrowseTarget) -> &str {
        match target.screen {
            Screen::Cert => {
                let cert = self.cert();
                match target.field {
                    12 => &cert.signer.cert_pem_file,
                    13 => &cert.signer.private_key_pem_file,
                    _ => "",
                }
            }
            Screen::Csr => {
                let csr = self.csr();
                match target.field {
                    9 => &csr.csr_pem_file,
                    13 => &csr.signer.cert_pem_file,
                    14 => &csr.signer.private_key_pem_file,
                    _ => "",
                }
            }
            Screen::Crl => match target.field {
                1 => &self.crl.signer.cert_pem_file,
                2 => &self.crl.signer.private_key_pem_file,
                _ => "",
            },
            Screen::Cms => {
                let cms = self.cms();
                match target.field {
                    1 => &cms.data_file,
                    2 => &cms.recipient,
                    3 => &cms.signer.cert_pem_file,
                    4 => &cms.signer.private_key_pem_file,
                    _ => "",
                }
            }
            Screen::Menu => "",
        }
    }

    fn open_dialog(&mut self, action: ConfirmAction) {
        if self.screen == Screen::Menu {
            return;
        }
        self.dialog = Some(Dialog::Confirm {
            action,
            path: self.output_dir.clone(),
        });
    }

    fn go_back(&mut self) {
        if self.screen == Screen::Menu {
            self.should_quit = true;
        } else {
            self.screen = Screen::Menu;
            self.focus = Focus::Menu;
        }
    }

    fn toggle_focus(&mut self) {
        if self.screen == Screen::Menu {
            return;
        }
        // Entry-bearing screens (Cert / Csr / Cms) have a three-way cycle
        // (Menu → Entries → Form) so the multi-entry sub-list is reachable;
        // other screens (Crl) toggle Menu ↔ Form.
        self.focus = if Self::screen_has_entries(self.screen) {
            match self.focus {
                Focus::Menu => Focus::Entries,
                Focus::Entries => Focus::Form,
                Focus::Form => Focus::Menu,
            }
        } else {
            match self.focus {
                Focus::Entries | Focus::Menu => Focus::Form,
                Focus::Form => Focus::Menu,
            }
        };
    }

    fn move_up(&mut self) {
        if self.focus == Focus::Menu {
            self.menu_index = self.menu_index.saturating_sub(1);
            return;
        }
        if self.focus == Focus::Entries {
            // Move the active screen's entry index up (clamped at 0).
            match self.screen {
                Screen::Cert => self.cert_index = self.cert_index.saturating_sub(1),
                Screen::Csr => self.csr_index = self.csr_index.saturating_sub(1),
                Screen::Cms => self.cms_index = self.cms_index.saturating_sub(1),
                _ => {}
            }
            return;
        }
        // CRL revoked-table navigation (R3): while a revoked row is selected,
        // focus is "in the table" (encoded by `selected_row.is_some()`, with
        // `field` parked at the last fixed field 2). Up retreats the selected
        // row; Up from row 0 leaves the table back into the fixed fields.
        if self.screen == Screen::Crl
            && self.focus == Focus::Form
            && let Some(idx) = self.crl.selected_row
        {
            if idx == 0 {
                self.crl.selected_row = None;
                self.crl.field = 2;
            } else {
                self.crl.selected_row = Some(idx - 1);
            }
            return;
        }
        if let Some(field) = self.active_field_mut() {
            *field = field.saturating_sub(1);
        }
    }

    fn move_down(&mut self) {
        if self.focus == Focus::Menu {
            let last = MENU_ITEMS.len().saturating_sub(1);
            if self.menu_index < last {
                self.menu_index += 1;
            }
            return;
        }
        if self.focus == Focus::Entries {
            // Move the active screen's entry index down within its list length.
            match self.screen {
                Screen::Cert => {
                    let last = self.cert_list.len().saturating_sub(1);
                    if self.cert_index < last {
                        self.cert_index += 1;
                    }
                }
                Screen::Csr => {
                    let last = self.csr_list.len().saturating_sub(1);
                    if self.csr_index < last {
                        self.csr_index += 1;
                    }
                }
                Screen::Cms => {
                    let last = self.cms_list.len().saturating_sub(1);
                    if self.cms_index < last {
                        self.cms_index += 1;
                    }
                }
                _ => {}
            }
            return;
        }
        // CRL revoked-table navigation (R3). The 3 fixed text fields are
        // `field` 0..=2; the revoked rows live "below" field 2 and are
        // addressed by `selected_row` (NOT counted in `active_field_count`).
        // Encoding: a row is focused iff `selected_row.is_some()`; `field` is
        // parked at 2 while in the table so the fixed-field state is preserved
        // for when the user steps back up. Down past field 2 enters the table
        // at row 0; subsequent Downs advance `selected_row` to the last row.
        if self.screen == Screen::Crl && self.focus == Focus::Form {
            let row_count = self.crl.revoked.len();
            match self.crl.selected_row {
                None if self.crl.field == 2 && row_count > 0 => {
                    self.crl.selected_row = Some(0);
                    return;
                }
                Some(idx) => {
                    if idx + 1 < row_count {
                        self.crl.selected_row = Some(idx + 1);
                    }
                    return;
                }
                None => {}
            }
        }
        let max = self.active_field_count().saturating_sub(1);
        if let Some(field) = self.active_field_mut()
            && *field < max
        {
            *field += 1;
        }
    }

    fn cycle(&mut self, forward: bool) {
        // Cyclers are form-specific; only the enum fields respond. For
        // simplicity the reducer cycles the form's primary enum fields based
        // on the focused field index. Forms render this consistently. Cycling
        // never applies to the entry sub-list.
        if self.focus == Focus::Entries {
            return;
        }
        match self.screen {
            Screen::Cert => cycle_cert(self.cert_mut(), forward),
            Screen::Csr => cycle_csr(self.csr_mut(), forward),
            Screen::Crl => cycle_crl(&mut self.crl, forward),
            Screen::Cms => {}
            Screen::Menu => {}
        }
    }

    fn toggle_active(&mut self) {
        if self.focus == Focus::Entries {
            return;
        }
        match self.screen {
            Screen::Cert => toggle_cert(self.cert_mut()),
            Screen::Csr => toggle_csr(self.csr_mut()),
            Screen::Cms => {
                let cms = self.cms_mut();
                cms.detached = !cms.detached;
            }
            Screen::Crl | Screen::Menu => {}
        }
    }

    fn confirm(&mut self) {
        if self.focus == Focus::Menu && self.screen == Screen::Menu {
            self.screen = self.menu_screen();
            self.focus = Focus::Form;
        } else if self.focus == Focus::Entries {
            // From the Cert entry sub-list, Enter dives into the form to edit
            // the selected entry rather than opening the generate dialog.
            self.focus = Focus::Form;
        } else if self.screen != Screen::Menu {
            // Within a form, Enter opens the confirm dialog (Generate default).
            self.open_dialog(ConfirmAction::Generate);
        }
    }

    fn input_char(&mut self, c: char) {
        if let Some(buf) = self.active_text_field_mut() {
            buf.push(c);
        }
    }

    fn input_backspace(&mut self) {
        if let Some(buf) = self.active_text_field_mut() {
            buf.pop();
        }
    }

    fn add_row(&mut self) {
        // A compact per-screen match is used here (rather than the
        // `screen_has_entries` predicate) because each arm selects a *different*
        // list/index to mutate; the CRL arm is a separate revoked-row concern.
        match self.screen {
            // Cert/Csr/Cms: append a new entry to the active list and select it.
            // The new entry becomes the one being edited.
            Screen::Cert => {
                self.cert_list.push(CertForm::default());
                self.cert_index = self.cert_list.len().saturating_sub(1);
            }
            Screen::Csr => {
                self.csr_list.push(CsrForm::default());
                self.csr_index = self.csr_list.len().saturating_sub(1);
            }
            Screen::Cms => {
                self.cms_list.push(CmsForm::default());
                self.cms_index = self.cms_list.len().saturating_sub(1);
            }
            Screen::Crl => {
                self.crl.revoked.push(RevokedRow::default());
                self.crl.selected_row = Some(self.crl.revoked.len().saturating_sub(1));
            }
            _ => {}
        }
    }

    fn delete_row(&mut self) {
        // Compact per-screen match: each entry-bearing screen removes from its
        // own list/index, never emptying it (mirrors the `len() > 1` guard); the
        // CRL arm is the separate revoked-row concern.
        match self.screen {
            // Cert: remove the selected entry, but never empty the list.
            Screen::Cert => {
                if self.cert_list.len() > 1 {
                    let idx = self.active_cert_index();
                    self.cert_list.remove(idx);
                    self.cert_index = idx.min(self.cert_list.len().saturating_sub(1));
                }
            }
            Screen::Csr => {
                if self.csr_list.len() > 1 {
                    let idx = self.active_csr_index();
                    self.csr_list.remove(idx);
                    self.csr_index = idx.min(self.csr_list.len().saturating_sub(1));
                }
            }
            Screen::Cms => {
                if self.cms_list.len() > 1 {
                    let idx = self.active_cms_index();
                    self.cms_list.remove(idx);
                    self.cms_index = idx.min(self.cms_list.len().saturating_sub(1));
                }
            }
            Screen::Crl => {
                if let Some(idx) = self.crl.selected_row
                    && idx < self.crl.revoked.len()
                {
                    self.crl.revoked.remove(idx);
                    self.crl.selected_row = if self.crl.revoked.is_empty() {
                        None
                    } else {
                        Some(idx.min(self.crl.revoked.len() - 1))
                    };
                }
            }
            _ => {}
        }
    }

    /// Resets the active screen's *current* form to its default and clears the
    /// status/error slots. On the Cert screen only the selected entry
    /// (`cert_list[cert_index]`) is reset; sibling entries are preserved.
    fn clear_form(&mut self) {
        match self.screen {
            Screen::Cert => *self.cert_mut() = CertForm::default(),
            Screen::Csr => *self.csr_mut() = CsrForm::default(),
            Screen::Crl => self.crl = CrlForm::default(),
            Screen::Cms => *self.cms_mut() = CmsForm::default(),
            Screen::Menu => {}
        }
        self.status = None;
        self.error = None;
    }

    /// Wipes the active screen. On an entry-bearing screen (Cert / Csr / Cms)
    /// this replaces the whole list with a single default entry and resets the
    /// index to `0`; other screens are equivalent to [`App::clear_form`].
    fn clear_all(&mut self) {
        match self.screen {
            Screen::Cert => {
                self.cert_list = vec![CertForm::default()];
                self.cert_index = 0;
            }
            Screen::Csr => {
                self.csr_list = vec![CsrForm::default()];
                self.csr_index = 0;
            }
            Screen::Cms => {
                self.cms_list = vec![CmsForm::default()];
                self.cms_index = 0;
            }
            // Crl / Menu have no entry list: reset the single form.
            _ => {
                self.clear_form();
                return;
            }
        }
        self.status = None;
        self.error = None;
    }

    /// Whether the currently focused form field is a free-text buffer (as
    /// opposed to a cycler/toggle/list field). Used by the input mapper to
    /// decide whether printable keys are typed characters or shortcuts.
    #[must_use]
    pub fn focused_field_is_text(&self) -> bool {
        self.active_text_field().is_some()
    }

    /// Shared (read-only) view of the focused field's text buffer, if it is a
    /// free-text field. The immutable twin of [`Self::active_text_field_mut`] —
    /// classification only depends on `screen`/`focus`/the field index, so this
    /// avoids cloning the whole `App` just to answer "is the focus a text field"
    /// (see [`Self::focused_field_is_text`], called on every key event).
    fn active_text_field(&self) -> Option<&String> {
        // The entry sub-list is not a text field.
        if self.focus == Focus::Entries {
            return None;
        }
        match self.screen {
            Screen::Cert => cert_text_field_ref(self.cert()),
            Screen::Csr => csr_text_field_ref(self.csr()),
            // While a revoked row is selected, focus is in the table (not on a
            // fixed text field), so typing/clear must not touch field 0..=2.
            Screen::Crl if self.crl.selected_row.is_some() => None,
            Screen::Crl => crl_text_field_ref(&self.crl),
            Screen::Cms => cms_text_field_ref(self.cms()),
            Screen::Menu => None,
        }
    }

    /// Mutable access to the text buffer for the currently focused field, if
    /// the focused field is a free-text one. Enum/toggle/list fields return
    /// `None` (they are driven by cycle/toggle/add/delete instead).
    fn active_text_field_mut(&mut self) -> Option<&mut String> {
        // The entry sub-list is not a text field.
        if self.focus == Focus::Entries {
            return None;
        }
        match self.screen {
            Screen::Cert => cert_text_field(self.cert_mut()),
            Screen::Csr => csr_text_field(self.csr_mut()),
            // While a revoked row is selected, focus is in the table (not on a
            // fixed text field), so typing/clear must not touch field 0..=2.
            Screen::Crl if self.crl.selected_row.is_some() => None,
            Screen::Crl => crl_text_field(&mut self.crl),
            Screen::Cms => cms_text_field(self.cms_mut()),
            Screen::Menu => None,
        }
    }

    /// Records a plain informational status line (muted style). Called by the
    /// event loop for transient hints. Clears any error.
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status = Some(msg.into());
        self.status_kind = StatusKind::Info;
        self.error = None;
    }

    /// Records a success status line, rendered with a `✓` marker and the
    /// success theme style. Called by the event loop after a completed
    /// generate/save effect. Clears any error.
    pub fn set_success(&mut self, msg: impl Into<String>) {
        self.status = Some(msg.into());
        self.status_kind = StatusKind::Success;
        self.error = None;
    }

    /// The styling kind for the current [`App::status`] line, read by the
    /// footer renderer to choose between the plain and success styles.
    #[must_use]
    pub fn status_kind(&self) -> StatusKind {
        self.status_kind
    }

    /// Records an error line. Called by the event loop after a failed
    /// [`Effect`].
    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.error = Some(msg.into());
        self.status = None;
    }

    /// Records a full error message in the dismissable error popup (a centered,
    /// word-wrapped modal). Called by the event loop when an [`Effect::Generate`]
    /// or [`Effect::SaveYaml`] fails, so long cert-helper/cms errors are shown in
    /// full rather than truncated into the footer. Clears any transient
    /// [`App::status`]; the popup is dismissed with `Esc`/`Enter` (see
    /// [`App::update`]). The short footer [`App::set_error`] slot is unaffected.
    pub fn set_error_popup(&mut self, msg: impl Into<String>) {
        self.error_popup = Some(msg.into());
        self.status = None;
    }

    /// Installs a freshly loaded set of certificate entries, replacing the whole
    /// `cert_list`. Called by the [`Effect::LoadConfig`] handler in `mod.rs`
    /// after reverse-mapping a certificate config into form structs. Resets
    /// `cert_index` to `0`, switches to the Cert screen and focuses the form so
    /// the user lands on the first loaded entry.
    ///
    /// The caller guarantees `forms` is non-empty (an empty config is reported
    /// as an error before this is called); the `cert_list` never-empty invariant
    /// is preserved by replacing only with a non-empty vector. Defensive: a stray
    /// empty vector is replaced with a single default entry.
    pub fn load_cert_list(&mut self, forms: Vec<CertForm>) {
        self.cert_list = if forms.is_empty() {
            vec![CertForm::default()]
        } else {
            forms
        };
        self.cert_index = 0;
        self.screen = Screen::Cert;
        self.focus = Focus::Form;
    }

    /// Installs a freshly loaded set of CSR entries, replacing the whole
    /// `csr_list`. Called by the [`Effect::LoadConfig`] handler in `mod.rs`
    /// after reverse-mapping a CSR config (both generate-mode `csrs` and
    /// sign-mode `to_sign`/`signing_requests`) into form structs. Resets
    /// `csr_index` to `0`, switches to the CSR screen and focuses the form so
    /// the user lands on the first loaded entry.
    ///
    /// Mirrors [`App::load_cert_list`]: the `csr_list` never-empty invariant is
    /// preserved by replacing only with a non-empty vector. Defensive: a stray
    /// empty vector is replaced with a single default entry.
    pub fn load_csr_list(&mut self, forms: Vec<CsrForm>) {
        self.csr_list = if forms.is_empty() {
            vec![CsrForm::default()]
        } else {
            forms
        };
        self.csr_index = 0;
        self.screen = Screen::Csr;
        self.focus = Focus::Form;
    }

    /// Installs a freshly loaded CRL form, replacing `self.crl`. Switches to the
    /// CRL screen and focuses the form. The loaded form's `selected_row` is
    /// clamped into range (or cleared when there are no revoked rows). Called by
    /// the [`Effect::LoadConfig`] handler in `mod.rs`.
    pub fn load_crl(&mut self, form: CrlForm) {
        self.crl = form;
        self.crl.selected_row = match self.crl.selected_row {
            Some(idx) if !self.crl.revoked.is_empty() => Some(idx.min(self.crl.revoked.len() - 1)),
            _ => None,
        };
        self.screen = Screen::Crl;
        self.focus = Focus::Form;
    }

    /// Installs a freshly loaded set of CMS entries, replacing the whole
    /// `cms_list`. Called by the [`Effect::LoadConfig`] handler in `mod.rs`
    /// after reverse-mapping a CMS config into form structs. Resets `cms_index`
    /// to `0`, switches to the CMS screen and focuses the form so the user lands
    /// on the first loaded entry.
    ///
    /// Mirrors [`App::load_cert_list`]: the `cms_list` never-empty invariant is
    /// preserved by replacing only with a non-empty vector. Defensive: a stray
    /// empty vector is replaced with a single default entry.
    pub fn load_cms_list(&mut self, forms: Vec<CmsForm>) {
        self.cms_list = if forms.is_empty() {
            vec![CmsForm::default()]
        } else {
            forms
        };
        self.cms_index = 0;
        self.screen = Screen::Cms;
        self.focus = Focus::Form;
    }

    /// Returns a [`BrowseTarget`] when the currently focused field is a
    /// browseable file-path field, or `None` otherwise.
    ///
    /// Path fields, by screen and field index (matching the `*_text_field`
    /// routing):
    /// - **Cert**: 12 `signer.cert_pem_file`, 13 `signer.private_key_pem_file`.
    /// - **Csr**: 9 `csr_pem_file`, 13 `signer.cert_pem_file`,
    ///   14 `signer.private_key_pem_file` (the sign-mode signer paths, mirroring
    ///   Cert's 12/13).
    /// - **Crl**: 1 `signer.cert_pem_file`, 2 `signer.private_key_pem_file`.
    /// - **Cms**: 1 `data_file`, 2 `recipient`, 3 `signer.cert_pem_file`,
    ///   4 `signer.private_key_pem_file`.
    ///
    /// developer-03 consumes this to open the file browser via `Ctrl+O`.
    #[must_use]
    pub fn focused_path_field(&self) -> Option<BrowseTarget> {
        if self.focus != Focus::Form {
            return None;
        }
        let (field, is_path) = match self.screen {
            Screen::Cert => {
                let f = self.cert().field;
                (f, matches!(f, 12 | 13))
            }
            // Csr path fields: 9 (`csr_pem_file`) plus the sign-mode signer
            // paths 13 (`signer.cert_pem_file`) and 14
            // (`signer.private_key_pem_file`), mirroring Cert's 12/13.
            Screen::Csr => (self.csr().field, matches!(self.csr().field, 9 | 13 | 14)),
            // While a revoked row is selected, focus is in the table, not on a
            // fixed path field — no browseable path is focused.
            Screen::Crl if self.crl.selected_row.is_some() => return None,
            Screen::Crl => (self.crl.field, matches!(self.crl.field, 1 | 2)),
            Screen::Cms => (self.cms().field, matches!(self.cms().field, 1..=4)),
            Screen::Menu => return None,
        };
        if !is_path {
            return None;
        }
        Some(BrowseTarget {
            screen: self.screen,
            field,
        })
    }

    /// Whether the currently focused field is a browseable path field. A thin
    /// boolean wrapper over [`App::focused_path_field`] for the input mapper.
    #[must_use]
    pub fn focused_field_is_path(&self) -> bool {
        self.focused_path_field().is_some()
    }
}

// --- field cyclers / toggles / text routing -------------------------------
//
// These map the focused-field index to the right enum/toggle/text buffer.
// The indices match the render order documented in the forms module.

/// Picks the directory to open the file browser in, given the path field's
/// current text value. If the value looks like a path with a parent directory,
/// that parent is used; if it is a bare name (no parent) the current directory
/// `.` is used; an empty value also yields `.`.
fn initial_browse_dir(current: &str) -> std::path::PathBuf {
    let trimmed = current.trim();
    if trimmed.is_empty() {
        return std::path::PathBuf::from(".");
    }
    let path = std::path::Path::new(trimmed);
    match path.parent() {
        // `Path::parent` returns Some("") for a bare file name; treat that as
        // the current directory.
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    }
}

fn cycle_index(idx: &mut usize, len: usize, forward: bool) {
    if len == 0 {
        return;
    }
    *idx = if forward {
        (*idx + 1) % len
    } else {
        (*idx + len - 1) % len
    };
}

fn cycle_cert(form: &mut CertForm, forward: bool) {
    match form.field {
        4 => cycle_index(&mut form.key_type, KEY_TYPE_OPTIONS.len(), forward),
        5 => cycle_index(&mut form.hash_alg, HASH_ALG_OPTIONS.len(), forward),
        // ←→ move the usage highlight; toggling is done with Space.
        6 => cycle_index(&mut form.usage_cursor, USAGE_OPTIONS.len(), forward),
        // key length (RSA only; ignored at conversion for other key types).
        9 => cycle_index(&mut form.key_length, RSA_KEY_LENGTH_OPTIONS.len(), forward),
        _ => {}
    }
}

fn cycle_csr(form: &mut CsrForm, forward: bool) {
    match form.field {
        4 => cycle_index(&mut form.key_type, KEY_TYPE_OPTIONS.len(), forward),
        5 => cycle_index(&mut form.hash_alg, HASH_ALG_OPTIONS.len(), forward),
        // ←→ move the usage highlight; toggling is done with Space.
        6 => cycle_index(&mut form.usage_cursor, USAGE_OPTIONS.len(), forward),
        // key length (RSA only).
        12 => cycle_index(&mut form.key_length, RSA_KEY_LENGTH_OPTIONS.len(), forward),
        _ => {}
    }
}

fn cycle_crl(form: &mut CrlForm, forward: bool) {
    if let Some(idx) = form.selected_row
        && let Some(row) = form.revoked.get_mut(idx)
    {
        cycle_index(&mut row.reason, REASON_OPTIONS.len(), forward);
    }
}

fn toggle_cert(form: &mut CertForm) {
    match form.field {
        // Multi-select usage flags occupy field index 6: Space toggles only the
        // option under the cursor (←→ moves the cursor), so any subset is
        // reachable and an option can be stepped over without selecting it.
        6 => {
            if let Some(slot) = form.usage.get_mut(form.usage_cursor) {
                *slot = !*slot;
            }
        }
        // CA toggle occupies field index 8.
        8 => form.ca = !form.ca,
        _ => {}
    }
}

fn toggle_csr(form: &mut CsrForm) {
    match form.field {
        // Usage multi-select: toggle only the cursor option (see toggle_cert).
        6 => {
            if let Some(slot) = form.usage.get_mut(form.usage_cursor) {
                *slot = !*slot;
            }
        }
        // sign-mode toggle.
        7 => form.sign_mode = !form.sign_mode,
        // CA toggle (sign mode).
        11 => form.ca = !form.ca,
        _ => {}
    }
}

/// Maps the Cert form's focused-field index to its text buffer. The full
/// field-index map (the render order ui-designer-03 mirrors) is:
///
/// | idx | field                          | kind        |
/// |-----|--------------------------------|-------------|
/// | 0   | `id`                           | text        |
/// | 1   | `common_name`                  | text        |
/// | 2   | `country`                      | text        |
/// | 3   | `organization`                 | text        |
/// | 4   | `key_type`                     | cycler      |
/// | 5   | `hash_alg`                     | cycler      |
/// | 6   | `usage`                        | multi-select|
/// | 7   | `altnames`                     | text        |
/// | 8   | `ca`                           | toggle      |
/// | 9   | `key_length`                   | cycler (RSA)|
/// | 10  | `valid_to`                     | text        |
/// | 11  | `parent`                       | text        |
/// | 12  | `signer.cert_pem_file`         | text / path |
/// | 13  | `signer.private_key_pem_file`  | text / path |
fn cert_text_field(form: &mut CertForm) -> Option<&mut String> {
    Some(match form.field {
        0 => &mut form.id,
        1 => &mut form.common_name,
        2 => &mut form.country,
        3 => &mut form.organization,
        // 4 key_type (cycler), 5 hash_alg (cycler), 6 usage (toggle)
        7 => &mut form.altnames,
        // 8 ca (toggle), 9 key_length (cycler)
        10 => &mut form.valid_to,
        11 => &mut form.parent,
        12 => &mut form.signer.cert_pem_file,
        13 => &mut form.signer.private_key_pem_file,
        _ => return None,
    })
}

fn csr_text_field(form: &mut CsrForm) -> Option<&mut String> {
    Some(match form.field {
        0 => &mut form.id,
        1 => &mut form.common_name,
        2 => &mut form.country,
        3 => &mut form.organization,
        // 4 key_type, 5 hash_alg, 6 usage, 7 sign_mode
        8 => &mut form.altnames,
        9 => &mut form.csr_pem_file,
        10 => &mut form.valid_to,
        // 11 ca toggle, 12 key_length (cycler)
        // 13/14: sign-mode signer paths, mirroring Cert's 12/13.
        13 => &mut form.signer.cert_pem_file,
        14 => &mut form.signer.private_key_pem_file,
        _ => return None,
    })
}

fn crl_text_field(form: &mut CrlForm) -> Option<&mut String> {
    Some(match form.field {
        0 => &mut form.crl_file,
        1 => &mut form.signer.cert_pem_file,
        2 => &mut form.signer.private_key_pem_file,
        _ => return None,
    })
}

fn cms_text_field(form: &mut CmsForm) -> Option<&mut String> {
    Some(match form.field {
        0 => &mut form.id,
        1 => &mut form.data_file,
        2 => &mut form.recipient,
        3 => &mut form.signer.cert_pem_file,
        4 => &mut form.signer.private_key_pem_file,
        _ => return None,
    })
}

// Read-only twins of the `*_text_field` routers above. They mirror the same
// field-index -> buffer mapping but borrow shared, so `active_text_field`
// (hence `focused_field_is_text`, called per key event) needs no `App` clone.
// Keep each in lock-step with its `_mut` counterpart.

fn cert_text_field_ref(form: &CertForm) -> Option<&String> {
    Some(match form.field {
        0 => &form.id,
        1 => &form.common_name,
        2 => &form.country,
        3 => &form.organization,
        7 => &form.altnames,
        10 => &form.valid_to,
        11 => &form.parent,
        12 => &form.signer.cert_pem_file,
        13 => &form.signer.private_key_pem_file,
        _ => return None,
    })
}

fn csr_text_field_ref(form: &CsrForm) -> Option<&String> {
    Some(match form.field {
        0 => &form.id,
        1 => &form.common_name,
        2 => &form.country,
        3 => &form.organization,
        8 => &form.altnames,
        9 => &form.csr_pem_file,
        10 => &form.valid_to,
        13 => &form.signer.cert_pem_file,
        14 => &form.signer.private_key_pem_file,
        _ => return None,
    })
}

fn crl_text_field_ref(form: &CrlForm) -> Option<&String> {
    Some(match form.field {
        0 => &form.crl_file,
        1 => &form.signer.cert_pem_file,
        2 => &form.signer.private_key_pem_file,
        _ => return None,
    })
}

fn cms_text_field_ref(form: &CmsForm) -> Option<&String> {
    Some(match form.field {
        0 => &form.id,
        1 => &form.data_file,
        2 => &form.recipient,
        3 => &form.signer.cert_pem_file,
        4 => &form.signer.private_key_pem_file,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_app() -> App {
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Cert;
        app.focus = Focus::Form;
        app
    }

    #[test]
    fn menu_index_maps_to_screen() {
        let mut app = App::new("./out".to_string());
        app.menu_index = 0;
        assert_eq!(app.menu_screen(), Screen::Cert);
        app.menu_index = 1;
        assert_eq!(app.menu_screen(), Screen::Csr);
        app.menu_index = 2;
        assert_eq!(app.menu_screen(), Screen::Crl);
        app.menu_index = 3;
        assert_eq!(app.menu_screen(), Screen::Cms);
    }

    #[test]
    fn confirm_from_menu_enters_form() {
        let mut app = App::new("./out".to_string());
        app.menu_index = 1;
        let effect = app.update(Message::Confirm);
        assert!(effect.is_none());
        assert_eq!(app.screen, Screen::Csr);
        assert_eq!(app.focus, Focus::Form);
    }

    #[test]
    fn back_from_form_returns_to_menu_without_quitting() {
        let mut app = cert_app();
        app.update(Message::Back);
        assert_eq!(app.screen, Screen::Menu);
        assert!(!app.should_quit);
    }

    #[test]
    fn back_from_menu_quits() {
        let mut app = App::new("./out".to_string());
        app.update(Message::Back);
        assert!(app.should_quit);
    }

    #[test]
    fn down_clamps_at_last_menu_item() {
        let mut app = App::new("./out".to_string());
        for _ in 0..10 {
            app.update(Message::Down);
        }
        assert_eq!(app.menu_index, MENU_ITEMS.len() - 1);
    }

    #[test]
    fn typing_appends_to_focused_text_field() {
        let mut app = cert_app();
        app.cert_mut().field = 0;
        app.update(Message::Char('a'));
        app.update(Message::Char('b'));
        assert_eq!(app.cert_mut().id, "ab");
        app.update(Message::Backspace);
        assert_eq!(app.cert_mut().id, "a");
    }

    #[test]
    fn cycling_key_type_wraps_and_reuses_config_enum() {
        let mut app = cert_app();
        app.cert_mut().field = 4;
        let start = app.cert_mut().key_type;
        app.update(Message::Right);
        assert_ne!(app.cert_mut().key_type, start);
        // Wrap back around to the start.
        for _ in 1..KEY_TYPE_OPTIONS.len() {
            app.update(Message::Right);
        }
        assert_eq!(app.cert_mut().key_type, start);
        // Option set is the canonical config enum, not a redefined list.
        assert_eq!(KEY_TYPE_OPTIONS[0], KeyType::RSA);
    }

    #[test]
    fn ca_toggle_flips_boolean() {
        let mut app = cert_app();
        app.cert_mut().field = 8;
        assert!(!app.cert_mut().ca);
        app.update(Message::Toggle);
        assert!(app.cert_mut().ca);
    }

    #[test]
    fn key_length_field_cycles_through_rsa_options() {
        let mut app = cert_app();
        app.cert_mut().field = 9; // key length selector
        assert_eq!(app.cert_mut().key_length, 0);
        app.update(Message::Right);
        assert_eq!(app.cert_mut().key_length, 1 % RSA_KEY_LENGTH_OPTIONS.len());
        // Wrap back to the first option.
        for _ in 1..RSA_KEY_LENGTH_OPTIONS.len() {
            app.update(Message::Right);
        }
        assert_eq!(app.cert_mut().key_length, 0);
        // It is a selector, not a text field — typing must not edit it.
        app.update(Message::Char('9'));
        assert_eq!(app.cert_mut().key_length, 0);
    }

    #[test]
    fn usage_left_right_moves_cursor_without_selecting() {
        let mut app = cert_app();
        app.cert_mut().field = 6; // usage multi-select
        app.update(Message::Right);
        app.update(Message::Right);
        assert_eq!(app.cert_mut().usage_cursor, 2);
        // Navigating must NOT toggle any option.
        assert!(
            app.cert_mut().usage.iter().all(|&b| !b),
            "moving the cursor must not select anything"
        );
    }

    #[test]
    fn usage_cursor_wraps_backward_from_first() {
        let mut app = cert_app();
        app.cert_mut().field = 6;
        app.update(Message::Left);
        assert_eq!(app.cert_mut().usage_cursor, USAGE_OPTIONS.len() - 1);
    }

    #[test]
    fn usage_space_toggles_only_the_cursor_option() {
        let mut app = cert_app();
        app.cert_mut().field = 6;
        app.update(Message::Right); // cursor -> 1 (clientauth)
        app.update(Message::Toggle); // select only option 1
        assert!(app.cert_mut().usage[1], "cursor option is selected");
        assert!(!app.cert_mut().usage[0], "earlier option is untouched");
        assert!(
            app.cert_mut().usage[2..].iter().all(|&b| !b),
            "later options are untouched"
        );
        app.update(Message::Toggle); // toggling again clears it
        assert!(!app.cert_mut().usage[1]);
    }

    #[test]
    fn usage_can_select_a_later_option_while_skipping_earlier_ones() {
        let mut app = cert_app();
        app.cert_mut().field = 6;
        // Step over the first three options without selecting them.
        for _ in 0..3 {
            app.update(Message::Right);
        }
        app.update(Message::Toggle);
        assert!(
            app.cert_mut().usage[3],
            "the stepped-to option is selectable"
        );
        assert!(
            app.cert_mut().usage[..3].iter().all(|&b| !b),
            "skipped options stay unselected"
        );
    }

    #[test]
    fn csr_usage_toggles_only_the_cursor_option() {
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Csr;
        app.focus = Focus::Form;
        app.csr_mut().field = 6;
        app.update(Message::Right); // cursor -> 1
        app.update(Message::Toggle);
        assert!(app.csr().usage[1]);
        assert!(!app.csr().usage[0]);
    }

    #[test]
    fn add_and_delete_revoked_rows() {
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Crl;
        app.focus = Focus::Form;
        app.update(Message::AddRow);
        app.update(Message::AddRow);
        assert_eq!(app.crl.revoked.len(), 2);
        app.crl.selected_row = Some(0);
        app.update(Message::DeleteRow);
        assert_eq!(app.crl.revoked.len(), 1);
    }

    // --- R1: CSR signer fields (13/14) routing ----------------------------

    fn csr_app() -> App {
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Csr;
        app.focus = Focus::Form;
        app
    }

    #[test]
    fn csr_field_13_routes_typed_chars_into_signer_cert_pem() {
        let mut app = csr_app();
        app.csr_mut().field = 13;
        app.update(Message::Char('c'));
        app.update(Message::Char('a'));
        assert_eq!(app.csr().signer.cert_pem_file, "ca");
        assert!(
            app.csr().signer.private_key_pem_file.is_empty(),
            "the key buffer must be untouched"
        );
        app.update(Message::Backspace);
        assert_eq!(app.csr().signer.cert_pem_file, "c");
    }

    #[test]
    fn csr_field_14_routes_typed_chars_into_signer_private_key_pem() {
        let mut app = csr_app();
        app.csr_mut().field = 14;
        app.update(Message::Char('k'));
        app.update(Message::Char('y'));
        assert_eq!(app.csr().signer.private_key_pem_file, "ky");
        assert!(
            app.csr().signer.cert_pem_file.is_empty(),
            "the cert buffer must be untouched"
        );
    }

    #[test]
    fn csr_signer_fields_are_browseable_path_targets() {
        let mut app = csr_app();
        app.csr_mut().field = 13;
        assert_eq!(
            app.focused_path_field(),
            Some(BrowseTarget {
                screen: Screen::Csr,
                field: 13,
            })
        );
        app.csr_mut().field = 14;
        assert_eq!(
            app.focused_path_field(),
            Some(BrowseTarget {
                screen: Screen::Csr,
                field: 14,
            })
        );
        // The original csr_pem_file path field is still browseable.
        app.csr_mut().field = 9;
        assert!(app.focused_path_field().is_some());
    }

    #[test]
    fn csr_apply_path_writes_into_signer_buffers() {
        let mut app = csr_app();
        app.apply_path(
            BrowseTarget {
                screen: Screen::Csr,
                field: 13,
            },
            "/tmp/ca.pem".to_string(),
        );
        app.apply_path(
            BrowseTarget {
                screen: Screen::Csr,
                field: 14,
            },
            "/tmp/ca.key".to_string(),
        );
        assert_eq!(app.csr().signer.cert_pem_file, "/tmp/ca.pem");
        assert_eq!(app.csr().signer.private_key_pem_file, "/tmp/ca.key");
    }

    #[test]
    fn csr_down_reaches_field_14() {
        let mut app = csr_app();
        app.csr_mut().field = 0;
        // 14 Downs from field 0 reach field 14 (0..=14 => 15 fields).
        for _ in 0..14 {
            app.update(Message::Down);
        }
        assert_eq!(app.csr().field, 14, "active_field_count must allow 0..=14");
        // Further Down is clamped at the last field.
        app.update(Message::Down);
        assert_eq!(app.csr().field, 14);
    }

    // --- R3: CRL revoked-row navigation -----------------------------------

    fn crl_app_with_rows(n: usize) -> App {
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Crl;
        app.focus = Focus::Form;
        for _ in 0..n {
            app.update(Message::AddRow);
        }
        app
    }

    #[test]
    fn crl_down_past_last_fixed_field_enters_revoked_table() {
        let mut app = crl_app_with_rows(2);
        // AddRow leaves selected_row at the last row; reset to fixed fields to
        // exercise navigation from the top.
        app.crl.selected_row = None;
        app.crl.field = 0;
        // Step through the 3 fixed fields 0..=2.
        app.update(Message::Down); // -> 1
        app.update(Message::Down); // -> 2
        assert_eq!(app.crl.field, 2);
        assert_eq!(app.crl.selected_row, None);
        // Down past field 2 enters the table at row 0.
        app.update(Message::Down);
        assert_eq!(app.crl.selected_row, Some(0));
        // Next Down advances to row 1 (the last row).
        app.update(Message::Down);
        assert_eq!(app.crl.selected_row, Some(1));
        // Further Down is clamped at the last row.
        app.update(Message::Down);
        assert_eq!(app.crl.selected_row, Some(1));
    }

    #[test]
    fn crl_up_retreats_rows_then_returns_to_fixed_fields() {
        let mut app = crl_app_with_rows(2);
        app.crl.selected_row = Some(1);
        app.crl.field = 2;
        // Up retreats within the table.
        app.update(Message::Up);
        assert_eq!(app.crl.selected_row, Some(0));
        // Up from row 0 leaves the table back to the last fixed field.
        app.update(Message::Up);
        assert_eq!(app.crl.selected_row, None);
        assert_eq!(app.crl.field, 2);
        // Continued Up steps the fixed fields.
        app.update(Message::Up);
        assert_eq!(app.crl.field, 1);
    }

    #[test]
    fn crl_down_into_empty_table_stays_on_fixed_field() {
        let mut app = crl_app_with_rows(0);
        app.crl.field = 2;
        app.crl.selected_row = None;
        app.update(Message::Down);
        // No rows to enter; selection stays None and field stays at 2.
        assert_eq!(app.crl.selected_row, None);
        assert_eq!(app.crl.field, 2);
    }

    #[test]
    fn crl_right_cycles_only_the_selected_rows_reason() {
        let mut app = crl_app_with_rows(2);
        // Select row 0 and cycle its reason; row 1 must stay untouched.
        app.crl.selected_row = Some(0);
        let row1_before = app.crl.revoked[1].reason;
        app.update(Message::Right);
        assert_eq!(
            app.crl.revoked[0].reason,
            1 % REASON_OPTIONS.len(),
            "selected row 0's reason advances"
        );
        assert_eq!(
            app.crl.revoked[1].reason, row1_before,
            "non-selected row 1 is untouched"
        );
        // Now select row 1 and cycle it; row 0 must stay where it was.
        let row0_after = app.crl.revoked[0].reason;
        app.crl.selected_row = Some(1);
        app.update(Message::Right);
        assert_eq!(app.crl.revoked[1].reason, 1 % REASON_OPTIONS.len());
        assert_eq!(app.crl.revoked[0].reason, row0_after);
    }

    #[test]
    fn crl_typing_does_not_edit_fixed_field_while_row_selected() {
        let mut app = crl_app_with_rows(1);
        app.crl.field = 2; // private_key_pem fixed field
        app.crl.selected_row = Some(0);
        app.update(Message::Char('x'));
        assert!(
            app.crl.signer.private_key_pem_file.is_empty(),
            "typing must not edit the fixed field while a row is selected"
        );
        assert!(app.focused_path_field().is_none());
    }

    #[test]
    fn generate_request_opens_dialog_then_confirm_yields_effect() {
        let mut app = cert_app();
        app.update(Message::RequestGenerate);
        assert!(app.dialog.is_some());
        let effect = app.update(Message::Confirm);
        assert_eq!(
            effect,
            Some(Effect::Generate {
                screen: Screen::Cert,
                path: "./out".to_string(),
            })
        );
        assert!(app.dialog.is_none());
    }

    #[test]
    fn save_yaml_request_opens_dialog_then_confirm_yields_effect() {
        let mut app = cert_app();
        app.update(Message::RequestSaveYaml);
        let effect = app.update(Message::Confirm);
        assert_eq!(
            effect,
            Some(Effect::SaveYaml {
                screen: Screen::Cert,
                path: "./out".to_string(),
            })
        );
    }

    #[test]
    fn dialog_back_cancels_without_effect() {
        let mut app = cert_app();
        app.update(Message::RequestGenerate);
        let effect = app.update(Message::Back);
        assert!(effect.is_none());
        assert!(app.dialog.is_none());
    }

    #[test]
    fn dialog_typing_edits_path() {
        let mut app = cert_app();
        app.update(Message::RequestGenerate);
        app.update(Message::Backspace);
        app.update(Message::Char('x'));
        if let Some(Dialog::Confirm { path, .. }) = &app.dialog {
            assert!(path.ends_with('x'));
        } else {
            panic!("dialog should still be open");
        }
    }

    #[test]
    fn update_is_pure_no_quit_on_normal_keys() {
        let mut app = cert_app();
        app.update(Message::Char('z'));
        app.update(Message::Down);
        app.update(Message::Up);
        assert!(!app.should_quit);
    }

    #[test]
    fn set_status_clears_error_and_vice_versa() {
        let mut app = App::new("./out".to_string());
        app.set_error("boom");
        assert_eq!(app.error.as_deref(), Some("boom"));
        assert!(app.status.is_none());
        app.set_status("ok");
        assert_eq!(app.status.as_deref(), Some("ok"));
        assert!(app.error.is_none());
    }

    // --- multi-certificate list ------------------------------------------

    #[test]
    fn new_app_seeds_exactly_one_cert_entry() {
        // Setup & invoke
        let app = App::new("./out".to_string());
        // Expect
        assert_eq!(app.cert_list.len(), 1);
        assert_eq!(app.cert_index, 0);
    }

    #[test]
    fn tab_on_cert_cycles_menu_entries_form() {
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Cert;
        app.focus = Focus::Menu;
        app.update(Message::FocusNext);
        assert_eq!(app.focus, Focus::Entries);
        app.update(Message::FocusNext);
        assert_eq!(app.focus, Focus::Form);
        app.update(Message::FocusNext);
        assert_eq!(app.focus, Focus::Menu);
    }

    #[test]
    fn tab_on_non_entry_screen_skips_entries() {
        // CRL is the only screen without an entry sub-list: Tab toggles
        // Menu ↔ Form, never landing on Focus::Entries.
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Crl;
        app.focus = Focus::Menu;
        app.update(Message::FocusNext);
        assert_eq!(app.focus, Focus::Form);
        app.update(Message::FocusNext);
        assert_eq!(app.focus, Focus::Menu);
    }

    #[test]
    fn add_row_on_cert_grows_list_and_selects_new_entry() {
        let mut app = cert_app();
        app.update(Message::AddRow);
        assert_eq!(app.cert_list.len(), 2);
        assert_eq!(app.cert_index, 1);
        app.update(Message::AddRow);
        assert_eq!(app.cert_list.len(), 3);
        assert_eq!(app.cert_index, 2);
    }

    #[test]
    fn delete_row_on_cert_never_empties_list() {
        let mut app = cert_app();
        app.update(Message::AddRow); // 2 entries, index 1
        app.update(Message::DeleteRow);
        assert_eq!(app.cert_list.len(), 1);
        assert_eq!(app.cert_index, 0);
        // Deleting the last remaining entry is a no-op.
        app.update(Message::DeleteRow);
        assert_eq!(app.cert_list.len(), 1);
    }

    #[test]
    fn entries_up_down_select_entry() {
        let mut app = cert_app();
        app.update(Message::AddRow);
        app.update(Message::AddRow); // 3 entries, index 2
        app.focus = Focus::Entries;
        app.update(Message::Up);
        assert_eq!(app.cert_index, 1);
        app.update(Message::Up);
        assert_eq!(app.cert_index, 0);
        app.update(Message::Up); // clamps at 0
        assert_eq!(app.cert_index, 0);
        app.update(Message::Down);
        assert_eq!(app.cert_index, 1);
    }

    #[test]
    fn enter_on_entries_moves_focus_into_form() {
        let mut app = cert_app();
        app.focus = Focus::Entries;
        let effect = app.update(Message::Confirm);
        assert!(effect.is_none());
        assert_eq!(app.focus, Focus::Form);
    }

    #[test]
    fn form_fields_edit_the_selected_entry() {
        let mut app = cert_app();
        app.update(Message::AddRow); // index 1
        app.cert_mut().field = 0;
        app.update(Message::Char('x'));
        assert_eq!(app.cert_list[1].id, "x");
        assert_eq!(app.cert_list[0].id, "");
    }

    // --- clear actions ----------------------------------------------------

    #[test]
    fn clear_form_resets_active_cert_entry_only() {
        let mut app = cert_app();
        app.cert_mut().id = "first".to_string();
        app.update(Message::AddRow); // index 1
        app.cert_mut().id = "second".to_string();
        app.set_status("hint");
        app.update(Message::ClearForm);
        // Active (second) entry reset, sibling untouched.
        assert_eq!(app.cert_list[1].id, "");
        assert_eq!(app.cert_list[0].id, "first");
        assert_eq!(app.cert_list.len(), 2);
        assert!(app.status.is_none());
    }

    #[test]
    fn clear_all_on_cert_collapses_to_single_default_entry() {
        let mut app = cert_app();
        app.cert_mut().id = "first".to_string();
        app.update(Message::AddRow);
        app.cert_mut().id = "second".to_string();
        app.update(Message::ClearAll);
        assert_eq!(app.cert_list.len(), 1);
        assert_eq!(app.cert_index, 0);
        assert_eq!(app.cert_list[0].id, "");
    }

    #[test]
    fn clear_form_resets_csr() {
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Csr;
        app.focus = Focus::Form;
        app.csr_mut().id = "req".to_string();
        app.update(Message::ClearForm);
        assert_eq!(app.csr().id, "");
    }

    #[test]
    fn clear_all_on_crl_matches_clear_form() {
        // CRL is the single-form screen: ClearAll falls back to clear_form.
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Crl;
        app.focus = Focus::Form;
        app.crl.crl_file = "out.crl".to_string();
        app.update(Message::ClearAll);
        assert_eq!(app.crl.crl_file, "");
    }

    // --- status kind ------------------------------------------------------

    #[test]
    fn set_success_marks_status_kind_success() {
        let mut app = App::new("./out".to_string());
        app.set_success("Generated 1 certificate to ./out");
        assert_eq!(app.status_kind(), StatusKind::Success);
        assert!(app.error.is_none());
        // Plain status falls back to Info.
        app.set_status("hint");
        assert_eq!(app.status_kind(), StatusKind::Info);
    }

    // --- signer key field -------------------------------------------------

    #[test]
    fn typing_into_field_13_fills_signer_private_key() {
        let mut app = cert_app();
        app.cert_mut().field = 13;
        app.update(Message::Char('k'));
        app.update(Message::Char('e'));
        app.update(Message::Char('y'));
        assert_eq!(app.cert().signer.private_key_pem_file, "key");
        assert_eq!(app.cert().signer.cert_pem_file, "");
    }

    #[test]
    fn cert_field_count_is_fourteen() {
        let app = cert_app();
        assert_eq!(app.active_field_count(), 14);
    }

    // --- path-field tagging ----------------------------------------------

    #[test]
    fn focused_path_field_true_on_cert_signer_paths() {
        let mut app = cert_app();
        app.cert_mut().field = 12;
        assert_eq!(
            app.focused_path_field(),
            Some(BrowseTarget {
                screen: Screen::Cert,
                field: 12
            })
        );
        app.cert_mut().field = 13;
        assert!(app.focused_field_is_path());
    }

    #[test]
    fn focused_path_field_false_on_id() {
        let mut app = cert_app();
        app.cert_mut().field = 0;
        assert!(!app.focused_field_is_path());
        assert!(app.focused_path_field().is_none());
    }

    #[test]
    fn focused_path_field_tags_cms_paths() {
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Cms;
        app.focus = Focus::Form;
        for f in [1usize, 2, 3, 4] {
            app.cms_mut().field = f;
            assert!(
                app.focused_field_is_path(),
                "cms field {f} should be a path"
            );
        }
        app.cms_mut().field = 0;
        assert!(!app.focused_field_is_path());
    }

    #[test]
    fn focused_path_field_none_when_entries_focused() {
        let mut app = cert_app();
        app.cert_mut().field = 12;
        app.focus = Focus::Entries;
        assert!(app.focused_path_field().is_none());
    }

    // --- file browser -----------------------------------------------------

    use std::path::PathBuf;

    fn dir(name: &str) -> FileEntry {
        FileEntry {
            name: name.to_string(),
            is_dir: true,
        }
    }

    fn file(name: &str) -> FileEntry {
        FileEntry {
            name: name.to_string(),
            is_dir: false,
        }
    }

    /// A `FillField` purpose for the given (screen, field) — the common test
    /// shape replacing the old bare `BrowseTarget`.
    fn fill(screen: Screen, field: usize) -> BrowsePurpose {
        BrowsePurpose::FillField(BrowseTarget { screen, field })
    }

    #[test]
    fn open_browser_on_path_field_requests_read_dir() {
        let mut app = cert_app();
        app.cert_mut().field = 12; // signer cert pem (path field)
        let effect = app.update(Message::OpenBrowser);
        assert_eq!(
            effect,
            Some(Effect::ReadDir {
                path: PathBuf::from("."),
                purpose: fill(Screen::Cert, 12),
            })
        );
        // The reducer requested the listing but performed no I/O / no install.
        assert!(app.browser.is_none());
    }

    #[test]
    fn open_browser_uses_current_value_dirname() {
        let mut app = cert_app();
        app.cert_mut().field = 12;
        app.cert_mut().signer.cert_pem_file = "/etc/certs/root.pem".to_string();
        let effect = app.update(Message::OpenBrowser);
        assert_eq!(
            effect,
            Some(Effect::ReadDir {
                path: PathBuf::from("/etc/certs"),
                purpose: fill(Screen::Cert, 12),
            })
        );
    }

    #[test]
    fn open_browser_on_non_path_field_is_noop() {
        let mut app = cert_app();
        app.cert_mut().field = 0; // id, not a path
        let effect = app.update(Message::OpenBrowser);
        assert!(effect.is_none());
        assert!(app.browser.is_none());
    }

    #[test]
    fn set_browser_entries_installs_and_resets_selection() {
        let mut app = cert_app();
        let purpose = fill(Screen::Cert, 12);
        app.set_browser_entries(
            PathBuf::from("/tmp"),
            vec![dir(".."), file("a.pem")],
            purpose,
        );
        let browser = app.browser.as_ref().unwrap();
        assert_eq!(browser.current_dir, PathBuf::from("/tmp"));
        assert_eq!(browser.entries.len(), 2);
        assert_eq!(browser.selected, 0);
        assert_eq!(browser.purpose, purpose);
    }

    #[test]
    fn browser_up_down_clamp_selection() {
        let mut app = cert_app();
        app.set_browser_entries(
            PathBuf::from("/tmp"),
            vec![dir(".."), dir("ca"), file("a.pem")],
            fill(Screen::Cert, 12),
        );
        app.update(Message::Down);
        assert_eq!(app.browser.as_ref().unwrap().selected, 1);
        app.update(Message::Down);
        assert_eq!(app.browser.as_ref().unwrap().selected, 2);
        app.update(Message::Down); // clamps at last
        assert_eq!(app.browser.as_ref().unwrap().selected, 2);
        app.update(Message::Up);
        app.update(Message::Up);
        app.update(Message::Up); // clamps at 0
        assert_eq!(app.browser.as_ref().unwrap().selected, 0);
    }

    #[test]
    fn browser_enter_on_dir_requests_read_dir() {
        let mut app = cert_app();
        let purpose = fill(Screen::Cert, 12);
        app.set_browser_entries(
            PathBuf::from("/tmp"),
            vec![dir("ca"), file("a.pem")],
            purpose,
        );
        let effect = app.update(Message::Confirm);
        assert_eq!(
            effect,
            Some(Effect::ReadDir {
                path: PathBuf::from("/tmp/ca"),
                purpose,
            })
        );
        // Still open: the descended listing arrives via set_browser_entries.
        assert!(app.browser.is_some());
    }

    #[test]
    fn browser_enter_on_parent_requests_read_dir() {
        let mut app = cert_app();
        let purpose = fill(Screen::Cms, 1);
        app.screen = Screen::Cms;
        app.set_browser_entries(PathBuf::from("/tmp/sub"), vec![dir("..")], purpose);
        let effect = app.update(Message::Confirm);
        assert_eq!(
            effect,
            Some(Effect::ReadDir {
                path: PathBuf::from("/tmp/sub/.."),
                purpose,
            })
        );
    }

    #[test]
    fn browser_enter_on_file_applies_path_and_closes() {
        let mut app = cert_app();
        app.cert_mut().field = 13; // signer key pem
        app.set_browser_entries(
            PathBuf::from("/keys"),
            vec![dir(".."), file("root_key.pem")],
            fill(Screen::Cert, 13),
        );
        app.update(Message::Down); // select the file
        let effect = app.update(Message::Confirm);
        assert!(effect.is_none());
        assert!(app.browser.is_none());
        assert_eq!(app.cert().signer.private_key_pem_file, "/keys/root_key.pem");
    }

    #[test]
    fn browser_backspace_requests_parent() {
        let mut app = cert_app();
        let purpose = fill(Screen::Cert, 12);
        app.set_browser_entries(PathBuf::from("/tmp/sub"), vec![file("a.pem")], purpose);
        let effect = app.update(Message::Backspace);
        assert_eq!(
            effect,
            Some(Effect::ReadDir {
                path: PathBuf::from("/tmp"),
                purpose,
            })
        );
    }

    #[test]
    fn browser_backspace_at_root_is_noop() {
        let mut app = cert_app();
        app.set_browser_entries(PathBuf::from("/"), vec![dir("etc")], fill(Screen::Cert, 12));
        let effect = app.update(Message::Backspace);
        assert!(effect.is_none());
        assert!(app.browser.is_some());
    }

    #[test]
    fn browser_esc_closes_without_writing_and_without_quitting() {
        let mut app = cert_app();
        app.cert_mut().field = 12;
        app.set_browser_entries(
            PathBuf::from("/tmp"),
            vec![file("a.pem")],
            fill(Screen::Cert, 12),
        );
        let effect = app.update(Message::Back);
        assert!(effect.is_none());
        assert!(app.browser.is_none());
        assert_eq!(app.cert().signer.cert_pem_file, "");
        assert!(!app.should_quit);
    }

    #[test]
    fn apply_path_routes_to_cert_signer_key() {
        let mut app = cert_app();
        app.apply_path(
            BrowseTarget {
                screen: Screen::Cert,
                field: 13,
            },
            "/k/key.pem".to_string(),
        );
        assert_eq!(app.cert().signer.private_key_pem_file, "/k/key.pem");
    }

    #[test]
    fn apply_path_routes_to_cms_data_file() {
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Cms;
        app.apply_path(
            BrowseTarget {
                screen: Screen::Cms,
                field: 1,
            },
            "/d/data.bin".to_string(),
        );
        assert_eq!(app.cms().data_file, "/d/data.bin");
    }

    // --- error popup ------------------------------------------------------

    #[test]
    fn set_error_popup_populates_popup_and_clears_status() {
        // Setup
        let mut app = App::new("./out".to_string());
        app.set_status("working");
        // Invoke
        app.set_error_popup("Generate failed: boom");
        // Expect
        assert_eq!(app.error_popup.as_deref(), Some("Generate failed: boom"));
        assert!(app.status.is_none());
    }

    #[test]
    fn error_popup_dismissed_by_back_and_consumes_key() {
        let mut app = cert_app();
        app.set_error_popup("boom");
        let effect = app.update(Message::Back);
        assert!(effect.is_none());
        assert!(app.error_popup.is_none());
        // Back was consumed by the popup, not the form: still on the Cert screen.
        assert_eq!(app.screen, Screen::Cert);
    }

    #[test]
    fn error_popup_dismissed_by_confirm() {
        let mut app = cert_app();
        app.set_error_popup("boom");
        let effect = app.update(Message::Confirm);
        assert!(effect.is_none());
        assert!(app.error_popup.is_none());
    }

    #[test]
    fn error_popup_ignores_other_keys() {
        let mut app = cert_app();
        app.cert_mut().field = 0;
        app.set_error_popup("boom");
        // Arbitrary navigation / typing while the popup is open is a no-op.
        let effect = app.update(Message::Down);
        assert!(effect.is_none());
        app.update(Message::Char('x'));
        assert!(app.error_popup.is_some(), "popup still open");
        assert_eq!(app.cert().id, "", "typing did not leak to the form");
    }

    #[test]
    fn error_popup_takes_precedence_over_open_dialog() {
        let mut app = cert_app();
        app.update(Message::RequestGenerate);
        assert!(app.dialog.is_some());
        // A failure popup opens on top of the dialog.
        app.set_error_popup("boom");
        // Enter dismisses the popup only — it does not confirm the dialog.
        let effect = app.update(Message::Confirm);
        assert!(effect.is_none());
        assert!(app.error_popup.is_none());
        assert!(app.dialog.is_some(), "the dialog underneath is untouched");
    }

    // --- per-field clear (ClearField) -------------------------------------

    #[test]
    fn clear_field_empties_focused_text_buffer() {
        let mut app = cert_app();
        app.cert_mut().field = 1; // common_name (text)
        app.cert_mut().common_name = "example.com".to_string();
        let effect = app.update(Message::ClearField);
        assert!(effect.is_none());
        assert_eq!(app.cert().common_name, "");
    }

    #[test]
    fn clear_field_is_noop_on_cycler_field() {
        let mut app = cert_app();
        app.cert_mut().field = 4; // key_type cycler (not a text field)
        app.cert_mut().key_type = 2;
        let effect = app.update(Message::ClearField);
        assert!(effect.is_none());
        assert_eq!(app.cert().key_type, 2, "cycler is left untouched");
    }

    #[test]
    fn clear_field_is_noop_on_toggle_field() {
        let mut app = cert_app();
        app.cert_mut().field = 8; // ca toggle
        app.cert_mut().ca = true;
        app.update(Message::ClearField);
        assert!(app.cert().ca, "toggle is left untouched");
    }

    // --- browser clear / none ---------------------------------------------

    #[test]
    fn browser_clear_field_empties_target_and_closes() {
        let mut app = cert_app();
        app.cert_mut().field = 12;
        app.cert_mut().signer.cert_pem_file = "/old/cert.pem".to_string();
        app.set_browser_entries(
            PathBuf::from("/tmp"),
            vec![file("a.pem")],
            fill(Screen::Cert, 12),
        );
        let effect = app.update(Message::ClearField);
        assert!(effect.is_none());
        assert!(app.browser.is_none());
        assert_eq!(app.cert().signer.cert_pem_file, "");
    }

    #[test]
    fn browser_char_c_clears_target_and_closes() {
        let mut app = cert_app();
        app.cert_mut().field = 13;
        app.cert_mut().signer.private_key_pem_file = "/old/key.pem".to_string();
        app.set_browser_entries(
            PathBuf::from("/keys"),
            vec![file("k.pem")],
            fill(Screen::Cert, 13),
        );
        let effect = app.update(Message::Char('c'));
        assert!(effect.is_none());
        assert!(app.browser.is_none());
        assert_eq!(app.cert().signer.private_key_pem_file, "");
    }

    // --- load mode (Ctrl+L) -----------------------------------------------

    #[test]
    fn load_config_message_opens_load_browser_on_form_screen() {
        let mut app = cert_app(); // Screen::Cert
        let effect = app.update(Message::LoadConfig);
        assert_eq!(
            effect,
            Some(Effect::ReadDir {
                path: PathBuf::from("./out"),
                purpose: BrowsePurpose::LoadConfig(Screen::Cert),
            })
        );
        // The reducer requested the listing but installed nothing yet.
        assert!(app.browser.is_none());
    }

    #[test]
    fn load_config_message_is_noop_on_menu() {
        let mut app = App::new("./out".to_string()); // Screen::Menu
        let effect = app.update(Message::LoadConfig);
        assert!(effect.is_none());
        assert!(app.browser.is_none());
    }

    #[test]
    fn browser_enter_on_file_in_load_mode_returns_load_config_effect() {
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Csr;
        app.focus = Focus::Form;
        app.set_browser_entries(
            PathBuf::from("/cfg"),
            vec![dir(".."), file("csr.yaml")],
            BrowsePurpose::LoadConfig(Screen::Csr),
        );
        app.update(Message::Down); // select the file
        let effect = app.update(Message::Confirm);
        assert_eq!(
            effect,
            Some(Effect::LoadConfig {
                screen: Screen::Csr,
                path: "/cfg/csr.yaml".to_string(),
            })
        );
        // The browser closes; the impure read happens in the effect handler.
        assert!(app.browser.is_none());
    }

    #[test]
    fn browser_enter_on_dir_in_load_mode_preserves_purpose() {
        let mut app = cert_app();
        app.set_browser_entries(
            PathBuf::from("/cfg"),
            vec![dir("sub"), file("c.yaml")],
            BrowsePurpose::LoadConfig(Screen::Cert),
        );
        let effect = app.update(Message::Confirm);
        assert_eq!(
            effect,
            Some(Effect::ReadDir {
                path: PathBuf::from("/cfg/sub"),
                purpose: BrowsePurpose::LoadConfig(Screen::Cert),
            })
        );
        assert!(app.browser.is_some());
    }

    #[test]
    fn browser_clear_in_load_mode_just_closes() {
        let mut app = cert_app();
        app.set_browser_entries(
            PathBuf::from("/cfg"),
            vec![file("c.yaml")],
            BrowsePurpose::LoadConfig(Screen::Cert),
        );
        let effect = app.update(Message::ClearField);
        assert!(effect.is_none());
        assert!(app.browser.is_none(), "load mode clear just closes");
    }

    // --- load_* install setters -------------------------------------------

    #[test]
    fn load_cert_list_replaces_list_and_resets_index() {
        let mut app = App::new("./out".to_string());
        // Pre-existing multi-entry state with a stale index.
        app.cert_list = vec![CertForm::default(), CertForm::default()];
        app.cert_index = 1;
        app.focus = Focus::Menu;

        let a = CertForm {
            id: "ca".to_string(),
            ..CertForm::default()
        };
        let b = CertForm {
            id: "leaf".to_string(),
            ..CertForm::default()
        };
        app.load_cert_list(vec![a, b]);

        assert_eq!(app.cert_list.len(), 2);
        assert_eq!(app.cert_list[0].id, "ca");
        assert_eq!(app.cert_list[1].id, "leaf");
        assert_eq!(app.cert_index, 0);
        assert_eq!(app.screen, Screen::Cert);
        assert_eq!(app.focus, Focus::Form);
    }

    #[test]
    fn load_cert_list_with_empty_keeps_one_default_entry() {
        let mut app = App::new("./out".to_string());
        app.load_cert_list(Vec::new());
        assert_eq!(app.cert_list.len(), 1);
        assert_eq!(app.cert_index, 0);
    }

    #[test]
    fn load_csr_list_replaces_list_and_resets_index() {
        let mut app = App::new("./out".to_string());
        // Pre-existing multi-entry state with a stale index.
        app.csr_list = vec![CsrForm::default(), CsrForm::default()];
        app.csr_index = 1;
        app.focus = Focus::Menu;

        let generate = CsrForm {
            id: "req".to_string(),
            sign_mode: false,
            ..CsrForm::default()
        };
        let sign = CsrForm {
            id: "sign".to_string(),
            sign_mode: true,
            ..CsrForm::default()
        };
        app.load_csr_list(vec![generate, sign]);

        assert_eq!(app.csr_list.len(), 2);
        assert_eq!(app.csr_list[0].id, "req");
        assert!(!app.csr_list[0].sign_mode);
        assert_eq!(app.csr_list[1].id, "sign");
        assert!(app.csr_list[1].sign_mode, "sign_mode preserved per entry");
        assert_eq!(app.csr_index, 0);
        assert_eq!(app.screen, Screen::Csr);
        assert_eq!(app.focus, Focus::Form);
    }

    #[test]
    fn load_csr_list_with_empty_keeps_one_default_entry() {
        let mut app = App::new("./out".to_string());
        app.load_csr_list(Vec::new());
        assert_eq!(app.csr_list.len(), 1);
        assert_eq!(app.csr_index, 0);
    }

    #[test]
    fn load_crl_replaces_form_and_clamps_selected_row() {
        let mut app = App::new("./out".to_string());
        let form = CrlForm {
            crl_file: "out.crl".to_string(),
            revoked: vec![RevokedRow::default()],
            selected_row: Some(5), // out of range
            ..CrlForm::default()
        };
        app.load_crl(form);
        assert_eq!(app.crl.crl_file, "out.crl");
        assert_eq!(app.crl.selected_row, Some(0), "clamped into range");
        assert_eq!(app.focus, Focus::Form);
    }

    #[test]
    fn load_cms_list_replaces_list_and_resets_index() {
        let mut app = App::new("./out".to_string());
        // Pre-existing multi-entry state with a stale index.
        app.cms_list = vec![CmsForm::default(), CmsForm::default()];
        app.cms_index = 1;
        app.focus = Focus::Menu;

        let a = CmsForm {
            id: "msg1".to_string(),
            ..CmsForm::default()
        };
        let b = CmsForm {
            id: "msg2".to_string(),
            ..CmsForm::default()
        };
        app.load_cms_list(vec![a, b]);

        assert_eq!(app.cms_list.len(), 2);
        assert_eq!(app.cms_list[0].id, "msg1");
        assert_eq!(app.cms_list[1].id, "msg2");
        assert_eq!(app.cms_index, 0);
        assert_eq!(app.screen, Screen::Cms);
        assert_eq!(app.focus, Focus::Form);
    }

    #[test]
    fn load_cms_list_with_empty_keeps_one_default_entry() {
        let mut app = App::new("./out".to_string());
        app.load_cms_list(Vec::new());
        assert_eq!(app.cms_list.len(), 1);
        assert_eq!(app.cms_index, 0);
    }

    // --- R1/R2: CSR & CMS multi-entry reducers ----------------------------

    fn cms_app() -> App {
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Cms;
        app.focus = Focus::Form;
        app
    }

    #[test]
    fn new_app_seeds_exactly_one_csr_and_cms_entry() {
        let app = App::new("./out".to_string());
        assert_eq!(app.csr_list.len(), 1);
        assert_eq!(app.csr_index, 0);
        assert_eq!(app.cms_list.len(), 1);
        assert_eq!(app.cms_index, 0);
    }

    #[test]
    fn tab_on_csr_cycles_menu_entries_form() {
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Csr;
        app.focus = Focus::Menu;
        app.update(Message::FocusNext);
        assert_eq!(app.focus, Focus::Entries);
        app.update(Message::FocusNext);
        assert_eq!(app.focus, Focus::Form);
        app.update(Message::FocusNext);
        assert_eq!(app.focus, Focus::Menu);
    }

    #[test]
    fn tab_on_cms_cycles_menu_entries_form() {
        let mut app = cms_app();
        app.focus = Focus::Menu;
        app.update(Message::FocusNext);
        assert_eq!(app.focus, Focus::Entries);
        app.update(Message::FocusNext);
        assert_eq!(app.focus, Focus::Form);
        app.update(Message::FocusNext);
        assert_eq!(app.focus, Focus::Menu);
    }

    #[test]
    fn add_row_on_csr_grows_list_and_selects_new_entry() {
        let mut app = csr_app();
        app.update(Message::AddRow);
        assert_eq!(app.csr_list.len(), 2);
        assert_eq!(app.csr_index, 1);
        app.update(Message::AddRow);
        assert_eq!(app.csr_list.len(), 3);
        assert_eq!(app.csr_index, 2);
    }

    #[test]
    fn add_row_on_cms_grows_list_and_selects_new_entry() {
        let mut app = cms_app();
        app.update(Message::AddRow);
        assert_eq!(app.cms_list.len(), 2);
        assert_eq!(app.cms_index, 1);
    }

    #[test]
    fn delete_row_on_csr_never_empties_list() {
        let mut app = csr_app();
        app.update(Message::AddRow); // 2 entries, index 1
        app.update(Message::DeleteRow);
        assert_eq!(app.csr_list.len(), 1);
        assert_eq!(app.csr_index, 0);
        // Deleting the last remaining entry is a no-op.
        app.update(Message::DeleteRow);
        assert_eq!(app.csr_list.len(), 1);
    }

    #[test]
    fn delete_row_on_cms_never_empties_list() {
        let mut app = cms_app();
        app.update(Message::AddRow); // 2 entries, index 1
        app.update(Message::DeleteRow);
        assert_eq!(app.cms_list.len(), 1);
        assert_eq!(app.cms_index, 0);
        app.update(Message::DeleteRow);
        assert_eq!(app.cms_list.len(), 1);
    }

    #[test]
    fn csr_entries_up_down_select_entry() {
        let mut app = csr_app();
        app.update(Message::AddRow);
        app.update(Message::AddRow); // 3 entries, index 2
        app.focus = Focus::Entries;
        app.update(Message::Up);
        assert_eq!(app.csr_index, 1);
        app.update(Message::Up);
        assert_eq!(app.csr_index, 0);
        app.update(Message::Up); // clamps at 0
        assert_eq!(app.csr_index, 0);
        app.update(Message::Down);
        assert_eq!(app.csr_index, 1);
    }

    #[test]
    fn cms_entries_up_down_select_entry() {
        let mut app = cms_app();
        app.update(Message::AddRow);
        app.update(Message::AddRow); // 3 entries, index 2
        app.focus = Focus::Entries;
        app.update(Message::Up);
        assert_eq!(app.cms_index, 1);
        app.update(Message::Down);
        app.update(Message::Down); // clamps at last (2)
        assert_eq!(app.cms_index, 2);
        app.update(Message::Down);
        assert_eq!(app.cms_index, 2);
    }

    #[test]
    fn csr_typing_edits_the_selected_entry() {
        let mut app = csr_app();
        app.update(Message::AddRow); // index 1
        app.csr_mut().field = 0;
        app.update(Message::Char('x'));
        assert_eq!(app.csr_list[1].id, "x");
        assert_eq!(app.csr_list[0].id, "", "sibling entry untouched");
        // Switch back to entry 0 and type into it.
        app.csr_index = 0;
        app.csr_mut().field = 1;
        app.update(Message::Char('y'));
        assert_eq!(app.csr_list[0].common_name, "y");
        assert_eq!(app.csr_list[1].common_name, "");
    }

    #[test]
    fn cms_typing_edits_the_selected_entry() {
        let mut app = cms_app();
        app.update(Message::AddRow); // index 1
        app.cms_mut().field = 0;
        app.update(Message::Char('x'));
        assert_eq!(app.cms_list[1].id, "x");
        assert_eq!(app.cms_list[0].id, "", "sibling entry untouched");
        app.cms_index = 0;
        app.cms_mut().field = 1;
        app.update(Message::Char('d'));
        assert_eq!(app.cms_list[0].data_file, "d");
        assert_eq!(app.cms_list[1].data_file, "");
    }

    #[test]
    fn csr_cycle_and_toggle_act_on_selected_entry() {
        let mut app = csr_app();
        app.update(Message::AddRow); // index 1
        // sign_mode toggle is field 7.
        app.csr_mut().field = 7;
        app.update(Message::Toggle);
        assert!(app.csr_list[1].sign_mode);
        assert!(!app.csr_list[0].sign_mode, "sibling untouched");
        // key_type cycler is field 4.
        app.csr_mut().field = 4;
        let start = app.csr().key_type;
        app.update(Message::Right);
        assert_ne!(app.csr_list[1].key_type, start);
        assert_eq!(app.csr_list[0].key_type, 0, "sibling untouched");
    }

    #[test]
    fn cms_detached_toggle_acts_on_selected_entry() {
        let mut app = cms_app();
        app.update(Message::AddRow); // index 1
        app.update(Message::Toggle); // detached toggle (any field)
        assert!(app.cms_list[1].detached);
        assert!(!app.cms_list[0].detached, "sibling untouched");
    }

    #[test]
    fn clear_form_resets_active_csr_entry_only() {
        let mut app = csr_app();
        app.csr_mut().id = "first".to_string();
        app.update(Message::AddRow); // index 1
        app.csr_mut().id = "second".to_string();
        app.update(Message::ClearForm);
        assert_eq!(app.csr_list[1].id, "");
        assert_eq!(app.csr_list[0].id, "first");
        assert_eq!(app.csr_list.len(), 2);
    }

    #[test]
    fn clear_all_on_csr_collapses_to_single_default_entry() {
        let mut app = csr_app();
        app.csr_mut().id = "a".to_string();
        app.update(Message::AddRow);
        app.update(Message::AddRow);
        app.update(Message::ClearAll);
        assert_eq!(app.csr_list.len(), 1);
        assert_eq!(app.csr_index, 0);
        assert_eq!(app.csr_list[0].id, "");
    }

    #[test]
    fn clear_all_on_cms_collapses_to_single_default_entry() {
        let mut app = cms_app();
        app.cms_mut().id = "a".to_string();
        app.update(Message::AddRow);
        app.update(Message::ClearAll);
        assert_eq!(app.cms_list.len(), 1);
        assert_eq!(app.cms_index, 0);
        assert_eq!(app.cms_list[0].id, "");
    }
}
