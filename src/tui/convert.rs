//! Form-state -> config struct conversions with input validation.
//!
//! Each public `*_from_form` function takes a borrowed form-state struct from
//! [`crate::tui::app`] and produces the corresponding [`crate::config`] struct
//! that the existing generation / `write_*_config` pipeline already accepts.
//!
//! Validation happens at this boundary: required fields must be present, the
//! RSA key length (when a key type of RSA is selected) must be one of the
//! accepted values, revoked-cert serials must be valid hex, and blank optional
//! inputs collapse to `None`. Errors are returned as a user-readable [`String`]
//! that the TUI surfaces in its status slot; internally a typed [`ConvertError`]
//! is used and mapped to that string at the public boundary.

use std::fmt;

use num_bigint::BigUint;
use num_traits::Num;

use crate::config::{
    CertInfo, Certificate, Cms, Crl, Csr, CsrData, HashAlg, KeyType, Pkix, Reason, RevokedCert,
    Signer, SigningRequest, Usage,
};
use crate::tui::app::{
    CertForm, CmsForm, CrlForm, CsrForm, HASH_ALG_OPTIONS, KEY_TYPE_OPTIONS, REASON_OPTIONS,
    RSA_KEY_LENGTH_OPTIONS, RevokedRow, SignerState, USAGE_OPTIONS,
};

/// Typed conversion/validation error, mapped to a `String` at the public
/// boundary so the TUI can show a readable message in its status slot.
///
/// `Display` is implemented by hand rather than derived because the crate does
/// not depend on `thiserror`; the messages are user-facing.
#[derive(Debug, PartialEq, Eq)]
enum ConvertError {
    /// A required free-text field was left empty.
    Required(&'static str),
    /// A revoked-cert serial was not valid hexadecimal.
    InvalidSerial(String),
    /// A selected option index pointed outside its `*_OPTIONS` slice.
    BadIndex(&'static str),
    /// An optional signer had only one of its certificate / private-key paths
    /// filled in — signing needs both.
    PartialSigner,
}

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Required(field) => write!(f, "{field} is required"),
            Self::InvalidSerial(serial) => {
                write!(f, "revoked serial \"{serial}\" is not valid hex")
            }
            Self::BadIndex(field) => {
                write!(f, "internal: {field} selection index out of range")
            }
            Self::PartialSigner => write!(
                f,
                "signer requires both a certificate PEM and a private key PEM \
                 (one was left blank)"
            ),
        }
    }
}

impl std::error::Error for ConvertError {}

impl From<ConvertError> for String {
    fn from(err: ConvertError) -> Self {
        err.to_string()
    }
}

/// Builds a [`Certificate`] from the certificate form, validating required
/// fields and (for RSA) the key length.
///
/// # Errors
///
/// Returns a user-readable message when `id` or the common name is empty, when a
/// signer is half-specified, or when an enum selection index is out of range.
/// (RSA key length is chosen from a fixed selector, so it can never be invalid.)
pub fn cert_from_form(form: &CertForm) -> Result<Certificate, String> {
    Ok(cert_from_form_inner(form)?)
}

fn cert_from_form_inner(form: &CertForm) -> Result<Certificate, ConvertError> {
    let id = required("id", &form.id)?;
    let common_name = required("common name", &form.common_name)?;
    let keytype = key_type_at(form.key_type)?;
    let keylength = rsa_key_length(form.key_type, form.key_length)?;
    // A hash algorithm only applies to key types that sign over an external
    // hash (RSA / ECDSA). For Ed25519 and the PQC algorithms it is left unset
    // so it is omitted from a saved config.
    let hashalg = if keytype.uses_hash_alg() {
        Some(hash_alg_at(form.hash_alg)?)
    } else {
        None
    };

    Ok(Certificate {
        id,
        parent: optional(&form.parent),
        signer: signer_opt(&form.signer)?,
        ca: Some(form.ca),
        pkix: Pkix {
            commonname: common_name,
            country: form.country.trim().to_string(),
            organization: form.organization.trim().to_string(),
        },
        keytype,
        altnames: altnames(&form.altnames),
        hashalg,
        keylength,
        validto: optional(&form.valid_to),
        usage: usage(&form.usage),
    })
}

/// Builds [`CsrData`] from the CSR form.
///
/// In sign mode the form describes a [`SigningRequest`] (sign an existing CSR);
/// otherwise it describes a new [`Csr`] to generate. The returned `CsrData` has
/// exactly one populated vector matching the form's mode.
///
/// # Errors
///
/// Returns a user-readable message when required fields for the active mode are
/// missing, when a signer is half-specified, or when an enum selection index is
/// out of range. (RSA key length is a fixed selector and cannot be invalid.)
pub fn csr_from_form(form: &CsrForm) -> Result<CsrData, String> {
    Ok(csr_from_form_inner(form)?)
}

fn csr_from_form_inner(form: &CsrForm) -> Result<CsrData, ConvertError> {
    if form.sign_mode {
        let csr_pem_file = required("CSR PEM file", &form.csr_pem_file)?;
        let signer = signer_required(&form.signer)?;
        let to_sign = SigningRequest {
            csr_pem_file,
            signer,
            validto: optional(&form.valid_to),
            ca: Some(form.ca),
        };
        return Ok(CsrData {
            csrs: Vec::new(),
            to_sign: vec![to_sign],
        });
    }

    let id = required("id", &form.id)?;
    let common_name = required("common name", &form.common_name)?;
    let keytype = key_type_at(form.key_type)?;
    let keylength = rsa_key_length(form.key_type, form.key_length)?;
    // A hash algorithm only applies to key types that sign over an external
    // hash (RSA / ECDSA). For Ed25519 and the PQC algorithms it is left unset
    // so it is omitted from a saved config.
    let hashalg = if keytype.uses_hash_alg() {
        Some(hash_alg_at(form.hash_alg)?)
    } else {
        None
    };

    let csr = Csr {
        id,
        pkix: Pkix {
            commonname: common_name,
            country: form.country.trim().to_string(),
            organization: form.organization.trim().to_string(),
        },
        keytype,
        altnames: altnames(&form.altnames),
        hashalg,
        keylength,
        usage: usage(&form.usage),
    };

    Ok(CsrData {
        csrs: vec![csr],
        to_sign: Vec::new(),
    })
}

/// Builds a [`Crl`] from the CRL form, parsing each revoked-cert serial from
/// hex (colon separators are stripped, mirroring the YAML reader).
///
/// # Errors
///
/// Returns a user-readable message when the CRL file or signer paths are empty,
/// a revoked serial is not valid hex, or a reason selection index is out of
/// range.
pub fn crl_from_form(form: &CrlForm) -> Result<Crl, String> {
    Ok(crl_from_form_inner(form)?)
}

fn crl_from_form_inner(form: &CrlForm) -> Result<Crl, ConvertError> {
    let crl_file = required("CRL file", &form.crl_file)?;
    let signer = signer_required(&form.signer)?;

    let mut revoked = Vec::with_capacity(form.revoked.len());
    for row in &form.revoked {
        let serial = parse_serial(&row.serial)?;
        let reason = reason_at(row.reason)?;
        revoked.push(RevokedCert {
            cert_info: CertInfo { serial, reason },
        });
    }

    Ok(Crl {
        crl_file,
        signer,
        revoked,
    })
}

/// Builds a [`Cms`] from the CMS form.
///
/// # Errors
///
/// Returns a user-readable message when `id` or the data file path is empty.
pub fn cms_from_form(form: &CmsForm) -> Result<Cms, String> {
    Ok(cms_from_form_inner(form)?)
}

fn cms_from_form_inner(form: &CmsForm) -> Result<Cms, ConvertError> {
    let id = required("id", &form.id)?;
    let data_file = required("data file", &form.data_file)?;

    Ok(Cms {
        id,
        signer: signer_opt(&form.signer)?,
        recipient: optional(&form.recipient),
        data_file,
        detached: Some(form.detached),
    })
}

// --- reverse mappers (config -> form) --------------------------------------

/// Builds a [`CertForm`] from a parsed [`Certificate`].
///
/// This is the inverse of [`cert_from_form`]: enum values become `*_OPTIONS`
/// indices, `Option<Vec<String>>` altnames become a comma-joined buffer,
/// `Option<Vec<Usage>>` becomes the parallel `Vec<bool>`, and `Option`/`None`
/// fields become empty buffers. The conversion is lossless for any config the
/// TUI itself produced (modulo the documented index-0 fallbacks).
///
/// UI cursor state (`field`, `usage_cursor`) is reset to its default `0`; it is
/// not part of the config and is therefore not preserved.
#[must_use]
pub fn cert_to_form(cert: &Certificate) -> CertForm {
    CertForm {
        id: cert.id.clone(),
        common_name: cert.pkix.commonname.clone(),
        country: cert.pkix.country.clone(),
        organization: cert.pkix.organization.clone(),
        key_type: key_type_index(&cert.keytype),
        key_length: key_length_index(cert.keylength),
        // For key types with no `hashalg` (Ed25519/PQC) the config value is
        // `None`; we fall back to index 0. That index is ignored on
        // regeneration for those key types, so this is harmless.
        hash_alg: cert.hashalg.as_ref().map(hash_alg_index).unwrap_or(0),
        usage: usage_flags(&cert.usage),
        usage_cursor: 0,
        altnames: altnames_buffer(&cert.altnames),
        ca: cert.ca.unwrap_or(false),
        valid_to: opt_buffer(&cert.validto),
        parent: opt_buffer(&cert.parent),
        signer: signer_state(&cert.signer),
        field: 0,
    }
}

/// Builds a generate-mode [`CsrForm`] from a parsed [`Csr`].
///
/// The inverse of the generate branch of [`csr_from_form`]: `sign_mode` is
/// `false` and the sign-mode-only fields (`csr_pem_file`, `signer`, `valid_to`,
/// `ca`) stay at their defaults.
#[must_use]
pub fn csr_to_form(csr: &Csr) -> CsrForm {
    CsrForm {
        id: csr.id.clone(),
        common_name: csr.pkix.commonname.clone(),
        country: csr.pkix.country.clone(),
        organization: csr.pkix.organization.clone(),
        key_type: key_type_index(&csr.keytype),
        key_length: key_length_index(csr.keylength),
        hash_alg: csr.hashalg.as_ref().map(hash_alg_index).unwrap_or(0),
        usage: usage_flags(&csr.usage),
        usage_cursor: 0,
        altnames: altnames_buffer(&csr.altnames),
        sign_mode: false,
        ..CsrForm::default()
    }
}

/// Builds a sign-mode [`CsrForm`] from a parsed [`SigningRequest`].
///
/// The inverse of the sign branch of [`csr_from_form`]: `sign_mode` is `true`
/// and the new-CSR-only fields (`id`, `pkix`, key type, usage, altnames) stay at
/// their defaults.
#[must_use]
pub fn signing_request_to_form(req: &SigningRequest) -> CsrForm {
    CsrForm {
        sign_mode: true,
        csr_pem_file: req.csr_pem_file.clone(),
        signer: signer_state_req(&req.signer),
        valid_to: opt_buffer(&req.validto),
        ca: req.ca.unwrap_or(false),
        ..CsrForm::default()
    }
}

/// Builds a [`CrlForm`] from a parsed [`Crl`].
///
/// The inverse of [`crl_from_form`]: each revoked-cert serial (`BigUint`) is
/// rendered back to lowercase hex via [`serial_hex`], and each reason becomes a
/// [`REASON_OPTIONS`] index. `selected_row` is `Some(0)` when there is at least
/// one revoked row, else `None`; `field` resets to `0`.
#[must_use]
pub fn crl_to_form(crl: &Crl) -> CrlForm {
    let revoked: Vec<RevokedRow> = crl
        .revoked
        .iter()
        .map(|entry| RevokedRow {
            serial: serial_hex(&entry.cert_info.serial),
            reason: reason_index(&entry.cert_info.reason),
        })
        .collect();
    let selected_row = if revoked.is_empty() { None } else { Some(0) };

    CrlForm {
        crl_file: crl.crl_file.clone(),
        signer: signer_state_req(&crl.signer),
        revoked,
        field: 0,
        selected_row,
    }
}

/// Builds a [`CmsForm`] from a parsed [`Cms`].
///
/// The inverse of [`cms_from_form`]: optional signer/recipient collapse to empty
/// buffers when unset and `detached` defaults to `false` when absent.
#[must_use]
pub fn cms_to_form(cms: &Cms) -> CmsForm {
    CmsForm {
        id: cms.id.clone(),
        data_file: cms.data_file.clone(),
        signer: signer_state(&cms.signer),
        recipient: opt_buffer(&cms.recipient),
        detached: cms.detached.unwrap_or(false),
        field: 0,
    }
}

// --- reverse helpers (config value -> form representation) ------------------

/// Resolves a [`KeyType`] back to its [`KEY_TYPE_OPTIONS`] index.
///
/// Falls back to index `0` for a value absent from the options slice (e.g. a PQC
/// key type when the `pqc` feature is off). This is a documented lossy fallback;
/// in practice the reader would reject an unknown variant before this point, so
/// it only triggers for a valid variant missing from the slice.
fn key_type_index(kt: &KeyType) -> usize {
    KEY_TYPE_OPTIONS.iter().position(|k| *k == *kt).unwrap_or(0) // documented lossy fallback
}

/// Resolves a [`HashAlg`] back to its [`HASH_ALG_OPTIONS`] index, falling back to
/// index `0` for an absent value (documented lossy fallback).
fn hash_alg_index(alg: &HashAlg) -> usize {
    HASH_ALG_OPTIONS
        .iter()
        .position(|a| *a == *alg)
        .unwrap_or(0) // documented lossy fallback
}

/// Resolves a [`Reason`] back to its [`REASON_OPTIONS`] index, falling back to
/// index `0` for an absent value (documented lossy fallback).
fn reason_index(reason: &Reason) -> usize {
    REASON_OPTIONS
        .iter()
        .position(|r| *r == *reason)
        .unwrap_or(0) // documented lossy fallback
}

/// Maps an optional config usage list back to the parallel `Vec<bool>` toggle
/// vector (one `bool` per [`USAGE_OPTIONS`] entry). `None` -> all `false`.
fn usage_flags(usage: &Option<Vec<Usage>>) -> Vec<bool> {
    let mut flags = vec![false; USAGE_OPTIONS.len()];
    if let Some(selected) = usage {
        for value in selected {
            if let Some(idx) = USAGE_OPTIONS.iter().position(|u| *u == *value) {
                flags[idx] = true;
            }
        }
    }
    flags
}

/// Joins an optional alt-names list into the comma-separated buffer the forward
/// [`altnames`] helper splits on. `None` -> empty string.
fn altnames_buffer(names: &Option<Vec<String>>) -> String {
    match names {
        Some(list) => list.join(", "),
        None => String::new(),
    }
}

/// Renders a serial back to lowercase hex, matching `serialize_serial` (so the
/// forward `parse_serial` round-trips it).
fn serial_hex(serial: &BigUint) -> String {
    serial.to_str_radix(16)
}

/// Maps an optional RSA key length back to its [`RSA_KEY_LENGTH_OPTIONS`] index
/// for the form selector; unknown or `None` lengths fall back to index 0.
fn key_length_index(length: Option<u32>) -> usize {
    length
        .and_then(|n| RSA_KEY_LENGTH_OPTIONS.iter().position(|&o| o == n))
        .unwrap_or(0)
}

/// Clones an optional string into a buffer; `None` -> empty string.
fn opt_buffer(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

/// Builds a [`SignerState`] from an optional [`Signer`]; `None` -> empty buffers
/// (the forward `signer_opt` maps empty/empty -> `None`, so this round-trips).
fn signer_state(signer: &Option<Signer>) -> SignerState {
    match signer {
        Some(s) => signer_state_req(s),
        None => SignerState::default(),
    }
}

/// Builds a [`SignerState`] from a required [`Signer`].
fn signer_state_req(signer: &Signer) -> SignerState {
    SignerState {
        cert_pem_file: signer.cert_pem_file.clone(),
        private_key_pem_file: signer.private_key_pem_file.clone(),
    }
}

// --- shared helpers --------------------------------------------------------

/// Trims `value` and requires it to be non-empty, returning the owned string.
fn required(field: &'static str, value: &str) -> Result<String, ConvertError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(ConvertError::Required(field))
    } else {
        Ok(trimmed.to_string())
    }
}

/// Maps a blank (whitespace-only) optional buffer to `None`, otherwise the
/// trimmed owned string.
fn optional(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Splits a comma-separated alt-names buffer into a trimmed, non-empty list.
/// Returns `None` when no alt-names are present.
fn altnames(buffer: &str) -> Option<Vec<String>> {
    let names: Vec<String> = buffer
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    if names.is_empty() { None } else { Some(names) }
}

/// Maps the parallel `usage` toggle vector to the selected [`Usage`] values.
/// Returns `None` when nothing is selected.
fn usage(flags: &[bool]) -> Option<Vec<Usage>> {
    let selected: Vec<Usage> = USAGE_OPTIONS
        .iter()
        .zip(flags.iter())
        .filter(|&(_, &on)| on)
        .map(|(usage, _)| usage.clone())
        .collect();
    if selected.is_empty() {
        None
    } else {
        Some(selected)
    }
}

/// Resolves a key-type selection index into its config [`KeyType`].
fn key_type_at(index: usize) -> Result<crate::config::KeyType, ConvertError> {
    KEY_TYPE_OPTIONS
        .get(index)
        .cloned()
        .ok_or(ConvertError::BadIndex("key type"))
}

/// Resolves a hash-algorithm selection index into its config `HashAlg`.
fn hash_alg_at(index: usize) -> Result<crate::config::HashAlg, ConvertError> {
    HASH_ALG_OPTIONS
        .get(index)
        .cloned()
        .ok_or(ConvertError::BadIndex("hash algorithm"))
}

/// Resolves a reason selection index into its config [`Reason`].
fn reason_at(index: usize) -> Result<Reason, ConvertError> {
    REASON_OPTIONS
        .get(index)
        .cloned()
        .ok_or(ConvertError::BadIndex("reason"))
}

/// Resolves the RSA key length from the selected option index. Returns `None`
/// for non-RSA key types (length is irrelevant); for RSA it maps the index into
/// [`RSA_KEY_LENGTH_OPTIONS`] (the selector guarantees a valid value, so no
/// parsing or validation error is possible).
fn rsa_key_length(key_type_index: usize, length_index: usize) -> Result<Option<u32>, ConvertError> {
    let key_type = key_type_at(key_type_index)?;
    if !key_type.uses_rsa_key_length() {
        return Ok(None);
    }
    let len = *RSA_KEY_LENGTH_OPTIONS
        .get(length_index)
        .unwrap_or(&RSA_KEY_LENGTH_OPTIONS[0]);
    Ok(Some(len))
}

/// Parses a revoked-cert serial from a hex buffer, stripping `:` separators
/// exactly like the YAML `deserialize_serial` does.
fn parse_serial(raw: &str) -> Result<BigUint, ConvertError> {
    let normalized = raw.replace(':', "");
    let normalized = normalized.trim();
    if normalized.is_empty() {
        return Err(ConvertError::Required("revoked serial"));
    }
    BigUint::from_str_radix(normalized, 16)
        .map_err(|_| ConvertError::InvalidSerial(raw.trim().to_string()))
}

/// Builds an optional [`Signer`] from a signer form sub-state. Returns `None`
/// when both paths are blank (the signer is unset).
/// Builds an *optional* [`Signer`]: `None` when both paths are blank, `Some`
/// when both are filled. A half-filled signer (only the certificate or only the
/// key) is rejected with [`ConvertError::PartialSigner`] so the user gets a
/// clear message instead of a later "No such file or directory" when signing
/// tries to open the empty path.
fn signer_opt(state: &SignerState) -> Result<Option<Signer>, ConvertError> {
    let cert = state.cert_pem_file.trim();
    let key = state.private_key_pem_file.trim();
    match (cert.is_empty(), key.is_empty()) {
        (true, true) => Ok(None),
        (false, false) => Ok(Some(Signer {
            cert_pem_file: cert.to_string(),
            private_key_pem_file: key.to_string(),
        })),
        _ => Err(ConvertError::PartialSigner),
    }
}

/// Builds a required [`Signer`], erroring if either path is blank.
fn signer_required(state: &SignerState) -> Result<Signer, ConvertError> {
    let cert_pem_file = required("signer certificate PEM file", &state.cert_pem_file)?;
    let private_key_pem_file =
        required("signer private key PEM file", &state.private_key_pem_file)?;
    Ok(Signer {
        cert_pem_file,
        private_key_pem_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeyType;

    fn filled_cert() -> CertForm {
        CertForm {
            id: "cert1".to_string(),
            common_name: "Example CN".to_string(),
            ..CertForm::default()
        }
    }

    /// Extracts the error message from a result whose `Ok` type does not
    /// implement `Debug` (e.g. `CsrData`), so `unwrap_err()` cannot be used.
    fn expect_err<T>(result: Result<T, String>) -> String {
        match result {
            Ok(_) => panic!("expected an error, got Ok"),
            Err(e) => e,
        }
    }

    mod cert_from_form {
        use super::*;

        #[test]
        fn builds_certificate_from_minimal_form() {
            let cert = cert_from_form(&filled_cert()).unwrap();
            assert_eq!(cert.id, "cert1");
            assert_eq!(cert.pkix.commonname, "Example CN");
            assert_eq!(cert.keytype, KeyType::RSA);
            assert_eq!(cert.ca, Some(false));
        }

        #[test]
        fn rejects_missing_id() {
            let mut form = filled_cert();
            form.id = "   ".to_string();
            let err = cert_from_form(&form).unwrap_err();
            assert!(err.contains("id is required"), "{err}");
        }

        #[test]
        fn rejects_missing_common_name() {
            let mut form = filled_cert();
            form.common_name = String::new();
            let err = cert_from_form(&form).unwrap_err();
            assert!(err.contains("common name is required"), "{err}");
        }

        #[test]
        fn rsa_key_length_resolves_from_selected_index() {
            let mut form = filled_cert(); // defaults to RSA
            // Default index 0 maps to the first option.
            assert_eq!(
                cert_from_form(&form).unwrap().keylength,
                Some(RSA_KEY_LENGTH_OPTIONS[0])
            );
            // Select the 4096 option by its index.
            form.key_length = RSA_KEY_LENGTH_OPTIONS
                .iter()
                .position(|&n| n == 4096)
                .unwrap();
            assert_eq!(cert_from_form(&form).unwrap().keylength, Some(4096));
        }

        #[test]
        fn key_length_is_none_for_non_rsa_key_type() {
            let mut form = filled_cert();
            // P256 sits at a non-zero index; the selected length index is ignored.
            form.key_type = KEY_TYPE_OPTIONS
                .iter()
                .position(|k| *k == KeyType::P256)
                .unwrap();
            form.key_length = 1; // would be 4096 for RSA, but must be ignored
            let cert = cert_from_form(&form).unwrap();
            assert_eq!(cert.keylength, None);
            assert_eq!(cert.keytype, KeyType::P256);
        }

        #[test]
        fn hashalg_set_for_rsa_but_none_for_ed25519() {
            // RSA signs over an external hash -> hashalg present.
            let mut form = filled_cert();
            form.key_type = KEY_TYPE_OPTIONS
                .iter()
                .position(|k| *k == KeyType::RSA)
                .unwrap();
            assert!(cert_from_form(&form).unwrap().hashalg.is_some());

            // Ed25519 has its hashing built in -> hashalg omitted (None).
            form.key_type = KEY_TYPE_OPTIONS
                .iter()
                .position(|k| *k == KeyType::Ed25519)
                .unwrap();
            assert_eq!(cert_from_form(&form).unwrap().hashalg, None);
        }

        #[test]
        fn splits_altnames_and_drops_blanks() {
            let mut form = filled_cert();
            form.altnames = " a.com , , b.com ".to_string();
            let cert = cert_from_form(&form).unwrap();
            assert_eq!(
                cert.altnames,
                Some(vec!["a.com".to_string(), "b.com".to_string()])
            );
        }

        #[test]
        fn empty_altnames_maps_to_none() {
            let mut form = filled_cert();
            form.altnames = "   ".to_string();
            let cert = cert_from_form(&form).unwrap();
            assert_eq!(cert.altnames, None);
        }

        #[test]
        fn selected_usage_flags_map_to_usage_list() {
            let mut form = filled_cert();
            form.usage = vec![false; USAGE_OPTIONS.len()];
            form.usage[0] = true;
            form.usage[2] = true;
            let cert = cert_from_form(&form).unwrap();
            let selected = cert.usage.unwrap();
            assert_eq!(selected.len(), 2);
        }

        #[test]
        fn no_usage_selected_maps_to_none() {
            let cert = cert_from_form(&filled_cert()).unwrap();
            assert!(cert.usage.is_none());
        }

        #[test]
        fn blank_optional_fields_map_to_none() {
            let cert = cert_from_form(&filled_cert()).unwrap();
            assert!(cert.parent.is_none());
            assert!(cert.signer.is_none());
            assert!(cert.validto.is_none());
        }

        #[test]
        fn signer_populated_when_provided() {
            let mut form = filled_cert();
            form.signer.cert_pem_file = "c.pem".to_string();
            form.signer.private_key_pem_file = "k.pem".to_string();
            let cert = cert_from_form(&form).unwrap();
            let signer = cert.signer.unwrap();
            assert_eq!(signer.cert_pem_file, "c.pem");
            assert_eq!(signer.private_key_pem_file, "k.pem");
        }
    }

    mod csr_from_form {
        use super::*;

        fn filled_csr() -> CsrForm {
            CsrForm {
                id: "csr1".to_string(),
                common_name: "Example CN".to_string(),
                ..CsrForm::default()
            }
        }

        #[test]
        fn builds_new_csr_in_generate_mode() {
            let data = csr_from_form(&filled_csr()).unwrap();
            assert_eq!(data.csrs.len(), 1);
            assert!(data.to_sign.is_empty());
            assert_eq!(data.csrs[0].id, "csr1");
        }

        #[test]
        fn hashalg_omitted_for_ed25519() {
            let mut form = filled_csr();
            form.key_type = KEY_TYPE_OPTIONS
                .iter()
                .position(|k| *k == KeyType::Ed25519)
                .unwrap();
            assert_eq!(csr_from_form(&form).unwrap().csrs[0].hashalg, None);
        }

        #[test]
        fn builds_signing_request_in_sign_mode() {
            let mut form = filled_csr();
            form.sign_mode = true;
            form.csr_pem_file = "req.pem".to_string();
            form.signer.cert_pem_file = "c.pem".to_string();
            form.signer.private_key_pem_file = "k.pem".to_string();
            form.valid_to = "2030-01-01".to_string();
            form.ca = true;
            let data = csr_from_form(&form).unwrap();
            assert!(data.csrs.is_empty());
            assert_eq!(data.to_sign.len(), 1);
            let req = &data.to_sign[0];
            assert_eq!(req.csr_pem_file, "req.pem");
            assert_eq!(req.validto, Some("2030-01-01".to_string()));
            assert_eq!(req.ca, Some(true));
            assert_eq!(req.signer.cert_pem_file, "c.pem");
        }

        #[test]
        fn sign_mode_requires_csr_pem_file() {
            let mut form = filled_csr();
            form.sign_mode = true;
            form.signer.cert_pem_file = "c.pem".to_string();
            form.signer.private_key_pem_file = "k.pem".to_string();
            // `CsrData` has no `Debug`, so extract the error via `match` rather
            // than `unwrap_err()`.
            let err = expect_err(csr_from_form(&form));
            assert!(err.contains("CSR PEM file is required"), "{err}");
        }

        #[test]
        fn sign_mode_requires_signer() {
            let mut form = filled_csr();
            form.sign_mode = true;
            form.csr_pem_file = "req.pem".to_string();
            let err = expect_err(csr_from_form(&form));
            assert!(err.contains("signer"), "{err}");
        }

        #[test]
        fn generate_mode_requires_id() {
            let mut form = filled_csr();
            form.id = String::new();
            let err = expect_err(csr_from_form(&form));
            assert!(err.contains("id is required"), "{err}");
        }
    }

    mod crl_from_form {
        use super::*;

        fn filled_crl() -> CrlForm {
            CrlForm {
                crl_file: "crl.pem".to_string(),
                signer: SignerState {
                    cert_pem_file: "c.pem".to_string(),
                    private_key_pem_file: "k.pem".to_string(),
                },
                revoked: Vec::new(),
                field: 0,
                selected_row: None,
            }
        }

        #[test]
        fn builds_crl_with_no_revoked_entries() {
            let crl = crl_from_form(&filled_crl()).unwrap();
            assert_eq!(crl.crl_file, "crl.pem");
            assert!(crl.revoked.is_empty());
        }

        #[test]
        fn parses_serial_with_colon_separators() {
            let mut form = filled_crl();
            form.revoked.push(RevokedRow {
                serial: "20:4a:77:d3".to_string(),
                reason: 0,
            });
            let crl = crl_from_form(&form).unwrap();
            assert_eq!(crl.revoked.len(), 1);
            let expected = BigUint::from_str_radix("204a77d3", 16).unwrap();
            assert_eq!(crl.revoked[0].cert_info.serial, expected);
        }

        #[test]
        fn parses_plain_hex_serial() {
            let mut form = filled_crl();
            form.revoked.push(RevokedRow {
                serial: "224a77d3".to_string(),
                reason: 1,
            });
            let crl = crl_from_form(&form).unwrap();
            let expected = BigUint::from_str_radix("224a77d3", 16).unwrap();
            assert_eq!(crl.revoked[0].cert_info.serial, expected);
        }

        #[test]
        fn rejects_invalid_hex_serial() {
            let mut form = filled_crl();
            form.revoked.push(RevokedRow {
                serial: "xyz".to_string(),
                reason: 0,
            });
            let err = crl_from_form(&form).unwrap_err();
            assert!(err.contains("not valid hex"), "{err}");
        }

        #[test]
        fn rejects_empty_serial() {
            let mut form = filled_crl();
            form.revoked.push(RevokedRow {
                serial: "  ".to_string(),
                reason: 0,
            });
            let err = crl_from_form(&form).unwrap_err();
            assert!(err.contains("required"), "{err}");
        }

        #[test]
        fn rejects_missing_crl_file() {
            let mut form = filled_crl();
            form.crl_file = String::new();
            let err = crl_from_form(&form).unwrap_err();
            assert!(err.contains("CRL file is required"), "{err}");
        }

        #[test]
        fn rejects_missing_signer() {
            let mut form = filled_crl();
            form.signer.private_key_pem_file = String::new();
            let err = crl_from_form(&form).unwrap_err();
            assert!(err.contains("signer"), "{err}");
        }
    }

    mod cms_from_form {
        use super::*;

        fn filled_cms() -> CmsForm {
            CmsForm {
                id: "cms1".to_string(),
                data_file: "msg.txt".to_string(),
                signer: SignerState::default(),
                recipient: String::new(),
                detached: false,
                field: 0,
            }
        }

        #[test]
        fn builds_cms_from_minimal_form() {
            let cms = cms_from_form(&filled_cms()).unwrap();
            assert_eq!(cms.id, "cms1");
            assert_eq!(cms.data_file, "msg.txt");
            assert!(cms.signer.is_none());
            assert!(cms.recipient.is_none());
            assert_eq!(cms.detached, Some(false));
        }

        #[test]
        fn rejects_missing_id() {
            let mut form = filled_cms();
            form.id = String::new();
            let err = cms_from_form(&form).unwrap_err();
            assert!(err.contains("id is required"), "{err}");
        }

        #[test]
        fn rejects_missing_data_file() {
            let mut form = filled_cms();
            form.data_file = String::new();
            let err = cms_from_form(&form).unwrap_err();
            assert!(err.contains("data file is required"), "{err}");
        }

        #[test]
        fn populates_optional_signer_and_recipient() {
            let mut form = filled_cms();
            form.recipient = "rcpt.pem".to_string();
            form.signer.cert_pem_file = "c.pem".to_string();
            form.signer.private_key_pem_file = "k.pem".to_string();
            let cms = cms_from_form(&form).unwrap();
            assert_eq!(cms.recipient, Some("rcpt.pem".to_string()));
            assert!(cms.signer.is_some());
        }

        #[test]
        fn rejects_signer_with_cert_but_no_key() {
            let mut form = filled_cms();
            form.signer.cert_pem_file = "c.pem".to_string();
            // key left blank
            let err = cms_from_form(&form).unwrap_err();
            assert!(
                err.contains("signer requires both"),
                "a cert-only signer must be rejected with a clear message, got: {err}"
            );
        }

        #[test]
        fn rejects_signer_with_key_but_no_cert() {
            let mut form = filled_cms();
            form.signer.private_key_pem_file = "k.pem".to_string();
            // cert left blank
            let err = cms_from_form(&form).unwrap_err();
            assert!(err.contains("signer requires both"), "{err}");
        }
    }

    // --- reverse mappers (config -> form) ----------------------------------

    mod reverse_helpers {
        use super::*;
        use crate::config::Reason;

        #[test]
        fn usage_flags_sets_exactly_present_indices() {
            // Setup: select serverauth (idx 0) and certsign (idx 2).
            let usage = Some(vec![Usage::serverauth, Usage::certsign]);

            // Invoke
            let flags = usage_flags(&usage);

            // Expect: exactly those indices true.
            let mut expected = vec![false; USAGE_OPTIONS.len()];
            expected[0] = true;
            expected[2] = true;
            assert_eq!(flags, expected);
        }

        #[test]
        fn usage_flags_none_maps_to_all_false() {
            let flags = usage_flags(&None);
            assert_eq!(flags, vec![false; USAGE_OPTIONS.len()]);
        }

        #[test]
        fn altnames_buffer_joins_and_resplits_losslessly() {
            // Setup
            let names = Some(vec!["a.com".to_string(), "b.com".to_string()]);

            // Invoke
            let buffer = altnames_buffer(&names);

            // Expect: comma-space joined, and the forward helper re-splits it.
            assert_eq!(buffer, "a.com, b.com");
            assert_eq!(altnames(&buffer), names);
        }

        #[test]
        fn altnames_buffer_none_is_empty() {
            assert_eq!(altnames_buffer(&None), "");
        }

        #[test]
        fn serial_hex_is_lowercase_and_reparses() {
            // Setup
            let serial = BigUint::from_str_radix("204a77d3", 16).unwrap();

            // Invoke
            let hex = serial_hex(&serial);

            // Expect: lowercase hex that re-parses to the same value.
            assert_eq!(hex, "204a77d3");
            assert_eq!(parse_serial(&hex).unwrap(), serial);
        }

        #[test]
        fn reason_index_resolves_each_option() {
            assert_eq!(reason_index(&Reason::Unspecified), 0);
            assert_eq!(reason_index(&Reason::KeyCompromise), 1);
            assert_eq!(reason_index(&Reason::CaCompromise), 2);
        }
    }

    mod cert_round_trip {
        use super::*;

        /// A fully-populated RSA cert form to prove a lossless forward->reverse
        /// round-trip of every observable config-backed field.
        fn rich_cert() -> CertForm {
            let mut form = CertForm {
                id: "cert1".to_string(),
                common_name: "Example CN".to_string(),
                country: "SE".to_string(),
                organization: "Example Org".to_string(),
                altnames: "a.com, b.com".to_string(),
                ca: true,
                valid_to: "2030-01-01".to_string(),
                ..CertForm::default()
            };
            form.key_type = KEY_TYPE_OPTIONS
                .iter()
                .position(|k| *k == KeyType::RSA)
                .unwrap();
            form.key_length = RSA_KEY_LENGTH_OPTIONS
                .iter()
                .position(|&n| n == 4096)
                .unwrap();
            form.hash_alg = HASH_ALG_OPTIONS
                .iter()
                .position(|a| matches!(a, crate::config::HashAlg::SHA384))
                .unwrap();
            form.usage[0] = true;
            form.usage[2] = true;
            form.signer.cert_pem_file = "c.pem".to_string();
            form.signer.private_key_pem_file = "k.pem".to_string();
            form
        }

        #[test]
        fn rsa_cert_round_trips_observable_fields() {
            // Setup -> Invoke forward then reverse.
            let original = rich_cert();
            let cert = cert_from_form(&original).unwrap();
            let restored = cert_to_form(&cert);

            // Expect: every config-backed field survives.
            assert_eq!(restored.id, original.id);
            assert_eq!(restored.common_name, original.common_name);
            assert_eq!(restored.country, original.country);
            assert_eq!(restored.organization, original.organization);
            assert_eq!(restored.key_type, original.key_type);
            assert_eq!(restored.key_length, original.key_length);
            assert_eq!(restored.hash_alg, original.hash_alg);
            assert_eq!(restored.usage, original.usage);
            assert_eq!(restored.altnames, original.altnames);
            assert_eq!(restored.ca, original.ca);
            assert_eq!(restored.valid_to, original.valid_to);
            assert_eq!(restored.signer.cert_pem_file, original.signer.cert_pem_file);
            assert_eq!(
                restored.signer.private_key_pem_file,
                original.signer.private_key_pem_file
            );
        }

        #[test]
        fn ed25519_cert_has_no_hashalg_and_falls_back_to_index_zero() {
            // Setup: Ed25519 has its hashing built in -> config hashalg is None.
            let mut form = rich_cert();
            form.key_type = KEY_TYPE_OPTIONS
                .iter()
                .position(|k| *k == KeyType::Ed25519)
                .unwrap();

            // Invoke (no panic) forward then reverse.
            let cert = cert_from_form(&form).unwrap();
            assert_eq!(cert.hashalg, None);
            let restored = cert_to_form(&cert);

            // Expect: hashalg index defaults to 0 for the None case.
            assert_eq!(restored.hash_alg, 0);
            assert_eq!(restored.key_type, form.key_type);
        }

        #[test]
        fn empty_optionals_round_trip_to_empty_buffers() {
            let form = filled_cert();
            let cert = cert_from_form(&form).unwrap();
            let restored = cert_to_form(&cert);
            assert_eq!(restored.parent, "");
            assert_eq!(restored.valid_to, "");
            assert_eq!(restored.altnames, "");
            assert_eq!(restored.signer.cert_pem_file, "");
            assert_eq!(restored.signer.private_key_pem_file, "");
            assert_eq!(restored.usage, vec![false; USAGE_OPTIONS.len()]);
        }
    }

    mod csr_round_trip {
        use super::*;

        #[test]
        fn generate_mode_round_trips() {
            // Setup
            let mut original = CsrForm {
                id: "csr1".to_string(),
                common_name: "Example CN".to_string(),
                country: "SE".to_string(),
                organization: "Example Org".to_string(),
                altnames: "a.com, b.com".to_string(),
                sign_mode: false,
                ..CsrForm::default()
            };
            original.usage[1] = true;

            // Invoke: forward (one csr) then reverse.
            let data = csr_from_form(&original).unwrap();
            let restored = csr_to_form(&data.csrs[0]);

            // Expect
            assert!(!restored.sign_mode);
            assert_eq!(restored.id, original.id);
            assert_eq!(restored.common_name, original.common_name);
            assert_eq!(restored.key_type, original.key_type);
            assert_eq!(restored.usage, original.usage);
            assert_eq!(restored.altnames, original.altnames);
        }

        #[test]
        fn sign_mode_round_trips() {
            // Setup
            let original = CsrForm {
                sign_mode: true,
                csr_pem_file: "req.pem".to_string(),
                valid_to: "2030-01-01".to_string(),
                ca: true,
                signer: SignerState {
                    cert_pem_file: "c.pem".to_string(),
                    private_key_pem_file: "k.pem".to_string(),
                },
                ..CsrForm::default()
            };

            // Invoke: forward (one signing request) then reverse.
            let data = csr_from_form(&original).unwrap();
            let restored = signing_request_to_form(&data.to_sign[0]);

            // Expect
            assert!(restored.sign_mode);
            assert_eq!(restored.csr_pem_file, "req.pem");
            assert_eq!(restored.valid_to, "2030-01-01");
            assert!(restored.ca);
            assert_eq!(restored.signer.cert_pem_file, "c.pem");
            assert_eq!(restored.signer.private_key_pem_file, "k.pem");
        }
    }

    mod crl_round_trip {
        use super::*;

        #[test]
        fn round_trips_revoked_row_serial_and_reason() {
            // Setup: a CRL form with a colon-formatted serial.
            let original = CrlForm {
                crl_file: "crl.pem".to_string(),
                signer: SignerState {
                    cert_pem_file: "c.pem".to_string(),
                    private_key_pem_file: "k.pem".to_string(),
                },
                revoked: vec![RevokedRow {
                    serial: "20:4a:77:d3".to_string(),
                    reason: 1,
                }],
                field: 0,
                selected_row: None,
            };

            // Invoke: forward then reverse.
            let crl = crl_from_form(&original).unwrap();
            let restored = crl_to_form(&crl);

            // Expect: serial normalizes to lowercase hex that re-parses to the
            // same BigUint, reason index survives, selected_row becomes Some(0).
            assert_eq!(restored.crl_file, "crl.pem");
            assert_eq!(restored.signer.cert_pem_file, "c.pem");
            assert_eq!(restored.revoked.len(), 1);
            assert_eq!(restored.revoked[0].serial, "204a77d3");
            assert_eq!(restored.revoked[0].reason, 1);
            assert_eq!(restored.selected_row, Some(0));
            let expected = BigUint::from_str_radix("204a77d3", 16).unwrap();
            assert_eq!(parse_serial(&restored.revoked[0].serial).unwrap(), expected);
        }

        #[test]
        fn empty_revoked_list_has_no_selection() {
            let original = CrlForm {
                crl_file: "crl.pem".to_string(),
                signer: SignerState {
                    cert_pem_file: "c.pem".to_string(),
                    private_key_pem_file: "k.pem".to_string(),
                },
                revoked: Vec::new(),
                field: 0,
                selected_row: None,
            };
            let crl = crl_from_form(&original).unwrap();
            let restored = crl_to_form(&crl);
            assert!(restored.revoked.is_empty());
            assert_eq!(restored.selected_row, None);
        }
    }

    mod cms_round_trip {
        use super::*;

        #[test]
        fn round_trips_observable_fields() {
            // Setup
            let original = CmsForm {
                id: "cms1".to_string(),
                data_file: "msg.txt".to_string(),
                recipient: "rcpt.pem".to_string(),
                detached: true,
                signer: SignerState {
                    cert_pem_file: "c.pem".to_string(),
                    private_key_pem_file: "k.pem".to_string(),
                },
                field: 0,
            };

            // Invoke
            let cms = cms_from_form(&original).unwrap();
            let restored = cms_to_form(&cms);

            // Expect
            assert_eq!(restored.id, "cms1");
            assert_eq!(restored.data_file, "msg.txt");
            assert_eq!(restored.recipient, "rcpt.pem");
            assert!(restored.detached);
            assert_eq!(restored.signer.cert_pem_file, "c.pem");
            assert_eq!(restored.signer.private_key_pem_file, "k.pem");
        }

        #[test]
        fn empty_optionals_round_trip_to_empty_buffers() {
            let original = CmsForm {
                id: "cms1".to_string(),
                data_file: "msg.txt".to_string(),
                ..CmsForm::default()
            };
            let cms = cms_from_form(&original).unwrap();
            let restored = cms_to_form(&cms);
            assert_eq!(restored.recipient, "");
            assert_eq!(restored.signer.cert_pem_file, "");
            assert!(!restored.detached);
        }
    }
}
