//! Feature-level integration tests for the TUI boundary.
//!
//! This single file holds three groups of tests (organised as `mod` blocks so
//! the whole feature stays in one conflict-free file):
//!
//! 1. `round_trip` — `write_*_config` -> `read_*_config` symmetry for the four
//!    config structs. These run on the **default** build (config lives outside
//!    the `tui` feature) and protect the contract the TUI feeds into.
//! 2. `convert` — `cert_bar::tui::convert::*_from_form` happy/error paths. Gated
//!    behind `#[cfg(feature = "tui")]` because the form-state structs only exist
//!    under the `tui` feature.
//! 3. `generation` — structs shaped exactly as `convert.rs` emits them are
//!    accepted by the four generation entry points, writing into a `TempDir`.
//!    Also gated behind the `tui` feature so the default build skips them.
//!
//! All tests follow SIFER (Setup, Invoke, Find, Expect, Reset) and use
//! `result.unwrap()` / `result.unwrap_err()` per `.claude/rules/rust-testing-core.md`.

// ---------------------------------------------------------------------------
// Group 1: config round-trip (default build — no feature gate)
// ---------------------------------------------------------------------------

mod round_trip {
    use cert_bar::config::{
        CertInfo, Certificate, Cms, Crl, Csr, CsrData, HashAlg, KeyType, Pkix, Reason, RevokedCert,
        Signer, SigningRequest, Usage, read_certificate_config, read_cms_config, read_crl_config,
        read_csr_config, write_certificate_config, write_cms_config, write_crl_config,
        write_csr_config,
    };
    use num_bigint::BigUint;
    use num_traits::Num;
    use tempfile::TempDir;

    /// Builds a `TempDir` and a YAML path inside it for a round-trip.
    fn temp_yaml(name: &str) -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join(name);
        (dir, path)
    }

    #[test]
    fn certificate_config_round_trips_via_tempfile() {
        // Setup: two certs, one with all optionals populated, one all-None.
        let full = Certificate {
            id: "ca".to_string(),
            parent: Some("ca".to_string()),
            signer: Some(Signer {
                cert_pem_file: "s_cert.pem".to_string(),
                private_key_pem_file: "s_key.pem".to_string(),
            }),
            ca: Some(true),
            pkix: Pkix {
                commonname: "Root CA".to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
            },
            keytype: KeyType::P256,
            altnames: Some(vec!["a.com".to_string(), "b.com".to_string()]),
            hashalg: Some(HashAlg::SHA384),
            keylength: Some(4096),
            validto: Some("2031-12-31".to_string()),
            usage: Some(vec![Usage::certsign, Usage::crlsign]),
        };
        let bare = Certificate {
            id: "leaf".to_string(),
            parent: None,
            signer: None,
            ca: None,
            pkix: Pkix {
                commonname: "Leaf".to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
            },
            keytype: KeyType::Ed25519,
            altnames: None,
            hashalg: None,
            keylength: None,
            validto: None,
            usage: None,
        };

        let (_dir, path) = temp_yaml("certs.yaml");

        // Invoke: write then read back.
        write_certificate_config(vec![full.clone(), bare.clone()], &path).unwrap();
        let certs = read_certificate_config(&path).unwrap();

        // Find & Expect.
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].id, "ca");
        assert_eq!(certs[0].parent, Some("ca".to_string()));
        assert_eq!(certs[0].keytype, KeyType::P256);
        assert_eq!(certs[0].hashalg, Some(HashAlg::SHA384));
        assert_eq!(certs[0].keylength, Some(4096));
        assert_eq!(certs[0].usage.as_ref().unwrap().len(), 2);

        // All-optionals-None must come back as None, never Some("").
        assert_eq!(certs[1].id, "leaf");
        assert_eq!(certs[1].parent, None);
        assert_eq!(certs[1].signer, None);
        assert_eq!(certs[1].ca, None);
        assert_eq!(certs[1].altnames, None);
        assert_eq!(certs[1].hashalg, None);
        assert_eq!(certs[1].keylength, None);
        assert_eq!(certs[1].validto, None);
        assert!(certs[1].usage.is_none());
    }

    #[test]
    fn csr_config_round_trips_via_tempfile() {
        // Setup: one CSR (validto/ca N/A) + one signing request with optionals None.
        let csr = Csr {
            id: "csr1".to_string(),
            pkix: Pkix {
                commonname: "Example".to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
            },
            keytype: KeyType::P256,
            altnames: None,
            hashalg: Some(HashAlg::SHA256),
            keylength: None,
            usage: None,
        };
        let req = SigningRequest {
            csr_pem_file: "req.pem".to_string(),
            signer: Signer {
                cert_pem_file: "c.pem".to_string(),
                private_key_pem_file: "k.pem".to_string(),
            },
            validto: None,
            ca: None,
        };

        let (_dir, path) = temp_yaml("csrs.yaml");

        // Invoke.
        write_csr_config(
            CsrData {
                csrs: vec![csr.clone()],
                to_sign: vec![req.clone()],
            },
            &path,
        )
        .unwrap();
        let data = read_csr_config(&path).unwrap();

        // Expect — `SigningRequest: PartialEq`, and CSR-optional `None` symmetry.
        assert_eq!(data.csrs.len(), 1);
        assert_eq!(data.csrs[0].id, "csr1");
        assert_eq!(data.csrs[0].altnames, None);
        assert_eq!(data.csrs[0].keylength, None);
        assert_eq!(data.to_sign.len(), 1);
        assert_eq!(data.to_sign[0], req);
        assert_eq!(data.to_sign[0].validto, None);
        assert_eq!(data.to_sign[0].ca, None);
    }

    #[test]
    fn crl_config_round_trips_serial() {
        // Setup: two revoked rows, one entered colon-hex, one plain hex, plus a
        // tiny serial to guard the leading-zero / empty-hex regression.
        let colon_serial =
            BigUint::from_str_radix("204a77d33809ab2f6524c7cda6ae22e1ce1e7ad9", 16).unwrap();
        let plain_serial =
            BigUint::from_str_radix("224a77d33809ab2f6524c7cda6ae22e1ce1e7ad9", 16).unwrap();
        let one = BigUint::from(1u8);

        let crl = Crl {
            crl_file: "out_crl.pem".to_string(),
            signer: Signer {
                cert_pem_file: "c.pem".to_string(),
                private_key_pem_file: "k.pem".to_string(),
            },
            revoked: vec![
                RevokedCert {
                    cert_info: CertInfo {
                        serial: colon_serial.clone(),
                        reason: Reason::KeyCompromise,
                    },
                },
                RevokedCert {
                    cert_info: CertInfo {
                        serial: plain_serial.clone(),
                        reason: Reason::CaCompromise,
                    },
                },
                RevokedCert {
                    cert_info: CertInfo {
                        serial: one.clone(),
                        reason: Reason::Unspecified,
                    },
                },
            ],
        };

        let (_dir, path) = temp_yaml("crl.yaml");

        // Invoke.
        write_crl_config(crl, &path).unwrap();
        let data = read_crl_config(&path).unwrap();

        // Expect: serials survive as identical BigUints, crl_file preserved.
        assert_eq!(data.crl_file, "out_crl.pem");
        assert_eq!(data.revoked.len(), 3);
        assert_eq!(data.revoked[0].cert_info.serial, colon_serial);
        assert_eq!(data.revoked[1].cert_info.serial, plain_serial);
        assert_eq!(data.revoked[2].cert_info.serial, one);
    }

    #[test]
    fn crl_read_accepts_colon_hex_equals_plain() {
        // The colon and non-colon forms of the same serial must parse equal,
        // mirroring `deserialize_serial` (read-time) symmetry.
        let yaml = "\
crl_file: c.pem
signer:
  cert_pem_file: s_cert.pem
  private_key_pem_file: s_key.pem
revoked:
  - cert_info:
      serial: aa:bb:cc
      reason: KeyCompromise
  - cert_info:
      serial: aabbcc
      reason: KeyCompromise
";
        let (_dir, path) = temp_yaml("crl_colon.yaml");
        std::fs::write(&path, yaml).unwrap();

        let data = read_crl_config(&path).unwrap();
        assert_eq!(
            data.revoked[0].cert_info.serial,
            data.revoked[1].cert_info.serial
        );
        assert_eq!(
            data.revoked[0].cert_info.serial,
            BigUint::from_str_radix("aabbcc", 16).unwrap()
        );
    }

    #[test]
    fn crl_empty_revoked_round_trips() {
        // `#[serde(default)]` on `revoked` must accept and round-trip an empty list.
        let crl = Crl {
            crl_file: "empty_crl.pem".to_string(),
            signer: Signer {
                cert_pem_file: "c.pem".to_string(),
                private_key_pem_file: "k.pem".to_string(),
            },
            revoked: vec![],
        };
        let (_dir, path) = temp_yaml("crl_empty.yaml");
        write_crl_config(crl, &path).unwrap();
        let data = read_crl_config(&path).unwrap();
        assert_eq!(data.revoked.len(), 0);
    }

    #[test]
    fn cms_config_round_trips_via_tempfile() {
        // Setup: one encrypt entry (recipient, no signer) and one sign entry
        // (signer, detached Some(true), no recipient). Order must be preserved.
        let encrypt = Cms {
            id: "enc".to_string(),
            signer: None,
            recipient: Some("rcpt_cert.pem".to_string()),
            data_file: "msg.txt".to_string(),
            detached: None,
        };
        let sign = Cms {
            id: "sig".to_string(),
            signer: Some(Signer {
                cert_pem_file: "s_cert.pem".to_string(),
                private_key_pem_file: "s_key.pem".to_string(),
            }),
            recipient: None,
            data_file: "msg.txt".to_string(),
            detached: Some(true),
        };

        let (_dir, path) = temp_yaml("cms.yaml");

        // Invoke.
        write_cms_config(vec![encrypt.clone(), sign.clone()], &path).unwrap();
        let data = read_cms_config(&path).unwrap();

        // Expect: order + optional symmetry.
        assert_eq!(data.len(), 2);
        assert_eq!(data[0].id, "enc");
        assert_eq!(data[0].recipient, Some("rcpt_cert.pem".to_string()));
        assert_eq!(data[0].signer, None);
        assert_eq!(data[0].detached, None);

        assert_eq!(data[1].id, "sig");
        assert_eq!(data[1].recipient, None);
        assert!(data[1].signer.is_some());
        assert_eq!(data[1].detached, Some(true));
    }

    /// #6 — a full CA -> intermediate -> leaf list survives a write/read round
    /// trip with order and per-entry parent references preserved.
    #[test]
    fn multi_cert_config_round_trips_full_list() {
        // Setup: a three-tier chain with mixed optionals.
        let ca = Certificate {
            id: "rt-ca".to_string(),
            parent: None,
            signer: None,
            ca: Some(true),
            pkix: Pkix {
                commonname: "Root CA".to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
            },
            keytype: KeyType::Ed25519,
            altnames: None,
            hashalg: None,
            keylength: None,
            validto: None,
            usage: Some(vec![Usage::certsign]),
        };
        let intermediate = Certificate {
            id: "rt-int".to_string(),
            parent: Some("rt-ca".to_string()),
            signer: None,
            ca: Some(true),
            pkix: Pkix {
                commonname: "Intermediate".to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
            },
            keytype: KeyType::P256,
            altnames: Some(vec!["int.example".to_string()]),
            hashalg: Some(HashAlg::SHA256),
            keylength: None,
            validto: None,
            usage: Some(vec![Usage::certsign, Usage::crlsign]),
        };
        let leaf = Certificate {
            id: "rt-leaf".to_string(),
            parent: Some("rt-int".to_string()),
            signer: None,
            ca: Some(false),
            pkix: Pkix {
                commonname: "Leaf".to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
            },
            keytype: KeyType::RSA,
            altnames: None,
            hashalg: Some(HashAlg::SHA256),
            keylength: Some(2048),
            validto: None,
            usage: None,
        };

        let (_dir, path) = temp_yaml("chain.yaml");

        // Invoke.
        write_certificate_config(vec![ca.clone(), intermediate.clone(), leaf.clone()], &path)
            .unwrap();
        let certs = read_certificate_config(&path).unwrap();

        // Expect: length, order, parent references, key types preserved.
        assert_eq!(certs.len(), 3);
        assert_eq!(certs[0].id, "rt-ca");
        assert_eq!(certs[0].parent, None);
        assert_eq!(certs[1].id, "rt-int");
        assert_eq!(certs[1].parent, Some("rt-ca".to_string()));
        assert_eq!(certs[1].keytype, KeyType::P256);
        assert_eq!(certs[2].id, "rt-leaf");
        assert_eq!(certs[2].parent, Some("rt-int".to_string()));
        assert_eq!(certs[2].keytype, KeyType::RSA);
        assert_eq!(certs[2].keylength, Some(2048));
        assert!(certs[2].usage.is_none());
    }
}

// ---------------------------------------------------------------------------
// Group 1b: CMS error propagation (03-tui-polish #1 — default build)
//
// `cms::handle` must accumulate per-entry failures and return a combined `Err`
// that names each offending entry by its `id`, instead of swallowing failures
// into `Ok(())`. A successful run still returns `Ok(())` and writes the file. A
// mixed batch returns `Err` naming only the failing entry, while persisting the
// successful one. Driven via the public `cms::handle` with `tempfile` output.
// ---------------------------------------------------------------------------

mod cms_error_propagation {
    use cert_bar::config::{Certificate, Cms, HashAlg, KeyType, Pkix, Usage};
    use cert_bar::{certificate, cms};
    use std::path::Path;
    use tempfile::TempDir;

    fn pkix(cn: &str) -> Pkix {
        Pkix {
            commonname: cn.to_string(),
            country: "SE".to_string(),
            organization: "Org".to_string(),
        }
    }

    /// Writes a self-signed RSA recipient cert (encipherment usage) to disk and
    /// returns the cert PEM path — usable as a CMS encryption recipient.
    fn make_rsa_recipient(dir: &Path, id: &str) -> String {
        let cert = Certificate {
            id: id.to_string(),
            parent: Some(id.to_string()),
            signer: None,
            ca: Some(false),
            pkix: pkix(id),
            keytype: KeyType::RSA,
            altnames: None,
            hashalg: Some(HashAlg::SHA256),
            keylength: Some(2048),
            validto: None,
            usage: Some(vec![Usage::signature, Usage::encipherment]),
        };
        certificate::create(vec![cert], dir).unwrap();
        dir.join(format!("{id}_cert.pem"))
            .to_string_lossy()
            .into_owned()
    }

    /// Writes a self-signed P-256 cert to disk and returns the cert PEM path. A
    /// P-256 recipient cannot be used for RSA key-transport encryption, so
    /// `create_cms` rejects it — a deterministic per-entry failure.
    fn make_p256_cert(dir: &Path, id: &str) -> String {
        let cert = Certificate {
            id: id.to_string(),
            parent: Some(id.to_string()),
            signer: None,
            ca: Some(false),
            pkix: pkix(id),
            keytype: KeyType::P256,
            altnames: None,
            hashalg: Some(HashAlg::SHA256),
            keylength: None,
            validto: None,
            usage: Some(vec![Usage::signature, Usage::encipherment]),
        };
        certificate::create(vec![cert], dir).unwrap();
        dir.join(format!("{id}_cert.pem"))
            .to_string_lossy()
            .into_owned()
    }

    /// A CMS encrypt entry whose `data_file` does not exist — `data_to_sign` /
    /// `create_cms` fails reading the message data, so the entry fails.
    fn encrypt_entry(id: &str, recipient: String, data_file: &str) -> Cms {
        Cms {
            id: id.to_string(),
            signer: None,
            recipient: Some(recipient),
            data_file: data_file.to_string(),
            detached: None,
        }
    }

    #[test]
    fn handle_returns_err_naming_entry_when_data_file_missing() {
        // Setup: a valid RSA recipient but a data_file that does not exist.
        let dir = TempDir::new().unwrap();
        let recipient = make_rsa_recipient(dir.path(), "rcpt");
        let cfg = encrypt_entry(
            "missing-data",
            recipient,
            "/nonexistent/cert-bar-test-missing",
        );

        // Invoke & Expect: Err naming the offending entry by id.
        let err = cms::handle(vec![cfg], dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("missing-data"),
            "error must name the failing entry id: {err}"
        );
    }

    #[test]
    fn handle_returns_err_naming_entry_when_recipient_cannot_encrypt() {
        // Setup: a P-256 recipient (RSA-only encryption is enforced) + real data.
        let dir = TempDir::new().unwrap();
        let recipient = make_p256_cert(dir.path(), "ecrcpt");
        let data_file = dir.path().join("msg.txt");
        std::fs::write(&data_file, b"hello").unwrap();
        let cfg = encrypt_entry("ec-recipient", recipient, &data_file.to_string_lossy());

        // Invoke & Expect.
        let err = cms::handle(vec![cfg], dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("ec-recipient"),
            "error must name the failing entry id: {err}"
        );
    }

    #[test]
    fn handle_returns_ok_and_writes_file_on_success() {
        // Setup: a valid RSA recipient + a real data file.
        let dir = TempDir::new().unwrap();
        let recipient = make_rsa_recipient(dir.path(), "okrcpt");
        let data_file = dir.path().join("msg.txt");
        std::fs::write(&data_file, b"encrypt me").unwrap();
        let cfg = encrypt_entry("enc-ok", recipient, &data_file.to_string_lossy());

        // Invoke (prints Err on failure) & Expect: the encrypted file exists.
        cms::handle(vec![cfg], dir.path()).unwrap();
        assert!(
            dir.path().join("enc-ok.cms").exists(),
            "encrypted CMS file must be written on success"
        );
    }

    #[test]
    fn handle_accumulates_multiple_failing_entries() {
        // Setup: two entries that fail for different reasons.
        let dir = TempDir::new().unwrap();
        let rsa = make_rsa_recipient(dir.path(), "rsa");
        let p256 = make_p256_cert(dir.path(), "ec");
        let data_file = dir.path().join("msg.txt");
        std::fs::write(&data_file, b"data").unwrap();

        let alpha = encrypt_entry("alpha", rsa, "/nonexistent/cert-bar-alpha"); // missing data
        let beta = encrypt_entry("beta", p256, &data_file.to_string_lossy()); // bad recipient

        // Invoke & Expect: a single Err naming BOTH failing entries.
        let err = cms::handle(vec![alpha, beta], dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("alpha"), "must name alpha: {msg}");
        assert!(msg.contains("beta"), "must name beta: {msg}");
    }

    #[test]
    fn handle_reports_only_failing_entry_in_mixed_batch() {
        // Setup: one good encrypt entry + one bad (missing data file).
        let dir = TempDir::new().unwrap();
        let good_rcpt = make_rsa_recipient(dir.path(), "goodrcpt");
        let bad_rcpt = make_rsa_recipient(dir.path(), "badrcpt");
        let data_file = dir.path().join("msg.txt");
        std::fs::write(&data_file, b"good data").unwrap();

        let good = encrypt_entry("good", good_rcpt, &data_file.to_string_lossy());
        let bad = encrypt_entry("broken", bad_rcpt, "/nonexistent/cert-bar-broken");

        // Invoke & Expect: Err names the bad entry but not the good one; the good
        // entry's output is still persisted (partial success).
        let err = cms::handle(vec![good, bad], dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("broken"), "must name the failing entry: {msg}");
        assert!(
            !msg.contains("good"),
            "must not name the successful entry: {msg}"
        );
        assert!(
            dir.path().join("good.cms").exists(),
            "the successful entry's output must still be written"
        );
    }

    #[test]
    fn handle_err_message_is_nonempty_for_blank_id_entry() {
        // Edge: a failing entry with a blank id still yields a well-formed,
        // non-empty error (`: <error>`) and never panics.
        let dir = TempDir::new().unwrap();
        let recipient = make_rsa_recipient(dir.path(), "blankrcpt");
        let cfg = encrypt_entry("", recipient, "/nonexistent/cert-bar-blank");

        let err = cms::handle(vec![cfg], dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.trim().is_empty(), "blank-id error must be non-empty");
    }
}

// ---------------------------------------------------------------------------
// Group 1c: structural silence guard (03-tui-polish #1 — GREP, default build)
//
// `handle` runs in-process during the live TUI, so capturing process stdout /
// stderr from a unit test is brittle. Instead we enforce silence structurally:
// read each generate-path source file, truncate at the `#[cfg(test)]` marker,
// and assert the production region above it contains none of the four tokens
// that would corrupt the alternate screen or panic on the generate path.
// (The `#[cfg(test)]` modules below legitimately use `.unwrap()`/`panic!`.)
// ---------------------------------------------------------------------------

mod no_stdio_on_generate_path {
    /// Reads `path` and returns the production region: everything before the
    /// first `#[cfg(test)]` marker (the unit-test module).
    fn production_region(path: &str) -> String {
        let src =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
        match src.find("#[cfg(test)]") {
            Some(idx) => src[..idx].to_string(),
            None => src,
        }
    }

    /// Counts lines in the production region containing any of `tokens`.
    fn offending_lines(path: &str, tokens: &[&str]) -> Vec<String> {
        let region = production_region(path);
        let mut hits = Vec::new();
        for (lineno, line) in region.lines().enumerate() {
            for token in tokens {
                if line.contains(token) {
                    hits.push(format!("{path}:{}: {}", lineno + 1, line.trim()));
                }
            }
        }
        hits
    }

    /// Asserts the production region contains none of `tokens`.
    fn assert_absent(path: &str, tokens: &[&str]) {
        let hits = offending_lines(path, tokens);
        assert!(
            hits.is_empty(),
            "{path}: production generate path must not contain {tokens:?}:\n{}",
            hits.join("\n")
        );
    }

    /// The tokens that corrupt the alternate screen (stdout/stderr) or panic
    /// the live TUI via `.expect(...)`/`.unwrap()` on the generate path. These
    /// MUST be absent. `.unwrap()` is included now that the CMS signing
    /// sub-path propagates its errors as `Err` instead of unwinding.
    const STDIO_TOKENS: &[&str] = &["println!", "eprintln!", "panic!", ".expect(", ".unwrap()"];

    #[test]
    fn cms_generate_path_has_no_stdio_or_expect() {
        // developer-01's diagnosed scope: the `eprintln!`/`println!` and the
        // `.expect("failed to save cms file")` are gone and stay gone.
        assert_absent("src/cms.rs", STDIO_TOKENS);
    }

    #[test]
    fn certificate_generate_path_is_silent() {
        // Confirms `println!("\nAll certificates created:")` is gone for good.
        assert_absent(
            "src/certificate.rs",
            &["println!", "eprintln!", "panic!", ".expect(", ".unwrap()"],
        );
    }

    #[test]
    fn csr_generate_path_is_silent() {
        assert_absent(
            "src/csr.rs",
            &["println!", "eprintln!", "panic!", ".expect(", ".unwrap()"],
        );
    }

    #[test]
    fn crl_generate_path_is_silent() {
        assert_absent(
            "src/crl.rs",
            &["println!", "eprintln!", "panic!", ".expect(", ".unwrap()"],
        );
    }

    /// GAP CLOSED (developer-04): the plan's Issue 1 contract states the CMS
    /// generate path must "never panic". The signing sub-path
    /// (`DetectedKey::create_signed_data` / `create_pkcs7_signed_data`) used to
    /// contain 16 bare `.unwrap()` calls that would panic the live TUI on
    /// malformed signer input; they now propagate via `?`/`map_err` into
    /// `cms::builder::Error`. This guard runs in the default suite and
    /// `.unwrap()` is now folded into the strict `STDIO_TOKENS` list so the
    /// no-`.unwrap()` invariant on the CMS production path is enforced going
    /// forward.
    #[test]
    fn cms_generate_path_has_no_unwrap() {
        assert_absent("src/cms.rs", &[".unwrap()"]);
    }
}

// ---------------------------------------------------------------------------
// Group 2: form -> config conversion (gated behind `tui`)
//
// NOTE: The `*Form` structs in `cert_bar::tui::app` have all-`pub` fields and a
// `Default` impl, so they ARE constructible from this integration test — convert
// coverage is NOT blocked on form-state constructibility. We build form states
// directly here and assert against the real `*_from_form` signatures.
// ---------------------------------------------------------------------------

#[cfg(feature = "tui")]
mod convert {
    use cert_bar::config::{HashAlg, KeyType, Usage};
    use cert_bar::tui::app::{
        CertForm, CmsForm, CrlForm, CsrForm, HASH_ALG_OPTIONS, KEY_TYPE_OPTIONS, REASON_OPTIONS,
        RevokedRow, SignerState, USAGE_OPTIONS,
    };
    use cert_bar::tui::convert::{cert_from_form, cms_from_form, crl_from_form, csr_from_form};
    use num_bigint::BigUint;
    use num_traits::Num;

    /// Index of a key type in `KEY_TYPE_OPTIONS`.
    fn key_type_index(kt: KeyType) -> usize {
        KEY_TYPE_OPTIONS.iter().position(|k| *k == kt).unwrap()
    }

    /// Index of a hash alg in `HASH_ALG_OPTIONS`.
    fn hash_alg_index(h: HashAlg) -> usize {
        HASH_ALG_OPTIONS.iter().position(|x| *x == h).unwrap()
    }

    /// `CsrData` has no `Debug`, so `unwrap_err()` cannot be used on it; extract
    /// the error string via `match`.
    fn err_of<T>(result: Result<T, String>) -> String {
        match result {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(e) => e,
        }
    }

    mod certificate_form {
        use super::*;

        fn base() -> CertForm {
            CertForm {
                id: "cert1".to_string(),
                common_name: "Example CN".to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
                ..CertForm::default()
            }
        }

        #[test]
        fn test_cert_happy_path_ec() {
            // Setup: P256, SHA256, two usages, two altnames, ca toggled.
            let mut form = base();
            form.key_type = key_type_index(KeyType::P256);
            form.hash_alg = hash_alg_index(HashAlg::SHA256);
            form.usage = vec![false; USAGE_OPTIONS.len()];
            form.usage[0] = true; // serverauth
            form.usage[1] = true; // clientauth
            form.altnames = "a.com, b.com".to_string();
            form.ca = true;

            // Invoke.
            let cert = cert_from_form(&form).unwrap();

            // Expect.
            assert_eq!(cert.id, "cert1");
            assert_eq!(cert.pkix.commonname, "Example CN");
            assert_eq!(cert.keytype, KeyType::P256);
            assert_eq!(cert.hashalg, Some(HashAlg::SHA256));
            assert_eq!(cert.usage.as_ref().unwrap().len(), 2);
            assert_eq!(
                cert.altnames,
                Some(vec!["a.com".to_string(), "b.com".to_string()])
            );
            assert_eq!(cert.ca, Some(true));
        }

        #[test]
        fn test_cert_blank_optionals_become_none() {
            // altnames/validto/parent/signer left blank -> None.
            let cert = cert_from_form(&base()).unwrap();
            assert_eq!(cert.altnames, None);
            assert_eq!(cert.validto, None);
            assert_eq!(cert.parent, None);
            assert_eq!(cert.signer, None);
            assert!(cert.usage.is_none());
        }

        #[test]
        fn test_cert_rsa_keylength_2048() {
            let mut form = base();
            form.key_type = key_type_index(KeyType::RSA);
            form.key_length = "2048".to_string();
            let cert = cert_from_form(&form).unwrap();
            assert_eq!(cert.keytype, KeyType::RSA);
            assert_eq!(cert.keylength, Some(2048));
        }

        #[test]
        fn test_cert_rsa_keylength_4096() {
            let mut form = base();
            form.key_type = key_type_index(KeyType::RSA);
            form.key_length = "4096".to_string();
            let cert = cert_from_form(&form).unwrap();
            assert_eq!(cert.keylength, Some(4096));
        }

        #[test]
        fn test_cert_missing_id() {
            let mut form = base();
            form.id = "   ".to_string();
            let err = cert_from_form(&form).unwrap_err();
            assert!(err.contains("id is required"), "{err}");
        }

        #[test]
        fn test_cert_missing_common_name() {
            let mut form = base();
            form.common_name = String::new();
            let err = cert_from_form(&form).unwrap_err();
            assert!(err.contains("common name is required"), "{err}");
        }

        #[test]
        fn test_cert_rsa_invalid_keylength() {
            let mut form = base();
            form.key_type = key_type_index(KeyType::RSA);
            form.key_length = "3000".to_string();
            let err = cert_from_form(&form).unwrap_err();
            // Message names the allowed RSA lengths.
            assert!(err.contains("not supported"), "{err}");
            assert!(err.contains("2048") && err.contains("4096"), "{err}");
        }

        #[test]
        fn test_cert_rsa_nonnumeric_keylength() {
            let mut form = base();
            form.key_type = key_type_index(KeyType::RSA);
            form.key_length = "abc".to_string();
            // Must Err (parse failure), never panic.
            let err = cert_from_form(&form).unwrap_err();
            assert!(err.contains("must be a number"), "{err}");
        }

        #[test]
        fn test_cert_ec_ignores_keylength() {
            // P384 with a stray key length -> ignored (None per convert contract).
            let mut form = base();
            form.key_type = key_type_index(KeyType::P384);
            form.key_length = "9999".to_string();
            let cert = cert_from_form(&form).unwrap();
            assert_eq!(cert.keytype, KeyType::P384);
            assert_eq!(cert.keylength, None);
        }
    }

    mod csr_form {
        use super::*;

        fn base() -> CsrForm {
            CsrForm {
                id: "csr1".to_string(),
                common_name: "Example CN".to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
                ..CsrForm::default()
            }
        }

        #[test]
        fn test_csr_happy_path() {
            let mut form = base();
            form.key_type = key_type_index(KeyType::P256);
            form.hash_alg = hash_alg_index(HashAlg::SHA256);
            form.usage = vec![false; USAGE_OPTIONS.len()];
            form.usage[0] = true;

            let data = csr_from_form(&form).unwrap();
            assert_eq!(data.csrs.len(), 1);
            assert!(data.to_sign.is_empty());
            let csr = &data.csrs[0];
            assert_eq!(csr.id, "csr1");
            assert_eq!(csr.keytype, KeyType::P256);
            assert_eq!(csr.hashalg, Some(HashAlg::SHA256));
            assert_eq!(csr.usage.as_ref().unwrap().len(), 1);
        }

        #[test]
        fn test_csr_blank_optionals_none() {
            // altnames/usage/keylength blank -> None (hashalg is always set).
            let data = csr_from_form(&base()).unwrap();
            let csr = &data.csrs[0];
            assert_eq!(csr.altnames, None);
            assert!(csr.usage.is_none());
            assert_eq!(csr.keylength, None);
        }

        #[test]
        fn test_csr_missing_id() {
            let mut form = base();
            form.id = String::new();
            let err = err_of(csr_from_form(&form));
            assert!(err.contains("id is required"), "{err}");
        }

        #[test]
        fn test_signing_request_happy_path() {
            let mut form = base();
            form.sign_mode = true;
            form.csr_pem_file = "req.pem".to_string();
            form.signer = SignerState {
                cert_pem_file: "c.pem".to_string(),
                private_key_pem_file: "k.pem".to_string(),
            };
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
            assert_eq!(req.signer.private_key_pem_file, "k.pem");
        }

        #[test]
        fn test_signing_request_missing_csr_file() {
            let mut form = base();
            form.sign_mode = true;
            form.signer = SignerState {
                cert_pem_file: "c.pem".to_string(),
                private_key_pem_file: "k.pem".to_string(),
            };
            let err = err_of(csr_from_form(&form));
            assert!(err.contains("CSR PEM file is required"), "{err}");
        }

        #[test]
        fn test_signing_request_missing_signer_key() {
            let mut form = base();
            form.sign_mode = true;
            form.csr_pem_file = "req.pem".to_string();
            form.signer.cert_pem_file = "c.pem".to_string();
            // private key left blank.
            let err = err_of(csr_from_form(&form));
            assert!(err.contains("signer private key"), "{err}");
        }

        #[test]
        fn test_signing_request_blank_validto_none() {
            // validto blank -> None; ca unticked -> Some(false) (convert sets
            // `ca: Some(form.ca)` unconditionally).
            let mut form = base();
            form.sign_mode = true;
            form.csr_pem_file = "req.pem".to_string();
            form.signer = SignerState {
                cert_pem_file: "c.pem".to_string(),
                private_key_pem_file: "k.pem".to_string(),
            };
            form.ca = false;
            let data = csr_from_form(&form).unwrap();
            let req = &data.to_sign[0];
            assert_eq!(req.validto, None);
            assert_eq!(req.ca, Some(false));
        }
    }

    mod crl_form {
        use super::*;

        fn base() -> CrlForm {
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

        /// Index of a reason in `REASON_OPTIONS` (`Reason` has no `PartialEq`,
        /// so compare discriminants).
        fn reason_index(r: cert_bar::config::Reason) -> usize {
            REASON_OPTIONS
                .iter()
                .position(|x| std::mem::discriminant(x) == std::mem::discriminant(&r))
                .unwrap()
        }

        #[test]
        fn test_crl_happy_path() {
            let mut form = base();
            form.revoked.push(RevokedRow {
                serial: "204a77d3".to_string(),
                reason: reason_index(cert_bar::config::Reason::KeyCompromise),
            });
            let crl = crl_from_form(&form).unwrap();
            assert_eq!(crl.crl_file, "crl.pem");
            assert_eq!(crl.revoked.len(), 1);
            let expected = BigUint::from_str_radix("204a77d3", 16).unwrap();
            assert_eq!(crl.revoked[0].cert_info.serial, expected);
            assert!(matches!(
                crl.revoked[0].cert_info.reason,
                cert_bar::config::Reason::KeyCompromise
            ));
        }

        #[test]
        fn test_crl_serial_with_colons() {
            let mut form = base();
            form.revoked.push(RevokedRow {
                serial: "20:4a:77".to_string(),
                reason: 0,
            });
            let crl = crl_from_form(&form).unwrap();
            let expected = BigUint::from_str_radix("204a77", 16).unwrap();
            assert_eq!(crl.revoked[0].cert_info.serial, expected);
        }

        #[test]
        fn test_convert_rejects_bad_serial() {
            let mut form = base();
            form.revoked.push(RevokedRow {
                serial: "zzzz".to_string(),
                reason: 0,
            });
            // Must Err (invalid hex), never panic.
            let err = crl_from_form(&form).unwrap_err();
            assert!(err.contains("not valid hex"), "{err}");
        }

        #[test]
        fn test_crl_empty_serial() {
            let mut form = base();
            form.revoked.push(RevokedRow {
                serial: "  ".to_string(),
                reason: 0,
            });
            let err = crl_from_form(&form).unwrap_err();
            assert!(err.contains("required"), "{err}");
        }

        #[test]
        fn test_crl_missing_crl_file() {
            let mut form = base();
            form.crl_file = String::new();
            let err = crl_from_form(&form).unwrap_err();
            assert!(err.contains("CRL file is required"), "{err}");
        }

        #[test]
        fn test_crl_missing_signer() {
            let mut form = base();
            form.signer.cert_pem_file = String::new();
            let err = crl_from_form(&form).unwrap_err();
            assert!(err.contains("signer"), "{err}");
        }

        #[test]
        fn test_crl_no_revoked_rows() {
            // Documented contract (developer-06): convert allows zero revoked rows
            // and produces an empty `revoked` vec (matches `read_crl_config`
            // `#[serde(default)]`).
            let crl = crl_from_form(&base()).unwrap();
            assert!(crl.revoked.is_empty());
        }
    }

    mod cms_form {
        use super::*;

        fn base() -> CmsForm {
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
        fn test_cms_happy_path_encrypt() {
            let mut form = base();
            form.recipient = "rcpt.pem".to_string();
            // signer blank, detached off.
            let cms = cms_from_form(&form).unwrap();
            assert_eq!(cms.id, "cms1");
            assert_eq!(cms.recipient, Some("rcpt.pem".to_string()));
            assert_eq!(cms.signer, None);
            assert_eq!(cms.detached, Some(false));
        }

        #[test]
        fn test_cms_happy_path_sign_detached() {
            let mut form = base();
            form.signer = SignerState {
                cert_pem_file: "c.pem".to_string(),
                private_key_pem_file: "k.pem".to_string(),
            };
            form.detached = true;
            let cms = cms_from_form(&form).unwrap();
            assert!(cms.signer.is_some());
            assert_eq!(cms.recipient, None);
            assert_eq!(cms.detached, Some(true));
        }

        #[test]
        fn test_cms_blank_optionals_none() {
            // signer/recipient blank -> None; detached has no "unset" so it is
            // Some(false) when off (matches convert contract).
            let cms = cms_from_form(&base()).unwrap();
            assert_eq!(cms.signer, None);
            assert_eq!(cms.recipient, None);
            assert_eq!(cms.detached, Some(false));
        }

        #[test]
        fn test_cms_missing_id() {
            let mut form = base();
            form.id = String::new();
            let err = cms_from_form(&form).unwrap_err();
            assert!(err.contains("id is required"), "{err}");
        }

        #[test]
        fn test_cms_missing_data_file() {
            let mut form = base();
            form.data_file = String::new();
            let err = cms_from_form(&form).unwrap_err();
            assert!(err.contains("data file is required"), "{err}");
        }

        #[test]
        fn test_cms_partial_signer_is_rejected() {
            // A CMS signer is optional, but if provided it needs BOTH the cert
            // and the private key. A half-filled signer (cert set, key blank)
            // is now rejected with a clear message instead of silently building
            // a `Signer { key: "" }` that later fails with "No such file or
            // directory" when signing tries to open the empty path.
            let mut form = base();
            form.signer.cert_pem_file = "c.pem".to_string();
            let err = cms_from_form(&form).unwrap_err();
            assert!(err.contains("signer requires both"), "{err}");

            // The mirror case (key set, cert blank) is also rejected.
            let mut form = base();
            form.signer.private_key_pem_file = "k.pem".to_string();
            let err = cms_from_form(&form).unwrap_err();
            assert!(err.contains("signer requires both"), "{err}");
        }
    }

    /// Sanity: usage flag positions map to the canonical config enum, not a
    /// redefined list — guards against `USAGE_OPTIONS` drift.
    #[test]
    fn usage_options_are_config_enum() {
        assert!(matches!(USAGE_OPTIONS[0], Usage::serverauth));
    }

    // -----------------------------------------------------------------------
    // #6 — multi-certificate convert + per-entry error reporting.
    //
    // NOTE: the actual multi-cert convert helper (`certs_from_list`) is PRIVATE
    // to `src/tui/mod.rs` and is not reachable from this integration boundary
    // (the only public convert API is the single-entry `cert_from_form`). Its
    // id/index error-naming is covered by developer-04's `#[cfg(test)]` tests in
    // `mod.rs`. Here we exercise the same contract at the integration boundary by
    // converting a `Vec<CertForm>` entry-by-entry via the public `cert_from_form`
    // and asserting the offending entry is identifiable — mirroring the helper's
    // "id, or `entry N` when blank" naming so the integration tier independently
    // proves the behaviour the architect cares about.
    // -----------------------------------------------------------------------

    mod multi_cert {
        use super::*;

        /// Converts a list of forms, naming the offending entry on the first
        /// error: by its `id` when set, otherwise by 1-based position. Mirrors
        /// the private `certs_from_list` helper in `mod.rs`.
        fn convert_list(forms: &[CertForm]) -> Result<Vec<cert_bar::config::Certificate>, String> {
            let mut out = Vec::with_capacity(forms.len());
            for (n, form) in forms.iter().enumerate() {
                let cert = cert_from_form(form).map_err(|e| {
                    let who = if form.id.trim().is_empty() {
                        format!("entry {}", n + 1)
                    } else {
                        form.id.trim().to_string()
                    };
                    format!("{who}: {e}")
                })?;
                out.push(cert);
            }
            Ok(out)
        }

        fn entry(id: &str, cn: &str, parent: &str) -> CertForm {
            CertForm {
                id: id.to_string(),
                common_name: cn.to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
                parent: parent.to_string(),
                ..CertForm::default()
            }
        }

        #[test]
        fn multi_cert_convert_all_valid() {
            // Setup: a CA + a leaf referencing it by id.
            let forms = vec![entry("ca", "Root CA", ""), entry("leaf", "Leaf", "ca")];

            // Invoke.
            let certs = convert_list(&forms).unwrap();

            // Expect: both convert; ids and parent reference preserved.
            assert_eq!(certs.len(), 2);
            assert_eq!(certs[0].id, "ca");
            assert_eq!(certs[0].parent, None);
            assert_eq!(certs[1].id, "leaf");
            assert_eq!(certs[1].parent, Some("ca".to_string()));
        }

        #[test]
        fn multi_cert_convert_error_names_offending_id() {
            // Setup: valid CA, then a leaf WITH an id but a blank common name.
            let forms = vec![entry("ca", "Root CA", ""), entry("leaf", "", "ca")];

            // Invoke & Expect: the error names the offending entry by its id.
            let err = convert_list(&forms).unwrap_err();
            assert!(
                err.contains("leaf"),
                "error must name the offending id: {err}"
            );
            assert!(
                err.contains("common name is required"),
                "error must report the underlying cause: {err}"
            );
        }

        #[test]
        fn multi_cert_convert_error_uses_index_when_id_blank() {
            // Setup: valid CA, then a blank-id AND blank-CN entry (position 2).
            let forms = vec![entry("ca", "Root CA", ""), entry("", "", "")];

            // Invoke & Expect: with no id available, the offender is named by
            // 1-based position.
            let err = convert_list(&forms).unwrap_err();
            assert!(
                err.contains("entry 2"),
                "blank-id entry should be named by position: {err}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Group 3: generation acceptance (gated behind `tui`)
//
// Structs are built exactly as `convert.rs` emits them and fed to the four
// generation entry points with a `TempDir` output. Signer/CA/recipient PEM
// material is generated at test time (hermetic, no checked-in fixtures).
// ---------------------------------------------------------------------------

#[cfg(feature = "tui")]
mod generation {
    use cert_bar::config::{
        CertInfo, Certificate, Cms, Crl, Csr, HashAlg, KeyType, Pkix, Reason, RevokedCert, Signer,
        SigningRequest, Usage,
    };
    use cert_bar::{certificate, cms, crl, csr};
    use num_bigint::BigUint;
    use num_traits::Num;
    use std::path::Path;
    use tempfile::TempDir;

    /// Reference `cert_bar::tui` to prove the module is exported under the feature.
    #[allow(unused_imports)]
    use cert_bar::tui as _tui_smoke;

    fn pkix(cn: &str) -> Pkix {
        Pkix {
            commonname: cn.to_string(),
            country: "SE".to_string(),
            organization: "Org".to_string(),
        }
    }

    /// Generates a self-signed CA to disk and returns the `Signer` paths cert
    /// tooling references ({id}_cert.pem / {id}_pkey.pem, per cert_helper save).
    fn make_ca(dir: &Path, id: &str, usage: Vec<Usage>) -> Signer {
        let ca = Certificate {
            id: id.to_string(),
            parent: Some(id.to_string()),
            signer: None,
            ca: Some(true),
            pkix: pkix(id),
            keytype: KeyType::P256,
            altnames: None,
            hashalg: Some(HashAlg::SHA256),
            keylength: None,
            validto: None,
            usage: Some(usage),
        };
        certificate::create(vec![ca], dir).unwrap();
        Signer {
            cert_pem_file: dir.join(format!("{id}_cert.pem")).to_string_lossy().into(),
            private_key_pem_file: dir.join(format!("{id}_pkey.pem")).to_string_lossy().into(),
        }
    }

    #[test]
    fn test_certificate_create_accepts_tui_struct() {
        // Setup: self-signed P256 CA (parent == id) as convert would build it.
        let dir = TempDir::new().unwrap();
        let cert = Certificate {
            id: "tui-ca".to_string(),
            parent: Some("tui-ca".to_string()),
            signer: None,
            ca: Some(true),
            pkix: pkix("tui-ca"),
            keytype: KeyType::P256,
            altnames: None,
            hashalg: Some(HashAlg::SHA256),
            keylength: None,
            validto: None,
            usage: Some(vec![Usage::certsign]),
        };

        // Invoke & Expect.
        certificate::create(vec![cert], dir.path()).unwrap();
        assert!(dir.path().join("tui-ca_cert.pem").exists());
        assert!(dir.path().join("tui-ca_pkey.pem").exists());
    }

    #[test]
    fn test_certificate_create_rsa_4096_accepts() {
        // RSA + keylength 4096 exactly as convert would set it.
        let dir = TempDir::new().unwrap();
        let cert = Certificate {
            id: "rsa-ca".to_string(),
            parent: Some("rsa-ca".to_string()),
            signer: None,
            ca: Some(true),
            pkix: pkix("rsa-ca"),
            keytype: KeyType::RSA,
            altnames: None,
            hashalg: Some(HashAlg::SHA256),
            keylength: Some(4096),
            validto: None,
            usage: None,
        };
        certificate::create(vec![cert], dir.path()).unwrap();
        assert!(dir.path().join("rsa-ca_cert.pem").exists());
    }

    #[test]
    fn test_csr_create_accepts_tui_struct() {
        let dir = TempDir::new().unwrap();
        let req = Csr {
            id: "tui-csr".to_string(),
            pkix: pkix("tui-csr"),
            keytype: KeyType::P256,
            altnames: None,
            hashalg: Some(HashAlg::SHA256),
            keylength: None,
            usage: Some(vec![Usage::serverauth]),
        };
        csr::create_csr(vec![req], dir.path()).unwrap();
        assert!(dir.path().join("tui-csr_csr.pem").exists());
    }

    #[test]
    fn test_csr_create_ed25519_no_hashalg() {
        // Ed25519 with hashalg == None is allowed (digestless path).
        let dir = TempDir::new().unwrap();
        let req = Csr {
            id: "ed-csr".to_string(),
            pkix: pkix("ed-csr"),
            keytype: KeyType::Ed25519,
            altnames: None,
            hashalg: None,
            keylength: None,
            usage: None,
        };
        csr::create_csr(vec![req], dir.path()).unwrap();
        assert!(dir.path().join("ed-csr_csr.pem").exists());
    }

    #[test]
    fn test_csr_create_missing_hashalg_non_ed25519_errors() {
        // Documents that convert MUST set hashalg for non-Ed25519 CSRs; the
        // generation backend rejects a None hashalg here. Must Err, not panic.
        let dir = TempDir::new().unwrap();
        let req = Csr {
            id: "bad-csr".to_string(),
            pkix: pkix("bad-csr"),
            keytype: KeyType::P256,
            altnames: None,
            hashalg: None,
            keylength: None,
            usage: None,
        };
        let err = csr::create_csr(vec![req], dir.path()).unwrap_err();
        assert!(err.to_string().contains("Missing hash Alg"), "{err}");
    }

    #[test]
    fn test_sign_requests_accepts_tui_struct() {
        // Setup: generate a CA + a CSR to disk, then sign the CSR.
        let dir = TempDir::new().unwrap();
        let signer = make_ca(dir.path(), "signca", vec![Usage::certsign]);

        // Create a CSR to sign.
        let csr_cfg = Csr {
            id: "to-sign".to_string(),
            pkix: pkix("to-sign"),
            keytype: KeyType::P256,
            altnames: None,
            hashalg: Some(HashAlg::SHA256),
            keylength: None,
            usage: Some(vec![Usage::clientauth]),
        };
        csr::create_csr(vec![csr_cfg], dir.path()).unwrap();
        let csr_pem = dir.path().join("to-sign_csr.pem");
        assert!(csr_pem.exists());

        // Invoke: sign the request as convert would build it.
        let req = SigningRequest {
            csr_pem_file: csr_pem.to_string_lossy().into(),
            signer,
            validto: None,
            ca: Some(false),
        };
        csr::sign_requests(vec![req], dir.path()).unwrap();

        // Expect: signed cert written ({stem}_cert.pem).
        assert!(dir.path().join("to-sign_csr_cert.pem").exists());
    }

    #[test]
    fn test_crl_handle_accepts_tui_struct() {
        // Setup: a CA with certsign/crlsign usage, then a CRL with one revoked row.
        let dir = TempDir::new().unwrap();
        let signer = make_ca(dir.path(), "crlca", vec![Usage::certsign, Usage::crlsign]);

        let crl_file = dir.path().join("out_crl.pem");
        let crl_cfg = Crl {
            crl_file: crl_file.to_string_lossy().into(),
            signer,
            revoked: vec![RevokedCert {
                cert_info: CertInfo {
                    serial: BigUint::from_str_radix("1234567890abcdef", 16).unwrap(),
                    reason: Reason::KeyCompromise,
                },
            }],
        };

        // Invoke & Expect.
        crl::handle(crl_cfg, dir.path()).unwrap();
        assert!(crl_file.exists());
        let contents = std::fs::read_to_string(&crl_file).unwrap();
        assert!(contents.contains("BEGIN X509 CRL"));
    }

    /// Generates an RSA cert (encipherment/signature usage) to disk and returns
    /// the PEM paths.
    fn make_rsa_cert(dir: &Path, id: &str) -> (String, String) {
        let cert = Certificate {
            id: id.to_string(),
            parent: Some(id.to_string()),
            signer: None,
            ca: Some(false),
            pkix: pkix(id),
            keytype: KeyType::RSA,
            altnames: None,
            hashalg: Some(HashAlg::SHA256),
            keylength: Some(2048),
            validto: None,
            usage: Some(vec![Usage::signature, Usage::encipherment]),
        };
        certificate::create(vec![cert], dir).unwrap();
        (
            dir.join(format!("{id}_cert.pem")).to_string_lossy().into(),
            dir.join(format!("{id}_pkey.pem")).to_string_lossy().into(),
        )
    }

    #[test]
    fn test_cms_handle_encrypt_accepts_tui_struct() {
        // Setup: RSA recipient cert + a data file.
        let dir = TempDir::new().unwrap();
        let (rcpt_cert, _rcpt_key) = make_rsa_cert(dir.path(), "rcpt");
        let data_file = dir.path().join("msg.txt");
        std::fs::write(&data_file, b"hello cms").unwrap();

        let cms_cfg = Cms {
            id: "enc1".to_string(),
            signer: None,
            recipient: Some(rcpt_cert),
            data_file: data_file.to_string_lossy().into(),
            detached: Some(false),
        };

        // Invoke. `cms::handle` returns Ok unless signer *loading* fails, so
        // assert on the OUTPUT FILE existence (a silently-skipped entry is caught).
        cms::handle(vec![cms_cfg], dir.path()).unwrap();
        assert!(
            dir.path().join("enc1.cms").exists(),
            "encrypted CMS file must exist"
        );
    }

    #[test]
    fn test_cms_handle_sign_accepts_tui_struct() {
        // Setup: RSA signer + a data file; no recipient, detached off.
        let dir = TempDir::new().unwrap();
        let (cert_pem, key_pem) = make_rsa_cert(dir.path(), "signer");
        let data_file = dir.path().join("msg.txt");
        std::fs::write(&data_file, b"sign me").unwrap();

        let cms_cfg = Cms {
            id: "sig1".to_string(),
            signer: Some(Signer {
                cert_pem_file: cert_pem,
                private_key_pem_file: key_pem,
            }),
            recipient: None,
            data_file: data_file.to_string_lossy().into(),
            detached: Some(false),
        };

        cms::handle(vec![cms_cfg], dir.path()).unwrap();
        // Attached signature -> {id}.pkcs7.
        assert!(
            dir.path().join("sig1.pkcs7").exists(),
            "signed PKCS#7 file must exist"
        );
    }

    // -----------------------------------------------------------------------
    // #1/#2 — self-signed root generation regression (the headline bug).
    //
    // A standalone self-signed certificate has `parent: None` AND `signer: None`
    // — exactly what `convert::cert_from_form` emits for a default cert form with
    // only id + common name filled. Before the `create_inner` queue-seeding fix
    // this cert was never enqueued, so nothing was written and the call still
    // returned `Ok(())`. These tests prove the regression is closed by asserting
    // the cert + key PEMs are actually written into a `TempDir`.
    // -----------------------------------------------------------------------

    #[test]
    fn test_self_signed_root_no_parent_no_signer_writes_files() {
        // Setup: a self-signed root with NO parent and NO signer (the bug path),
        // shaped exactly as `cert_from_form` emits it.
        let dir = TempDir::new().unwrap();
        let cert = Certificate {
            id: "selfroot".to_string(),
            parent: None,
            signer: None,
            ca: Some(false),
            pkix: pkix("selfroot"),
            keytype: KeyType::P256,
            altnames: None,
            hashalg: Some(HashAlg::SHA256),
            keylength: None,
            validto: None,
            usage: None,
        };

        // Invoke.
        certificate::create(vec![cert], dir.path()).unwrap();

        // Expect: both PEMs exist and are non-empty (silent-no-output bug closed).
        let cert_pem = dir.path().join("selfroot_cert.pem");
        let key_pem = dir.path().join("selfroot_pkey.pem");
        assert!(cert_pem.exists(), "self-signed cert PEM must be written");
        assert!(key_pem.exists(), "self-signed key PEM must be written");
        assert!(
            std::fs::metadata(&cert_pem).unwrap().len() > 0,
            "cert PEM must be non-empty"
        );
    }

    #[test]
    fn test_self_signed_root_ed25519_writes_files() {
        // Same regression on the digestless (hashalg: None) Ed25519 path.
        let dir = TempDir::new().unwrap();
        let cert = Certificate {
            id: "edroot".to_string(),
            parent: None,
            signer: None,
            ca: Some(false),
            pkix: pkix("edroot"),
            keytype: KeyType::Ed25519,
            altnames: None,
            hashalg: None,
            keylength: None,
            validto: None,
            usage: None,
        };

        certificate::create(vec![cert], dir.path()).unwrap();

        assert!(dir.path().join("edroot_cert.pem").exists());
        assert!(dir.path().join("edroot_pkey.pem").exists());
    }

    #[test]
    fn test_self_signed_root_built_via_convert_from_form_writes_files() {
        // Drive the SAME regression through the real form -> convert -> generate
        // boundary: a default `CertForm` with only id + common name set must
        // produce a `parent: None, signer: None` cert and write files.
        use cert_bar::tui::app::CertForm;
        use cert_bar::tui::convert::cert_from_form;
        let dir = TempDir::new().unwrap();

        let form = CertForm {
            id: "formroot".to_string(),
            common_name: "Form Root".to_string(),
            country: "SE".to_string(),
            organization: "Org".to_string(),
            ..CertForm::default()
        };

        // Convert via the public form -> config boundary, then generate.
        let cert = cert_from_form(&form).unwrap();
        // Sanity: the default form must yield the bug-triggering shape.
        assert_eq!(cert.parent, None);
        assert_eq!(cert.signer, None);

        certificate::create(vec![cert], dir.path()).unwrap();
        assert!(dir.path().join("formroot_cert.pem").exists());
        assert!(dir.path().join("formroot_pkey.pem").exists());
    }

    // -----------------------------------------------------------------------
    // #6 — multi-certificate CA -> leaf chain generation.
    //
    // A CA (parent: None, signer: None) and a leaf referencing it by id
    // (parent: Some("<ca id>")) are passed to `create` in ONE call; `create_inner`
    // must resolve the dependency order and write all four PEMs regardless of the
    // input order.
    // -----------------------------------------------------------------------

    #[test]
    fn test_ca_then_leaf_chain_generates_all() {
        // Setup: CA + leaf (leaf.parent == ca.id), CA listed first.
        let dir = TempDir::new().unwrap();
        let ca = Certificate {
            id: "chainca".to_string(),
            parent: None,
            signer: None,
            ca: Some(true),
            pkix: pkix("chainca"),
            keytype: KeyType::Ed25519,
            altnames: None,
            hashalg: None,
            keylength: None,
            validto: None,
            usage: Some(vec![Usage::certsign]),
        };
        let leaf = Certificate {
            id: "chainleaf".to_string(),
            parent: Some("chainca".to_string()),
            signer: None,
            ca: Some(false),
            pkix: pkix("chainleaf"),
            keytype: KeyType::Ed25519,
            altnames: None,
            hashalg: None,
            keylength: None,
            validto: None,
            usage: Some(vec![Usage::clientauth]),
        };

        // Invoke: one call, both certs.
        certificate::create(vec![ca, leaf], dir.path()).unwrap();

        // Expect: all four PEMs exist.
        assert!(dir.path().join("chainca_cert.pem").exists());
        assert!(dir.path().join("chainca_pkey.pem").exists());
        assert!(dir.path().join("chainleaf_cert.pem").exists());
        assert!(dir.path().join("chainleaf_pkey.pem").exists());
    }

    #[test]
    fn test_three_tier_chain_generates_all_regardless_of_order() {
        // Setup: leaf -> intermediate -> ca, listed LEAF FIRST to prove the
        // dependency resolver orders correctly.
        let dir = TempDir::new().unwrap();
        let mk = |id: &str, parent: Option<&str>, ca: bool| Certificate {
            id: id.to_string(),
            parent: parent.map(str::to_string),
            signer: None,
            ca: Some(ca),
            pkix: pkix(id),
            keytype: KeyType::Ed25519,
            altnames: None,
            hashalg: None,
            keylength: None,
            validto: None,
            usage: if ca {
                Some(vec![Usage::certsign])
            } else {
                None
            },
        };
        let leaf = mk("t3leaf", Some("t3int"), false);
        let intermediate = mk("t3int", Some("t3ca"), true);
        let ca = mk("t3ca", None, true);

        // Invoke: deliberately unsorted input.
        certificate::create(vec![leaf, intermediate, ca], dir.path()).unwrap();

        // Expect: all six PEMs exist.
        for id in ["t3ca", "t3int", "t3leaf"] {
            assert!(
                dir.path().join(format!("{id}_cert.pem")).exists(),
                "{id} cert must exist"
            );
            assert!(
                dir.path().join(format!("{id}_pkey.pem")).exists(),
                "{id} key must exist"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Group 4: reducer behaviour at the integration boundary (gated behind `tui`)
//
// Drives the pure `App::update` reducer through the public lib API. These cover
// the funnels and overlays from the plan that are reachable from outside the
// crate: the Generate/Save confirm dialog (#1/#2/#3), the multi-cert Entries
// pane (#6), the clear-form/clear-all actions (#7), and the file-browser
// navigation/effect issuance (#4/#5). `map_key`/`run_effect`/render tests live
// in the crate's own `#[cfg(test)]` modules (developer/ui-tester) since the
// input mapper and effect runner are not part of the public API.
// ---------------------------------------------------------------------------

#[cfg(feature = "tui")]
mod reducer {
    use cert_bar::tui::app::{
        App, BrowsePurpose, BrowseTarget, CertForm, ConfirmAction, Dialog, Effect, FileEntry,
        Focus, Message, Screen,
    };

    /// An `App` parked on the Cert screen with the form focused.
    fn cert_app() -> App {
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Cert;
        app.focus = Focus::Form;
        app
    }

    /// Wraps a `(screen, field)` into the `FillField` purpose that replaced the
    /// old bare `BrowseTarget` on `Effect::ReadDir` / `set_browser_entries`.
    fn fill(screen: Screen, field: usize) -> BrowsePurpose {
        BrowsePurpose::FillField(BrowseTarget { screen, field })
    }

    // --- #1/#2/#3 — Generate / Save confirm dialog funnel ------------------

    mod generate_dialog {
        use super::*;

        #[test]
        fn g_from_cert_form_opens_generate_dialog() {
            // Setup: Cert form focused.
            let mut app = cert_app();

            // Invoke: `g` -> RequestGenerate.
            let effect = app.update(Message::RequestGenerate);

            // Expect: a Generate confirm dialog opens; no effect yet.
            assert_eq!(effect, None);
            assert_eq!(
                app.dialog,
                Some(Dialog::Confirm {
                    action: ConfirmAction::Generate,
                    path: "./out".to_string(),
                })
            );
        }

        #[test]
        fn confirm_in_generate_dialog_yields_effect_generate() {
            // Setup: dialog already open via RequestGenerate.
            let mut app = cert_app();
            app.update(Message::RequestGenerate);

            // Invoke: confirm.
            let effect = app.update(Message::Confirm);

            // Expect: Effect::Generate for the Cert screen with the path.
            assert_eq!(
                effect,
                Some(Effect::Generate {
                    screen: Screen::Cert,
                    path: "./out".to_string(),
                })
            );
            assert_eq!(app.dialog, None);
        }

        #[test]
        fn in_form_enter_opens_generate_dialog_then_confirm_generates() {
            // The in-form Enter path: first Enter opens the dialog, second Enter
            // confirms and yields the same effect shape as `g`.
            let mut app = cert_app();

            // First Enter: open the dialog.
            let first = app.update(Message::Confirm);
            assert_eq!(first, None);
            assert_eq!(
                app.dialog,
                Some(Dialog::Confirm {
                    action: ConfirmAction::Generate,
                    path: "./out".to_string(),
                })
            );

            // Second Enter: confirm -> Effect::Generate.
            let effect = app.update(Message::Confirm);
            assert_eq!(
                effect,
                Some(Effect::Generate {
                    screen: Screen::Cert,
                    path: "./out".to_string(),
                })
            );
        }

        #[test]
        fn g_on_menu_does_not_open_dialog() {
            // Setup: still on the menu.
            let mut app = App::new("./out".to_string());

            // Invoke & Expect: open_dialog early-returns on the menu.
            let effect = app.update(Message::RequestGenerate);
            assert_eq!(effect, None);
            assert_eq!(app.dialog, None);
        }

        #[test]
        fn save_request_opens_dialog_and_confirm_yields_saveyaml() {
            // Same funnel shape for Save YAML.
            let mut app = cert_app();
            app.update(Message::RequestSaveYaml);
            assert_eq!(
                app.dialog,
                Some(Dialog::Confirm {
                    action: ConfirmAction::SaveYaml,
                    path: "./out".to_string(),
                })
            );
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
        fn dialog_char_and_backspace_edit_path() {
            let mut app = cert_app();
            app.update(Message::RequestGenerate);
            app.update(Message::Backspace); // "./out" -> "./ou"
            app.update(Message::Char('x')); // "./ou" -> "./oux"
            assert_eq!(
                app.dialog,
                Some(Dialog::Confirm {
                    action: ConfirmAction::Generate,
                    path: "./oux".to_string(),
                })
            );
        }

        #[test]
        fn dialog_esc_cancels_without_effect() {
            let mut app = cert_app();
            app.update(Message::RequestGenerate);
            let effect = app.update(Message::Back);
            assert_eq!(effect, None);
            assert_eq!(app.dialog, None);
        }
    }

    // --- #6 — multi-cert Entries pane --------------------------------------

    mod entries {
        use super::*;

        #[test]
        fn tab_cycles_menu_entries_form_on_cert_screen() {
            // Setup: Cert screen, focus on the menu.
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cert;
            app.focus = Focus::Menu;

            // Invoke & Expect: Menu -> Entries -> Form -> Menu.
            app.update(Message::FocusNext);
            assert_eq!(app.focus, Focus::Entries);
            app.update(Message::FocusNext);
            assert_eq!(app.focus, Focus::Form);
            app.update(Message::FocusNext);
            assert_eq!(app.focus, Focus::Menu);
        }

        #[test]
        fn add_entry_appends_and_keeps_nonempty() {
            // Setup: Entries focused, one entry.
            let mut app = cert_app();
            app.focus = Focus::Entries;
            assert_eq!(app.cert_list.len(), 1);

            // Invoke.
            app.update(Message::AddRow);

            // Expect: a second default entry, selected.
            assert_eq!(app.cert_list.len(), 2);
            assert_eq!(app.cert_index, 1);
            assert_eq!(app.cert_list[1].id, CertForm::default().id);
        }

        #[test]
        fn delete_entry_never_empties_list() {
            // Setup: Entries focused, only one entry.
            let mut app = cert_app();
            app.focus = Focus::Entries;

            // Invoke.
            app.update(Message::DeleteRow);

            // Expect: the last entry is not removable.
            assert_eq!(app.cert_list.len(), 1);
        }

        #[test]
        fn delete_entry_removes_and_clamps_index() {
            // Setup: two entries, second selected.
            let mut app = cert_app();
            app.focus = Focus::Entries;
            app.update(Message::AddRow); // len 2, index 1

            // Invoke.
            app.update(Message::DeleteRow);

            // Expect: back to one entry, index clamped to 0.
            assert_eq!(app.cert_list.len(), 1);
            assert_eq!(app.cert_index, 0);
        }

        #[test]
        fn entries_up_down_selects_entry() {
            // Setup: three entries, index 0.
            let mut app = cert_app();
            app.focus = Focus::Entries;
            app.update(Message::AddRow);
            app.update(Message::AddRow);
            app.cert_index = 0;

            // Invoke: Down, Down, Up -> index 1.
            app.update(Message::Down);
            app.update(Message::Down);
            app.update(Message::Up);

            // Expect.
            assert_eq!(app.cert_index, 1);
        }

        #[test]
        fn enter_in_entries_moves_focus_to_form() {
            // Setup: two entries, second selected, Entries focused.
            let mut app = cert_app();
            app.focus = Focus::Entries;
            app.update(Message::AddRow); // index 1

            // Invoke.
            let effect = app.update(Message::Confirm);

            // Expect: focus moves to the form, selection unchanged, no dialog.
            assert_eq!(effect, None);
            assert_eq!(app.focus, Focus::Form);
            assert_eq!(app.cert_index, 1);
            assert_eq!(app.dialog, None);
        }

        #[test]
        fn form_edits_only_selected_entry() {
            // Setup: two entries, second selected, form focused, id field.
            let mut app = cert_app();
            app.update(Message::AddRow); // index 1
            app.focus = Focus::Form;
            app.cert_mut().field = 0; // id

            // Invoke: type into the id of entry 1.
            app.update(Message::Char('x'));
            app.update(Message::Char('y'));

            // Expect: only entry 1 changes.
            assert_eq!(app.cert_list[1].id, "xy");
            assert_eq!(app.cert_list[0].id, "");
        }

        #[test]
        fn add_delete_noop_off_cert_screen() {
            // Setup: CSR screen — Cert list must be untouched (CRL owns row
            // add/delete; CSR has no list).
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Csr;
            app.focus = Focus::Form;
            let before = app.cert_list.len();

            app.update(Message::AddRow);
            app.update(Message::DeleteRow);

            assert_eq!(app.cert_list.len(), before);
        }
    }

    // --- #7 — clear actions ------------------------------------------------

    mod clear {
        use super::*;

        #[test]
        fn clear_form_resets_current_cert_entry_only() {
            // Setup: two populated entries, second selected.
            let mut app = cert_app();
            app.update(Message::AddRow); // index 1
            app.cert_list[0].id = "keep".to_string();
            app.cert_list[0].common_name = "Keep".to_string();
            app.cert_list[1].id = "wipe".to_string();
            app.cert_list[1].common_name = "Wipe".to_string();

            // Invoke.
            app.update(Message::ClearForm);

            // Expect: only the selected entry resets; sibling preserved; len kept.
            assert_eq!(app.cert_list.len(), 2);
            assert_eq!(app.cert_list[1].id, "");
            assert_eq!(app.cert_list[1].common_name, "");
            assert_eq!(app.cert_list[0].id, "keep");
            assert_eq!(app.cert_list[0].common_name, "Keep");
        }

        #[test]
        fn clear_all_on_cert_collapses_to_single_empty_entry() {
            // Setup: three entries, last selected.
            let mut app = cert_app();
            app.update(Message::AddRow);
            app.update(Message::AddRow); // len 3, index 2
            app.cert_list[0].id = "a".to_string();

            // Invoke.
            app.update(Message::ClearAll);

            // Expect: collapsed to one default entry, index reset.
            assert_eq!(app.cert_list.len(), 1);
            assert_eq!(app.cert_index, 0);
            assert_eq!(app.cert_list[0].id, "");
        }

        #[test]
        fn clear_all_on_csr_equals_clear_form() {
            // Setup: CSR screen with a populated id.
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Csr;
            app.focus = Focus::Form;
            app.csr.id = "csr-x".to_string();
            app.csr.common_name = "CN".to_string();

            // Invoke: ClearAll on a single-form screen == ClearForm.
            app.update(Message::ClearAll);

            // Expect: the single form is reset.
            assert_eq!(app.csr.id, "");
            assert_eq!(app.csr.common_name, "");
        }

        #[test]
        fn clear_form_on_menu_is_noop() {
            // Setup: on the menu; menu_index is the only observable state.
            let mut app = App::new("./out".to_string());
            app.menu_index = 2;

            // Invoke & Expect: no panic, menu_index untouched.
            app.update(Message::ClearForm);
            assert_eq!(app.menu_index, 2);
        }
    }

    // --- #2 (03-tui-polish) — error-popup precedence / dismiss (INT) -------
    //
    // The reducer-visible error-popup behaviour, asserted through the public
    // `App` API (`set_error_popup`, `error_popup`, `update`). The `run_effect`
    // routing of a failed `Effect::Generate` into the popup is developer-03's
    // in-`mod.rs` test (private function) and is NOT duplicated here.

    mod error_popup {
        use super::*;
        use std::path::PathBuf;

        fn file(name: &str) -> FileEntry {
            FileEntry {
                name: name.to_string(),
                is_dir: false,
            }
        }

        #[test]
        fn set_error_popup_sets_popup_and_clears_status() {
            // Setup: a success status is showing in the footer.
            let mut app = cert_app();
            app.set_success("done");
            assert!(app.status.is_some());

            // Invoke: a failure raises the popup.
            app.set_error_popup("boom");

            // Expect: popup holds the message and the transient status is cleared.
            assert_eq!(app.error_popup.as_deref(), Some("boom"));
            assert!(app.status.is_none());
        }

        #[test]
        fn back_dismisses_popup_and_consumes_key() {
            // Setup: popup open on the Cert screen.
            let mut app = cert_app();
            app.set_error_popup("boom");

            // Invoke: Esc.
            let effect = app.update(Message::Back);

            // Expect: dismissed, no effect, key consumed (still on Cert screen).
            assert_eq!(effect, None);
            assert!(app.error_popup.is_none());
            assert_eq!(app.screen, Screen::Cert);
        }

        #[test]
        fn confirm_dismisses_popup_and_consumes_key() {
            // Setup.
            let mut app = cert_app();
            app.set_error_popup("boom");

            // Invoke: Enter.
            let effect = app.update(Message::Confirm);

            // Expect: dismissed, no effect.
            assert_eq!(effect, None);
            assert!(app.error_popup.is_none());
        }

        #[test]
        fn other_messages_are_swallowed_while_popup_open() {
            // Setup: popup open, id field focused and empty.
            let mut app = cert_app();
            app.cert_mut().field = 0; // id (text)
            app.set_error_popup("boom");

            // Invoke: navigation + typing must not leak to the form underneath.
            assert_eq!(app.update(Message::Down), None);
            assert_eq!(app.update(Message::Char('x')), None);

            // Expect: popup still open, the form is untouched.
            assert!(app.error_popup.is_some());
            assert_eq!(app.cert().id, "");
        }

        #[test]
        fn popup_takes_precedence_over_open_dialog() {
            // Setup: a confirm dialog is open, then a failure popup opens on top.
            let mut app = cert_app();
            app.update(Message::RequestGenerate);
            assert!(app.dialog.is_some());
            app.set_error_popup("boom");

            // Invoke: Enter is intercepted by the popup, not the dialog.
            let effect = app.update(Message::Confirm);

            // Expect: popup dismissed, the dialog underneath is untouched, and no
            // Effect::Generate was emitted (the popup ran first).
            assert_eq!(effect, None);
            assert!(app.error_popup.is_none());
            assert!(app.dialog.is_some(), "the dialog underneath is untouched");
        }

        #[test]
        fn popup_takes_precedence_over_open_browser() {
            // Setup: a browser is open, then a failure popup opens on top.
            let mut app = cert_app();
            app.cert_mut().field = 12; // signer.cert_pem_file (a path field)
            app.set_browser_entries(
                PathBuf::from("/tmp"),
                vec![file("a.pem")],
                fill(Screen::Cert, 12),
            );
            app.set_error_popup("boom");

            // Invoke: Down is intercepted by the popup, not the browser.
            let effect = app.update(Message::Down);

            // Expect: no-op (popup still open, browser selection unchanged).
            assert_eq!(effect, None);
            assert!(app.error_popup.is_some());
            assert_eq!(app.browser.as_ref().unwrap().selected, 0);

            // Back dismisses the popup; the browser underneath is still open.
            let effect = app.update(Message::Back);
            assert_eq!(effect, None);
            assert!(app.error_popup.is_none());
            assert!(app.browser.is_some(), "browser survives the popup dismiss");
        }

        #[test]
        fn empty_message_popup_still_dismisses_cleanly() {
            // Edge: an empty-string popup is still dismissable (no panic).
            let mut app = cert_app();
            app.set_error_popup("");
            assert_eq!(app.error_popup.as_deref(), Some(""));
            let effect = app.update(Message::Confirm);
            assert_eq!(effect, None);
            assert!(app.error_popup.is_none());
        }
    }

    // --- #3 (03-tui-polish) — field clearing (ClearField) (INT) ------------

    mod clear_field {
        use super::*;
        use std::path::PathBuf;

        fn file(name: &str) -> FileEntry {
            FileEntry {
                name: name.to_string(),
                is_dir: false,
            }
        }

        #[test]
        fn empties_focused_text_buffer() {
            // Setup: Cms screen, data_file field focused with a value.
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cms;
            app.focus = Focus::Form;
            app.cms.field = 1; // data_file (text/path)
            app.cms.data_file = "/tmp/x.bin".to_string();

            // Invoke.
            let effect = app.update(Message::ClearField);

            // Expect: buffer emptied, no effect.
            assert_eq!(effect, None);
            assert!(app.cms.data_file.is_empty());
        }

        #[test]
        fn noop_on_cycler_field() {
            // Setup: Cert screen, key_type cycler (index 4).
            let mut app = cert_app();
            app.cert_mut().field = 4;
            app.cert_mut().key_type = 2;

            // Invoke & Expect: cycler is left untouched, no panic.
            let effect = app.update(Message::ClearField);
            assert_eq!(effect, None);
            assert_eq!(app.cert().key_type, 2);
        }

        #[test]
        fn noop_on_toggle_field() {
            // Setup: Cert screen, ca toggle (index 8).
            let mut app = cert_app();
            app.cert_mut().field = 8;
            app.cert_mut().ca = true;

            // Invoke & Expect: toggle is left untouched.
            let effect = app.update(Message::ClearField);
            assert_eq!(effect, None);
            assert!(app.cert().ca);
        }

        #[test]
        fn noop_on_menu() {
            // Setup: parked on the menu with a non-default index.
            let mut app = App::new("./out".to_string());
            app.menu_index = 2;

            // Invoke & Expect: nothing changes.
            let effect = app.update(Message::ClearField);
            assert_eq!(effect, None);
            assert_eq!(app.menu_index, 2);
        }

        #[test]
        fn noop_on_entries_focus() {
            // Setup: Cert screen but focusing the entry list (not a text field).
            let mut app = cert_app();
            app.focus = Focus::Entries;
            app.cert_mut().id = "keep".to_string();

            // Invoke & Expect: the entry list focus has no active text field.
            let effect = app.update(Message::ClearField);
            assert_eq!(effect, None);
            assert_eq!(app.cert().id, "keep");
        }

        #[test]
        fn browser_clear_field_clears_target_and_closes() {
            // Setup: Cms screen, data_file populated, browser open targeting it.
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cms;
            app.focus = Focus::Form;
            app.cms.field = 1;
            app.cms.data_file = "/tmp/old".to_string();
            app.set_browser_entries(
                PathBuf::from("/tmp"),
                vec![file("a.bin")],
                fill(Screen::Cms, 1),
            );

            // Invoke.
            let effect = app.update(Message::ClearField);

            // Expect: target cleared, browser closed.
            assert_eq!(effect, None);
            assert!(app.cms.data_file.is_empty());
            assert!(app.browser.is_none());
        }

        #[test]
        fn browser_char_c_clears_target_and_closes() {
            // Same setup, dismissed via the `c` letter shortcut.
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cms;
            app.focus = Focus::Form;
            app.cms.field = 1;
            app.cms.data_file = "/tmp/old".to_string();
            app.set_browser_entries(
                PathBuf::from("/tmp"),
                vec![file("a.bin")],
                fill(Screen::Cms, 1),
            );

            let effect = app.update(Message::Char('c'));

            assert_eq!(effect, None);
            assert!(app.cms.data_file.is_empty());
            assert!(app.browser.is_none());
        }

        #[test]
        fn browser_clear_targets_only_the_target_field() {
            // Setup: Cms with both data_file and recipient populated; the browser
            // targets recipient (field 2). Only recipient must be cleared.
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cms;
            app.focus = Focus::Form;
            app.cms.data_file = "/tmp/data".to_string();
            app.cms.recipient = "/tmp/rcpt.pem".to_string();
            app.cms.field = 2; // recipient
            app.set_browser_entries(
                PathBuf::from("/tmp"),
                vec![file("rcpt.pem")],
                fill(Screen::Cms, 2),
            );

            // Invoke.
            app.update(Message::ClearField);

            // Expect: only the targeted recipient field is cleared.
            assert!(app.cms.recipient.is_empty());
            assert_eq!(app.cms.data_file, "/tmp/data");
            assert!(app.browser.is_none());
        }

        #[test]
        fn browser_other_keys_still_navigate() {
            // Regression: clear handling did not break browser navigation.
            let mut app = cert_app();
            app.cert_mut().field = 12;
            app.set_browser_entries(
                PathBuf::from("/tmp"),
                vec![file("a.pem"), file("b.pem")],
                fill(Screen::Cert, 12),
            );

            app.update(Message::Down);
            assert_eq!(app.browser.as_ref().unwrap().selected, 1);
        }
    }

    // --- #4/#5 — file browser ----------------------------------------------

    mod browser {
        use super::*;
        use std::path::PathBuf;

        /// Cert app focused on the signer-cert path field (index 12).
        fn app_on_cert_signer_field() -> App {
            let mut app = cert_app();
            app.cert_mut().field = 12; // signer.cert_pem_file (a path field)
            app
        }

        fn dir_entry(name: &str) -> FileEntry {
            FileEntry {
                name: name.to_string(),
                is_dir: true,
            }
        }
        fn file_entry(name: &str) -> FileEntry {
            FileEntry {
                name: name.to_string(),
                is_dir: false,
            }
        }

        #[test]
        fn open_browser_on_path_field_issues_readdir() {
            // Setup: focused on a path field, browser closed.
            let mut app = app_on_cert_signer_field();

            // Invoke.
            let effect = app.update(Message::OpenBrowser);

            // Expect: a ReadDir effect targeting this field (default "." dir).
            assert_eq!(
                effect,
                Some(Effect::ReadDir {
                    path: PathBuf::from("."),
                    purpose: fill(Screen::Cert, 12),
                })
            );
        }

        #[test]
        fn open_browser_on_non_path_field_is_noop() {
            // Setup: focused on the id field (not a path field).
            let mut app = cert_app();
            app.cert_mut().field = 0;

            // Invoke & Expect: no effect, no browser opened.
            let effect = app.update(Message::OpenBrowser);
            assert_eq!(effect, None);
            assert_eq!(app.browser, None);
        }

        /// Opens the browser and loads a listing into it.
        fn open_with_entries(dir: &str, entries: Vec<FileEntry>) -> App {
            let mut app = app_on_cert_signer_field();
            app.set_browser_entries(PathBuf::from(dir), entries, fill(Screen::Cert, 12));
            app
        }

        #[test]
        fn up_clamps_at_top() {
            let mut app = open_with_entries(
                "/tmp/somewhere",
                vec![dir_entry(".."), file_entry("a.pem"), file_entry("b.pem")],
            );
            app.update(Message::Up); // already at 0
            assert_eq!(app.browser.as_ref().unwrap().selected, 0);
        }

        #[test]
        fn down_then_up_moves_selection() {
            let mut app = open_with_entries(
                "/tmp/somewhere",
                vec![dir_entry(".."), file_entry("a.pem"), file_entry("b.pem")],
            );
            app.update(Message::Down);
            assert_eq!(app.browser.as_ref().unwrap().selected, 1);
            app.update(Message::Up);
            assert_eq!(app.browser.as_ref().unwrap().selected, 0);
        }

        #[test]
        fn down_clamps_at_bottom() {
            let mut app =
                open_with_entries("/tmp/somewhere", vec![dir_entry(".."), file_entry("a.pem")]);
            app.update(Message::Down);
            app.update(Message::Down); // clamp at len-1 == 1
            assert_eq!(app.browser.as_ref().unwrap().selected, 1);
        }

        #[test]
        fn enter_on_dir_issues_readdir_for_that_dir() {
            // Setup: select a directory entry "ca".
            let mut app = open_with_entries(
                "/tmp/base",
                vec![dir_entry(".."), dir_entry("ca"), file_entry("x.pem")],
            );
            app.update(Message::Down); // select "ca"

            // Invoke.
            let effect = app.update(Message::Confirm);

            // Expect: a ReadDir for base/ca; browser still open.
            assert_eq!(
                effect,
                Some(Effect::ReadDir {
                    path: PathBuf::from("/tmp/base").join("ca"),
                    purpose: fill(Screen::Cert, 12),
                })
            );
            assert!(app.browser.is_some());
        }

        #[test]
        fn enter_on_file_writes_target_field_and_closes() {
            // Setup: select a file entry "root_cert.pem".
            let mut app = open_with_entries(
                "/tmp/base",
                vec![dir_entry(".."), file_entry("root_cert.pem")],
            );
            app.update(Message::Down); // select the file

            // Invoke.
            let effect = app.update(Message::Confirm);

            // Expect: full path written into the signer cert field; browser closed.
            assert_eq!(effect, None);
            assert_eq!(app.browser, None);
            let expected = PathBuf::from("/tmp/base")
                .join("root_cert.pem")
                .to_string_lossy()
                .into_owned();
            assert_eq!(app.cert().signer.cert_pem_file, expected);
        }

        #[test]
        fn esc_cancels_leaving_field_unchanged() {
            // Setup: the target field has a prior value.
            let mut app = app_on_cert_signer_field();
            app.cert_mut().signer.cert_pem_file = "prior.pem".to_string();
            app.set_browser_entries(
                PathBuf::from("/tmp/base"),
                vec![dir_entry(".."), file_entry("other.pem")],
                fill(Screen::Cert, 12),
            );

            // Invoke: Esc.
            let effect = app.update(Message::Back);

            // Expect: browser closed, field unchanged, app not quitting.
            assert_eq!(effect, None);
            assert_eq!(app.browser, None);
            assert_eq!(app.cert().signer.cert_pem_file, "prior.pem");
            assert!(!app.should_quit);
        }

        #[test]
        fn backspace_goes_up_one_level() {
            // Setup: browser in a non-root dir.
            let mut app = open_with_entries("/tmp/base/sub", vec![dir_entry("..")]);

            // Invoke.
            let effect = app.update(Message::Backspace);

            // Expect: a ReadDir for the parent dir.
            assert_eq!(
                effect,
                Some(Effect::ReadDir {
                    path: PathBuf::from("/tmp/base"),
                    purpose: fill(Screen::Cert, 12),
                })
            );
        }

        #[test]
        fn backspace_at_root_is_noop() {
            // Setup: browser at the filesystem root.
            let mut app = open_with_entries("/", vec![dir_entry("usr")]);

            // Invoke & Expect: no parent -> no effect; browser stays open.
            let effect = app.update(Message::Backspace);
            assert_eq!(effect, None);
            assert!(app.browser.is_some());
        }

        #[test]
        fn set_browser_entries_resets_selection_to_top() {
            // Setup: open with entries and move the selection down.
            let mut app = open_with_entries(
                "/tmp/base",
                vec![dir_entry(".."), file_entry("a"), file_entry("b")],
            );
            app.update(Message::Down);
            app.update(Message::Down);
            assert_eq!(app.browser.as_ref().unwrap().selected, 2);

            // Invoke: load a fresh (shorter) listing.
            let purpose = app.browser.as_ref().unwrap().purpose;
            app.set_browser_entries(
                PathBuf::from("/tmp/base/ca"),
                vec![dir_entry("..")],
                purpose,
            );

            // Expect: selection reset into range (top).
            assert_eq!(app.browser.as_ref().unwrap().selected, 0);
        }

        #[test]
        fn enter_on_file_writes_cms_data_file_target() {
            // Cross-form target (#5): a CMS data_file path field (index 1).
            let mut app = App::new("./out".to_string());
            app.screen = Screen::Cms;
            app.focus = Focus::Form;
            app.cms.field = 1; // data_file
            app.set_browser_entries(
                PathBuf::from("/tmp/data"),
                vec![dir_entry(".."), file_entry("msg.txt")],
                fill(Screen::Cms, 1),
            );
            app.update(Message::Down); // select the file
            app.update(Message::Confirm);

            let expected = PathBuf::from("/tmp/data")
                .join("msg.txt")
                .to_string_lossy()
                .into_owned();
            assert_eq!(app.cms.data_file, expected);
            assert_eq!(app.browser, None);
        }
    }
}

// ---------------------------------------------------------------------------
// Group 5: load path (04-load-config) — gated behind `tui`
//
// Exercises the *inverse* (read) path through the public API only:
//   `cert_bar::config::{read,write}_*_config` + `cert_bar::tui::convert::*_to_form`
//   + the forward `*_from_form` + the `App::update` reducer / `App::load_*`
//   setters.
//
// Two layers live here:
//   (a) read -> reverse -> forward round-trips: write a config, read it back,
//       reverse-map each entry into form state, forward-map it back, and assert
//       the re-derived config equals the original on every observable field.
//       Covers an Ed25519 cert (hashalg None) and a CRL whose revoked-row serial
//       (a `BigUint`) must survive the hex round-trip.
//   (b) reducer behaviour reachable from outside the crate: `Message::LoadConfig`
//       on a form screen returns a `ReadDir` with a `LoadConfig` purpose and is a
//       no-op on the menu; selecting a file in a `LoadConfig`-purpose browser
//       yields `Effect::LoadConfig`; and the `load_*` install setters replace
//       state (and `load_cert_list` resets the index).
//
// NOT covered here (and intentionally not duplicated): the impure
// `load_config_into_app` read+install in `src/tui/mod.rs` is private and is
// covered by developer-03's in-crate `#[cfg(test)]` tests, which assert the
// pinned status/error strings — see `spec/features/04-load-config/test-plan.md`.
// ---------------------------------------------------------------------------

#[cfg(feature = "tui")]
mod load_round_trip {
    use cert_bar::config::{
        CertInfo, Certificate, Cms, Crl, Csr, CsrData, HashAlg, KeyType, Pkix, Reason, RevokedCert,
        Signer, SigningRequest, Usage, read_certificate_config, read_cms_config, read_crl_config,
        read_csr_config, write_certificate_config, write_cms_config, write_crl_config,
        write_csr_config,
    };
    use cert_bar::tui::convert::{
        cert_from_form, cert_to_form, cms_from_form, cms_to_form, crl_from_form, crl_to_form,
        csr_from_form, csr_to_form, signing_request_to_form,
    };
    use num_bigint::BigUint;
    use num_traits::Num;
    use tempfile::TempDir;

    fn temp_yaml(name: &str) -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join(name);
        (dir, path)
    }

    /// `CsrData` has no `Debug`, so `unwrap_err()` cannot be used on its result;
    /// extract the `Ok` value via `match`.
    fn ok_csr(result: Result<CsrData, String>) -> CsrData {
        match result {
            Ok(data) => data,
            Err(e) => panic!("expected Ok CsrData, got Err: {e}"),
        }
    }

    // --- (a) read -> reverse -> forward round-trips ------------------------

    #[test]
    fn certificate_read_reverse_forward_round_trips() {
        // Setup: a fully populated RSA cert written to YAML.
        let original = Certificate {
            id: "ca".to_string(),
            parent: Some("ca".to_string()),
            signer: Some(Signer {
                cert_pem_file: "s_cert.pem".to_string(),
                private_key_pem_file: "s_key.pem".to_string(),
            }),
            ca: Some(true),
            pkix: Pkix {
                commonname: "Root CA".to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
            },
            keytype: KeyType::RSA,
            altnames: Some(vec!["a.com".to_string(), "b.com".to_string()]),
            hashalg: Some(HashAlg::SHA384),
            keylength: Some(4096),
            validto: Some("2031-12-31".to_string()),
            usage: Some(vec![Usage::certsign, Usage::crlsign]),
        };
        let (_dir, path) = temp_yaml("cert.yaml");
        write_certificate_config(vec![original.clone()], &path).unwrap();

        // Invoke: read -> reverse-map -> forward-map.
        let read = read_certificate_config(&path).unwrap();
        let form = cert_to_form(&read[0]);
        let restored = cert_from_form(&form).unwrap();

        // Expect: every observable field survives the full loop.
        assert_eq!(restored.id, original.id);
        assert_eq!(restored.parent, original.parent);
        assert_eq!(restored.signer, original.signer);
        assert_eq!(restored.ca, original.ca);
        assert_eq!(restored.pkix.commonname, original.pkix.commonname);
        assert_eq!(restored.pkix.country, original.pkix.country);
        assert_eq!(restored.pkix.organization, original.pkix.organization);
        assert_eq!(restored.keytype, original.keytype);
        assert_eq!(restored.altnames, original.altnames);
        assert_eq!(restored.hashalg, original.hashalg);
        assert_eq!(restored.keylength, original.keylength);
        assert_eq!(restored.validto, original.validto);
        assert_eq!(
            restored.usage.as_ref().map(Vec::len),
            original.usage.as_ref().map(Vec::len)
        );
    }

    #[test]
    fn ed25519_certificate_round_trips_with_no_hashalg() {
        // An Ed25519 cert has its hashing built in -> hashalg is None. The
        // reverse mapper falls back to index 0 for the absent value; the forward
        // mapper then re-omits hashalg for Ed25519, so None survives.
        let original = Certificate {
            id: "ed-leaf".to_string(),
            parent: None,
            signer: None,
            ca: Some(false),
            pkix: Pkix {
                commonname: "Ed Leaf".to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
            },
            keytype: KeyType::Ed25519,
            altnames: None,
            hashalg: None,
            keylength: None,
            validto: None,
            usage: None,
        };
        let (_dir, path) = temp_yaml("ed_cert.yaml");
        write_certificate_config(vec![original.clone()], &path).unwrap();

        let read = read_certificate_config(&path).unwrap();
        let restored = cert_from_form(&cert_to_form(&read[0])).unwrap();

        assert_eq!(restored.keytype, KeyType::Ed25519);
        assert_eq!(restored.hashalg, None, "Ed25519 hashalg stays None");
        assert_eq!(restored.altnames, None);
        assert_eq!(restored.usage, None);
        // The all-None optionals never resurrect as Some("").
        assert_eq!(restored.parent, None);
        assert_eq!(restored.signer, None);
        assert_eq!(restored.validto, None);
        // `ca` collapses None -> false on the way back (documented fallback);
        // here the config carried Some(false), so it survives unchanged.
        assert_eq!(restored.ca, Some(false));
    }

    #[test]
    fn multi_certificate_round_trips_preserving_order() {
        // Cert configs load *every* entry; the loop must preserve order/ids.
        let ca = Certificate {
            id: "rt-ca".to_string(),
            parent: None,
            signer: None,
            ca: Some(true),
            pkix: Pkix {
                commonname: "Root CA".to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
            },
            keytype: KeyType::Ed25519,
            altnames: None,
            hashalg: None,
            keylength: None,
            validto: None,
            usage: Some(vec![Usage::certsign]),
        };
        let leaf = Certificate {
            id: "rt-leaf".to_string(),
            parent: Some("rt-ca".to_string()),
            signer: None,
            ca: Some(false),
            pkix: Pkix {
                commonname: "Leaf".to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
            },
            keytype: KeyType::P256,
            altnames: None,
            hashalg: Some(HashAlg::SHA256),
            keylength: None,
            validto: None,
            usage: None,
        };
        let (_dir, path) = temp_yaml("chain.yaml");
        write_certificate_config(vec![ca, leaf], &path).unwrap();

        let read = read_certificate_config(&path).unwrap();
        let restored: Vec<Certificate> = read
            .iter()
            .map(|c| cert_from_form(&cert_to_form(c)).unwrap())
            .collect();

        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0].id, "rt-ca");
        assert_eq!(restored[0].parent, None);
        assert_eq!(restored[0].keytype, KeyType::Ed25519);
        assert_eq!(restored[1].id, "rt-leaf");
        assert_eq!(restored[1].parent, Some("rt-ca".to_string()));
        assert_eq!(restored[1].keytype, KeyType::P256);
    }

    #[test]
    fn csr_generate_entry_round_trips() {
        // The first `csr` loads as a generate-mode form.
        let csr = Csr {
            id: "csr1".to_string(),
            pkix: Pkix {
                commonname: "Example".to_string(),
                country: "SE".to_string(),
                organization: "Org".to_string(),
            },
            keytype: KeyType::P256,
            altnames: Some(vec!["a.com".to_string()]),
            hashalg: Some(HashAlg::SHA256),
            keylength: None,
            usage: Some(vec![Usage::serverauth]),
        };
        let (_dir, path) = temp_yaml("csr_gen.yaml");
        write_csr_config(
            CsrData {
                csrs: vec![csr.clone()],
                to_sign: Vec::new(),
            },
            &path,
        )
        .unwrap();

        let data = read_csr_config(&path).unwrap();
        let form = csr_to_form(&data.csrs[0]);
        let restored = ok_csr(csr_from_form(&form));

        assert_eq!(restored.csrs.len(), 1);
        assert!(restored.to_sign.is_empty());
        let out = &restored.csrs[0];
        assert_eq!(out.id, "csr1");
        assert_eq!(out.pkix.commonname, "Example");
        assert_eq!(out.keytype, KeyType::P256);
        assert_eq!(out.altnames, Some(vec!["a.com".to_string()]));
        assert_eq!(out.hashalg, Some(HashAlg::SHA256));
        assert_eq!(out.usage.as_ref().map(Vec::len), Some(1));
    }

    #[test]
    fn csr_signing_request_round_trips_in_sign_mode() {
        // A file with only `signing_requests` loads the first as a sign-mode form.
        let req = SigningRequest {
            csr_pem_file: "req.pem".to_string(),
            signer: Signer {
                cert_pem_file: "c.pem".to_string(),
                private_key_pem_file: "k.pem".to_string(),
            },
            validto: Some("2030-01-01".to_string()),
            ca: Some(true),
        };
        let (_dir, path) = temp_yaml("csr_sign.yaml");
        write_csr_config(
            CsrData {
                csrs: Vec::new(),
                to_sign: vec![req.clone()],
            },
            &path,
        )
        .unwrap();

        let data = read_csr_config(&path).unwrap();
        let form = signing_request_to_form(&data.to_sign[0]);
        assert!(form.sign_mode, "a signing request loads in sign mode");
        let restored = ok_csr(csr_from_form(&form));

        assert!(restored.csrs.is_empty());
        assert_eq!(restored.to_sign.len(), 1);
        assert_eq!(restored.to_sign[0], req);
    }

    #[test]
    fn crl_round_trips_revoked_serial_biguint() {
        // The revoked-row serial is a `BigUint`; it must survive the
        // hex-string round-trip (serialize -> read -> serial_hex -> parse).
        let big = BigUint::from_str_radix("204a77d33809ab2f6524c7cda6ae22e1ce1e7ad9", 16).unwrap();
        let one = BigUint::from(1u8);
        let original = Crl {
            crl_file: "out_crl.pem".to_string(),
            signer: Signer {
                cert_pem_file: "c.pem".to_string(),
                private_key_pem_file: "k.pem".to_string(),
            },
            revoked: vec![
                RevokedCert {
                    cert_info: CertInfo {
                        serial: big.clone(),
                        reason: Reason::KeyCompromise,
                    },
                },
                RevokedCert {
                    cert_info: CertInfo {
                        serial: one.clone(),
                        reason: Reason::CaCompromise,
                    },
                },
            ],
        };
        let (_dir, path) = temp_yaml("crl.yaml");
        write_crl_config(original.clone(), &path).unwrap();

        let read = read_crl_config(&path).unwrap();
        let form = crl_to_form(&read);
        let restored = crl_from_form(&form).unwrap();

        assert_eq!(restored.crl_file, "out_crl.pem");
        assert_eq!(restored.signer, original.signer);
        assert_eq!(restored.revoked.len(), 2);
        // The large serial and the tiny `1` both survive identically.
        assert_eq!(restored.revoked[0].cert_info.serial, big);
        assert_eq!(restored.revoked[1].cert_info.serial, one);
        assert!(matches!(
            restored.revoked[0].cert_info.reason,
            Reason::KeyCompromise
        ));
        assert!(matches!(
            restored.revoked[1].cert_info.reason,
            Reason::CaCompromise
        ));
    }

    #[test]
    fn cms_first_entry_round_trips() {
        // CMS is a single-entry form: the first entry loads.
        let sign = Cms {
            id: "sig".to_string(),
            signer: Some(Signer {
                cert_pem_file: "s_cert.pem".to_string(),
                private_key_pem_file: "s_key.pem".to_string(),
            }),
            recipient: None,
            data_file: "msg.txt".to_string(),
            detached: Some(true),
        };
        let encrypt = Cms {
            id: "enc".to_string(),
            signer: None,
            recipient: Some("rcpt.pem".to_string()),
            data_file: "other.txt".to_string(),
            detached: None,
        };
        let (_dir, path) = temp_yaml("cms.yaml");
        write_cms_config(vec![sign.clone(), encrypt], &path).unwrap();

        let read = read_cms_config(&path).unwrap();
        let form = cms_to_form(&read[0]);
        let restored = cms_from_form(&form).unwrap();

        assert_eq!(restored.id, "sig");
        assert_eq!(restored.data_file, "msg.txt");
        assert_eq!(restored.signer, sign.signer);
        assert_eq!(restored.recipient, None);
        // `detached: None` would collapse to Some(false) on the way back, but the
        // first entry carried Some(true), so it survives unchanged.
        assert_eq!(restored.detached, Some(true));
    }
}

// ---------------------------------------------------------------------------
// Group 6: load-path reducer behaviour at the integration boundary (tui-gated)
//
// The pure `App::update` funnels and `App::load_*` setters reachable from
// outside the crate. The impure `load_config_into_app` (private to mod.rs) is
// NOT exercised here — see Group 5's note and the feature test-plan.
// ---------------------------------------------------------------------------

#[cfg(feature = "tui")]
mod load_reducer {
    use cert_bar::tui::app::{
        App, BrowsePurpose, CertForm, CrlForm, CsrForm, Effect, FileEntry, Focus, Message,
        RevokedRow, Screen,
    };
    use std::path::PathBuf;

    fn file(name: &str) -> FileEntry {
        FileEntry {
            name: name.to_string(),
            is_dir: false,
        }
    }
    fn dir(name: &str) -> FileEntry {
        FileEntry {
            name: name.to_string(),
            is_dir: true,
        }
    }

    #[test]
    fn load_config_on_form_screen_requests_load_purpose_listing() {
        // Setup: parked on the CSR screen, form focused.
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Csr;
        app.focus = Focus::Form;

        // Invoke: Ctrl+L -> Message::LoadConfig.
        let effect = app.update(Message::LoadConfig);

        // Expect: a ReadDir carrying a LoadConfig purpose for the current screen;
        // nothing installed yet. The exact seed directory is the developer's
        // contract (covered by their in-crate test); here we only pin the
        // effect shape + purpose so this stays decoupled from that heuristic.
        // (FINDING: the in-crate test expects the seed dir to be the output dir
        //  `./out` itself, but `open_load_browser` reuses `initial_browse_dir`,
        //  which strips it to its parent `.` — see the load test-plan.)
        match effect {
            Some(Effect::ReadDir { purpose, .. }) => {
                assert_eq!(purpose, BrowsePurpose::LoadConfig(Screen::Csr));
            }
            other => panic!("expected a ReadDir with a LoadConfig purpose, got {other:?}"),
        }
        assert!(app.browser.is_none());
    }

    #[test]
    fn load_config_on_menu_is_noop() {
        // Setup: still on the menu (no active config type).
        let mut app = App::new("./out".to_string());

        // Invoke & Expect: no effect, no browser.
        let effect = app.update(Message::LoadConfig);
        assert_eq!(effect, None);
        assert!(app.browser.is_none());
    }

    #[test]
    fn enter_on_file_in_load_browser_yields_load_config_effect() {
        // Setup: a LoadConfig-purpose browser open on the Cert screen.
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Cert;
        app.focus = Focus::Form;
        app.set_browser_entries(
            PathBuf::from("/cfg"),
            vec![dir(".."), file("certs.yaml")],
            BrowsePurpose::LoadConfig(Screen::Cert),
        );
        app.update(Message::Down); // select the file

        // Invoke: confirm the file selection.
        let effect = app.update(Message::Confirm);

        // Expect: an Effect::LoadConfig for the screen + full path; browser closed.
        assert_eq!(
            effect,
            Some(Effect::LoadConfig {
                screen: Screen::Cert,
                path: "/cfg/certs.yaml".to_string(),
            })
        );
        assert!(app.browser.is_none());
    }

    #[test]
    fn enter_on_dir_in_load_browser_preserves_load_purpose() {
        // Setup: descend a directory while in load mode.
        let mut app = App::new("./out".to_string());
        app.screen = Screen::Crl;
        app.focus = Focus::Form;
        app.set_browser_entries(
            PathBuf::from("/cfg"),
            vec![dir("sub"), file("crl.yaml")],
            BrowsePurpose::LoadConfig(Screen::Crl),
        );

        // Invoke: Enter on the directory entry (selected at index 0).
        let effect = app.update(Message::Confirm);

        // Expect: a re-list that preserves the LoadConfig purpose; browser stays open.
        assert_eq!(
            effect,
            Some(Effect::ReadDir {
                path: PathBuf::from("/cfg/sub"),
                purpose: BrowsePurpose::LoadConfig(Screen::Crl),
            })
        );
        assert!(app.browser.is_some());
    }

    #[test]
    fn load_cert_list_replaces_list_and_resets_index() {
        // Setup: a stale multi-entry list with a non-zero index.
        let mut app = App::new("./out".to_string());
        app.cert_list = vec![
            CertForm::default(),
            CertForm::default(),
            CertForm::default(),
        ];
        app.cert_index = 2;

        // Invoke: install two loaded entries.
        let a = CertForm {
            id: "ca".to_string(),
            ..CertForm::default()
        };
        let b = CertForm {
            id: "leaf".to_string(),
            ..CertForm::default()
        };
        app.load_cert_list(vec![a, b]);

        // Expect: the list is replaced wholesale, index reset, lands in the form.
        assert_eq!(app.cert_list.len(), 2);
        assert_eq!(app.cert_list[0].id, "ca");
        assert_eq!(app.cert_list[1].id, "leaf");
        assert_eq!(app.cert_index, 0);
        assert_eq!(app.screen, Screen::Cert);
        assert_eq!(app.focus, Focus::Form);
    }

    #[test]
    fn load_csr_installs_form_and_focuses() {
        let mut app = App::new("./out".to_string());
        let form = CsrForm {
            id: "req".to_string(),
            ..CsrForm::default()
        };
        app.load_csr(form);
        assert_eq!(app.csr.id, "req");
        assert_eq!(app.screen, Screen::Csr);
        assert_eq!(app.focus, Focus::Form);
    }

    #[test]
    fn load_crl_installs_form_and_clamps_selected_row() {
        let mut app = App::new("./out".to_string());
        let form = CrlForm {
            crl_file: "out.crl".to_string(),
            revoked: vec![RevokedRow::default()],
            selected_row: Some(9), // out of range
            ..CrlForm::default()
        };
        app.load_crl(form);
        assert_eq!(app.crl.crl_file, "out.crl");
        assert_eq!(app.crl.selected_row, Some(0), "clamped into range");
        assert_eq!(app.screen, Screen::Crl);
        assert_eq!(app.focus, Focus::Form);
    }

    #[test]
    fn load_cms_installs_form_and_focuses() {
        let mut app = App::new("./out".to_string());
        let form = cert_bar::tui::app::CmsForm {
            id: "msg".to_string(),
            ..Default::default()
        };
        app.load_cms(form);
        assert_eq!(app.cms.id, "msg");
        assert_eq!(app.screen, Screen::Cms);
        assert_eq!(app.focus, Focus::Form);
    }
}
