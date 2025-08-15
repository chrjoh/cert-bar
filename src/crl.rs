use crate::config::CRL;
use cert_helper::certificate::Certificate as CHCertificate;
use cert_helper::crl::{CrlReason, X509CrlBuilder, X509CrlWrapper};
use chrono::Utc;
use std::fs;
use std::path::Path;

/// Updates or creates a Certificate Revocation List (CRL) based on the provided configuration.
///
/// This function performs the following steps:
/// - Loads the signer's certificate and private key.
/// - Attempts to read an existing CRL file; if found, it loads and extends it, otherwise it creates a new CRL.
/// - Adds all revoked certificates from the configuration, using the current timestamp and mapped revocation reasons.
/// - Signs the updated CRL and saves it to the specified output directory.
///
/// # Arguments
///
/// * `crl_data` - A `CRL` struct containing the signer information, revoked certificates, and target CRL file path.
/// * `output_dir` - The directory where the updated CRL will be saved.
///
/// # Returns
///
/// A `Result` indicating success or containing an error if any step fails.
///
/// # Errors
///
/// Returns an error if:
/// - The signer's certificate or key cannot be loaded.
/// - The existing CRL file cannot be read or parsed.
/// - The CRL cannot be built or signed.
/// - The final CRL cannot be saved to disk.
pub fn handle<C: AsRef<Path>>(
    crl_data: CRL,
    output_dir: C,
) -> Result<(), Box<dyn std::error::Error>> {
    let signer = CHCertificate::load_cert_and_key(
        &crl_data.signer.cert_pem_file,
        &crl_data.signer.private_key_pem_file,
    )?;
    let mut builder = if let Ok(existing) = fs::read(&crl_data.crl_file) {
        let wrapper = X509CrlWrapper::read_as_pem(&crl_data.crl_file)?;
        X509CrlBuilder::from_der(&wrapper.to_der()?, signer.clone())
            .expect("failed to get crl from file")
    } else {
        X509CrlBuilder::new(signer.clone())
    };
    for r in crl_data.revoked {
        builder.add_revoked_cert_with_reason(
            r.cert_info.serial,
            Utc::now(),
            vec![CrlReason::from(r.cert_info.reason)],
        );
    }
    let crl_signed = builder.build_and_sign();
    let wrapper = X509CrlWrapper::from_der(&crl_signed)?;
    let (dir, file) = split_path_and_filename(&crl_data.crl_file).unwrap();
    wrapper.save_as_pem(output_dir, file)?;

    Ok(())
}

fn split_path_and_filename(full_path: &str) -> Option<(String, String)> {
    let path = Path::new(full_path);
    let dir = path.parent()?.to_string_lossy().to_string();
    let file = path.file_name()?.to_string_lossy().to_string();
    Some((dir, file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use cert_helper::certificate::{CertBuilder, Certificate as CHCertificate, UseesBuilderFields};
    use num_bigint::BigUint;
    use num_traits::Num;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    const EXISTING_CRL_PEM: &str = r#"-----BEGIN X509 CRL-----
MIICHDCCAQQCAQEwDQYJKoZIhvcNAQELBQAwFTETMBEGA1UEAwwKd3d3LmZvby5z
ZRgPMjAyNTA4MTUwOTQ3MTJaGA8yMDI1MDkxNDA5NDcxMlowgbYwNQIUIEp30zgJ
qy9lJMfNpq4i4c4eetkYDzIwMjUwODE1MDk0NzEyWjAMMAoGA1UdFQQDCgEBMDUC
FCJKd9M4CasvZSTHzaauIuHOHnrZGA8yMDI1MDgxNTA5NDcxMlowDDAKBgNVHRUE
AwoBAjAiAgEiGA8yMDI1MDgxNTA5NDcxMlowDDAKBgNVHRUEAwoBAjAiAgEzGA8y
MDI1MDgxNTA5NTA1OFowDDAKBgNVHRUEAwoBAjANBgkqhkiG9w0BAQsFAAOCAQEA
K2lw+AVrq/5ycJ+IMEk4EU+NPrcdztmWtQeLvjkvBdhW4rJAmOWPpwANuZs+NQQW
Ad1sqtJmJ/qQhUdYkRUI6MQ7Y1m6/KV2zFFMUAnTl3HOWTBlVJJPQAYJH7Ediac+
xOGBFFWoeED2SoddLvQvSDutRr8roeK0a3nFpftulvg0b2Y8YBmamvxuUQs3tprb
zHpnoKH3GkXt0ycj+QokmmAYdxAlrjrtEn70h70W1L4eCh0G9YXZ7MqYedJtfca5
v/5ffE/G2xl2hE5HiTm4MOXjeimosVpqpJvhg3BxrTZ+vWK982NDeT8DyDqkgfta
GNwSHDA8nLhIpmdNaFkf2w==
-----END X509 CRL-----"#;

    #[test]
    fn test_handle_creates_crl_file() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path();

        let cert = dummy_certificate();
        let (cert_path, key_path) = write_dummy_cert_and_key(&cert, dir_path);

        let crl_file_path = dir_path.join("test_crl.pem");
        let crl_data = CRL {
            signer: Signer {
                cert_pem_file: cert_path,
                private_key_pem_file: key_path,
            },
            crl_file: crl_file_path.to_str().unwrap().to_string(),
            revoked: vec![RevokedCert {
                cert_info: CertInfo {
                    serial: BigUint::from_str_radix("1234567890", 10).unwrap(),
                    reason: Reason::CaCompromise,
                },
            }],
        };

        let result = handle(crl_data.clone(), dir_path);
        assert!(result.is_ok());

        let output_crl_path = dir_path.join("test_crl.pem");
        assert!(output_crl_path.exists());

        let contents = fs::read_to_string(output_crl_path).unwrap();
        assert!(contents.contains("BEGIN X509 CRL"));
    }

    #[test]
    fn test_handle_with_existing_crl_file() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path();

        let crl_file_path = dir_path.join("existing_crl.pem");
        let mut crl_file = File::create(&crl_file_path).unwrap();
        crl_file.write_all(EXISTING_CRL_PEM.as_bytes()).unwrap();

        let cert = dummy_certificate();
        let (cert_path, key_path) = write_dummy_cert_and_key(&cert, dir_path);

        let crl_data = CRL {
            signer: Signer {
                cert_pem_file: cert_path,
                private_key_pem_file: key_path,
            },
            crl_file: crl_file_path.to_str().unwrap().to_string(),
            revoked: vec![RevokedCert {
                cert_info: CertInfo {
                    serial: BigUint::from_str_radix("987654321", 10).unwrap(),
                    reason: Reason::CaCompromise,
                },
            }],
        };

        let result = handle(crl_data.clone(), dir_path);
        assert!(result.is_ok());

        let output_crl_path = dir_path.join("existing_crl.pem");
        assert!(output_crl_path.exists());

        let contents = fs::read_to_string(output_crl_path).unwrap();
        assert!(contents.contains("BEGIN X509 CRL"));
    }

    fn dummy_certificate() -> CHCertificate {
        CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .build_and_self_sign()
            .unwrap()
    }
    fn write_dummy_cert_and_key(cert: &CHCertificate, dir: &Path) -> (String, String) {
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");

        let cert_pem = cert.x509.to_pem().unwrap();
        let key_pem = cert
            .pkey
            .as_ref()
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();

        let mut cert_file = File::create(&cert_path).unwrap();
        cert_file.write_all(&cert_pem).unwrap();

        let mut key_file = File::create(&key_path).unwrap();
        key_file.write_all(&key_pem).unwrap();

        (
            cert_path.to_str().unwrap().to_string(),
            key_path.to_str().unwrap().to_string(),
        )
    }
}
