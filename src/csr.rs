#![allow(dead_code, unused_imports)]
use crate::config::{Certificate, Csr, FromKeyType, KeyType, SigningRequest};
use cert_helper::certificate::{
    Certificate as CHCertificate, Csr as CGCsr, CsrBuilder, CsrOptions, HashAlg as CHHashAlg,
    KeyType as CHKeyType, Usage as CHUsage, UseesBuilderFields, X509Common,
};
use std::collections::HashSet;
use std::path::Path;

/// Creates Certificate Signing Requests (CSRs) and saves them to the specified output directory.
///
/// This function processes a list of CSR definitions and delegates each to `handle_csr`,
/// which performs the actual creation and saving of the CSR.
///
/// # Arguments
///
/// * `flat_csrs` - A vector of `Csr` objects representing the CSRs to be created.
/// * `output_dir` - The directory where the generated CSRs will be saved.
///
/// # Returns
///
/// A `Result` indicating success or containing an error if any CSR creation fails.
///
/// # Errors
///
/// Returns an error if any individual CSR fails to be processed or saved.
pub fn create_csr<C: AsRef<Path>>(
    flat_csrs: Vec<Csr>,
    output_dir: C,
) -> Result<(), Box<dyn std::error::Error>> {
    flat_csrs
        .into_iter()
        .try_for_each(|csr| handle_csr(csr, &output_dir))?;
    Ok(())
}

/// Signs certificate requests and saves the resulting certificates to the specified output directory.
///
/// This function processes a list of signing requests and delegates each to `handle_sign`,
/// which performs the actual signing and saving of the certificate.
///
/// # Arguments
///
/// * `req` - A vector of `SigningRequest` objects to be signed.
/// * `output_dir` - The directory where the signed certificates will be saved.
///
/// # Returns
///
/// A `Result` indicating success or containing an error if any signing operation fails.
///
/// # Errors
///
/// Returns an error if any individual signing request fails to be processed or saved.
pub fn sign_requests<C: AsRef<Path>>(
    req: Vec<SigningRequest>,
    output_dir: C,
) -> Result<(), Box<dyn std::error::Error>> {
    req.into_iter()
        .try_for_each(|r| handle_sign(r, &output_dir))?;
    Ok(())
}
fn handle_sign<C: AsRef<Path>>(
    csr: SigningRequest,
    output_dir: C,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut option = CsrOptions::new();
    option = option.is_ca(csr.ca.unwrap_or(false));
    if let Some(valid_to) = csr.validto {
        option = option.valid_to(&valid_to);
    }
    let csr_to_sign = CGCsr::load_csr(&csr.csr_pem_file)?;
    let signer = CHCertificate::load_cert_and_key(
        &csr.signer.cert_pem_file,
        &csr.signer.private_key_pem_file,
    )?;
    let signed_cert = csr_to_sign.build_signed_certificate(&signer, option)?;

    let filename = Path::new(&csr.csr_pem_file)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("");

    signed_cert.save(output_dir, filename)?;
    Ok(())
}

fn handle_csr<C: AsRef<Path>>(csr: Csr, output_dir: C) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = CsrBuilder::new();
    builder = builder.country_name(&csr.pkix.country);
    builder = builder.organization(&csr.pkix.organization);
    builder = builder.common_name(&csr.pkix.commonname);
    builder = builder.key_type(CHKeyType::from_key_type(csr.keytype.clone(), csr.keylength));
    match (&csr.hashalg, csr.keytype) {
        (Some(hashalg), _) => builder = builder.signature_alg(CHHashAlg::from(hashalg.clone())),
        (None, KeyType::Ed25519) => {}
        (None, _) => return Err("Missing hash Alg for creating CSR".into()),
    }

    if let Some(ref altnames) = csr.altnames {
        let altnames_refs: Vec<&str> = altnames.iter().map(String::as_str).collect();
        builder = builder.alternative_names(altnames_refs);
    }
    if let Some(ref usage_vec) = csr.usage {
        let usage_set: HashSet<CHUsage> =
            usage_vec.iter().map(|u| CHUsage::from(u.clone())).collect();
        builder = builder.key_usage(usage_set);
    }
    let csr_request = builder.certificate_signing_request()?;
    csr_request.save(output_dir, &csr.id)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use cert_helper::certificate::{CertBuilder, Certificate as CHCertificate};
    use std::collections::HashSet;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_handle_csr_basic() {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let csr = Csr {
            id: "test1".to_string(),
            pkix: Pkix {
                commonname: "example.com".to_string(),
                country: "SE".to_string(),
                organization: "TestOrg".to_string(),
            },
            keytype: KeyType::RSA,
            altnames: Some(vec![
                "www.example.com".to_string(),
                "mail.example.com".to_string(),
            ]),
            hashalg: Some(HashAlg::SHA256),
            keylength: Some(2048),
            usage: Some(vec![Usage::serverauth, Usage::clientauth]),
        };

        let result = handle_csr(csr, &temp_dir);
        assert!(result.is_ok());

        let expected_path = temp_dir.path().join("test1_csr.pem");
        assert!(expected_path.exists());
    }

    #[test]
    fn test_handle_csr_missing_all_optional() {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let csr = Csr {
            id: "test2".to_string(),
            pkix: Pkix {
                commonname: "example.com".to_string(),
                country: "SE".to_string(),
                organization: "TestOrg".to_string(),
            },
            keytype: KeyType::P256,
            altnames: None,
            hashalg: None,
            keylength: None,
            usage: None,
        };

        let result = handle_csr(csr, &temp_dir);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_sign_with_dummy_cert() {
        let temp_dir = tempfile::tempdir().unwrap();
        let csr_path = temp_dir.path().join("test.csr");

        let csr_pem = b"-----BEGIN CERTIFICATE REQUEST-----
MIIC4zCCAcsCAQAwODETMBEGA1UEAwwKRXhhbXBsZSBDTjELMAkGA1UEBhMCU0Ux
FDASBgNVBAoMC0V4YW1wbGUgT3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA1IqP3IddAUybVGEhlu6kSVUW30i2NfAEisIcbVdQ9U45IJ/BmzugDlTx
aQ0Ms0g+Hb2yQhkqP0jXqQMUaEwSSgY2oZ0179YYRkYwmaso4N6flYA3+IarczrZ
1QrP/l/DYy7nqlvyDBd7nyiWYs8ZIRi6rLP0SXIat//TrW+rxNyh6XIePNL0RmXO
d4obpS5Gfo0BkWv6Y840SvvCMltfKVxKKu2HE07L0ODlA5OuxZeY8odNv6YzhXNq
qz6XWke0Lsfg7Cae+UejH+yUnsAtz1DV8ylEUbUSr2peF6OzAVySv1WtNT3qAN2S
skBADUiJiD0OGarntLy6uYuFt8g3MQIDAQABoGYwZAYJKoZIhvcNAQkOMVcwVTAd
BgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwNAYDVR0RBC0wK4IPd3d3LmV4
YW1wbGUuY29tggpFeGFtcGxlIENOggxleGFtcGxlLmNvbSwwDQYJKoZIhvcNAQEL
BQADggEBAEjROaK6aPFm4mhI1ca/RwQRxpC7Dx9hw6lwM7/vE9M8U8jkVwgs9DrA
HpuO24C2+mjdo7M2D6tfALQ4VXVPUBNxanTdSwJ3oXJ6wiueEIvQv+HojHtn2s+F
cA3HhjVX2s4z6NjufCLR43wCpmS9uBUmx5qmzepPknUGe9h/Mw37oTAhp9EewXQb
EP5+MhsSvnji2hwDtsmMfq0Zy/esBbbyBIE+WSbz6fCZNx+E82/qmZDCQY68XjPq
dKl92Fp7/SPP/HC+ffQLLTk8sPWJ1RNGB6xiq8pjOMR09epNwqrndJvR9TFgdCM8
QzIhEb5ZiTDMEkxBccLz/QQRwWVhF1c=
-----END CERTIFICATE REQUEST-----";

        std::fs::write(&csr_path, csr_pem).unwrap();

        let cert = dummy_certificate();
        let (cert_file, key_file) = write_dummy_cert_and_key(&cert, temp_dir.path());

        let signer = Signer {
            cert_pem_file: cert_file,
            private_key_pem_file: key_file,
        };
        let csr_pem_file = csr_path.to_str().unwrap().to_string();
        let request = SigningRequest {
            csr_pem_file: csr_pem_file.clone(),
            signer,
            validto: Some("2026-07-01".to_string()),
            ca: Some(true),
        };

        let result = handle_sign(request, temp_dir.path());
        match result {
            Ok(_) => assert!(true),
            Err(e) => println!("Error: {:?}", e),
        }

        let filename = Path::new(&csr_pem_file)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("");

        let signed_cert_path = temp_dir.path().join(format!("{filename}_cert.pem"));
        assert!(signed_cert_path.exists());
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
