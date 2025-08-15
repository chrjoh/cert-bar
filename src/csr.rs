#![allow(dead_code, unused_imports)]
use crate::config::{Certificate, Csr, FromKeyType, KeyType, SigningRequest};
use cert_helper::certificate::{
    Certificate as CHCertificate, Csr as CGCsr, CsrBuilder, CsrOptions, HashAlg as CHHashAlg,
    KeyType as CHKeyType, Usage as CHUsage, UseesBuilderFields, X509Common,
};
use std::collections::HashSet;
use std::path::Path;

pub fn create_csr<C: AsRef<Path>>(
    flat_csrs: Vec<Csr>,
    output_dir: C,
) -> Result<(), Box<dyn std::error::Error>> {
    flat_csrs
        .into_iter()
        .try_for_each(|csr| handle_csr(csr, &output_dir))?;
    Ok(())
}
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
    if let Some(ref hashalg) = csr.hashalg {
        builder = builder.signature_alg(CHHashAlg::from(hashalg.clone()));
    } else {
        if csr.keytype != KeyType::Ed25519 {
            return Err("Missing hash Alg for creating CSR".into());
        }
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
    use std::collections::HashSet;
    use std::fs;
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

    //  #[test]
    //  fn test_handle_csr_with_sign_request_skips_creation() {
    //      let temp_dir = tempdir().expect("Failed to create temp dir");
    //      let csr = Csr {
    //          id: "test3".to_string(),
    //          sign_request: Some(SigningRequest {
    //              csr_pem_file: "dummy.pem".to_string(),
    //              signer: Signer {
    //                  cert_pem_file: "cert.pem".to_string(),
    //                  private_key_pem_file: "key.pem".to_string(),
    //              },
    //              validto: None,
    //              ca: Some(true),
    //          }),
    //          pkix: None,
    //          keytype: None,
    //          altnames: None,
    //          hashalg: None,
    //          keylength: None,
    //          usage: None,
    //      };

    //      let result = handle_csr(csr, &temp_dir);
    //      assert!(result.is_ok());
    //  }
}
