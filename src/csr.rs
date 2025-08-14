#![allow(dead_code, unused_imports)]
use crate::config::{Csr, FromKeyType, KeyType};
use cert_helper::certificate::{
    Certificate as CHCertificate, CsrBuilder, CsrOptions, HashAlg as CHHashAlg,
    KeyType as CHKeyType, Usage as CHUsage, UseesBuilderFields, X509Common,
};
use std::collections::HashSet;
use std::path::Path;

pub fn create<C: AsRef<Path>>(
    flat_csrs: Vec<Csr>,
    output_dir: C,
) -> Result<(), Box<dyn std::error::Error>> {
    flat_csrs
        .into_iter()
        .try_for_each(|csr| handle_csr(csr, &output_dir))?;
    Ok(())
}
fn handle_csr<C: AsRef<Path>>(csr: Csr, output_dir: C) -> Result<(), Box<dyn std::error::Error>> {
    if csr.sign_request.is_some() {
        //let options = CsrOptions::new().is_ca(csr.ca.unwrap_or(false));
    } else {
        let mut builder = CsrBuilder::new();
        if let Some(ref pkix) = csr.pkix {
            builder = builder.country_name(&pkix.country);
            builder = builder.organization(&pkix.organization);
            builder = builder.common_name(&pkix.commonname);
        } else {
            return Err("Missing pkix for creating CSR".into());
        }
        if let Some(ref keytype) = csr.keytype {
            builder = builder.key_type(CHKeyType::from_key_type(keytype.clone(), csr.keylength));
        } else {
            return Err("Missing key type for creating CSR".into());
        }
        if let Some(ref hashalg) = csr.hashalg {
            builder = builder.signature_alg(CHHashAlg::from(hashalg.clone()));
        } else {
            if csr.keytype != Some(KeyType::Ed25519) {
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
        csr_request.save(output_dir, csr.id.clone())?;
    }
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
            sign_request: None,
            pkix: Some(Pkix {
                commonname: "example.com".to_string(),
                country: "SE".to_string(),
                organization: "TestOrg".to_string(),
            }),
            keytype: Some(KeyType::RSA),
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
    fn test_handle_csr_missing_pkix() {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let csr = Csr {
            id: "test2".to_string(),
            sign_request: None,
            pkix: None,
            keytype: Some(KeyType::Ed25519),
            altnames: None,
            hashalg: Some(HashAlg::SHA512),
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
