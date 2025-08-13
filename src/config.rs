use cert_helper::certificate::{
    Certificate as CHCertificate, HashAlg as CHHashAlg, KeyType as CHKeyType, Usage as CHUsage,
};
use serde::Deserialize;
use std::fs;
use std::path::Path;
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub enum HashAlg {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}
impl From<HashAlg> for CHHashAlg {
    fn from(h: HashAlg) -> Self {
        match h {
            HashAlg::SHA1 => CHHashAlg::SHA1,
            HashAlg::SHA384 => CHHashAlg::SHA256,
            HashAlg::SHA512 => CHHashAlg::SHA512,
            _ => CHHashAlg::SHA256,
        }
    }
}
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub enum KeyType {
    RSA,
    P224,
    P256,
    P384,
    P521,
    Ed25519,
}

pub trait FromKeyType {
    fn from_key_type(key_type: KeyType, rsa_bits: Option<u32>) -> Self;
}

impl FromKeyType for CHKeyType {
    fn from_key_type(key_type: KeyType, rsa_bits: Option<u32>) -> Self {
        match key_type {
            KeyType::RSA => match rsa_bits {
                Some(4096) => CHKeyType::RSA4096,
                _ => CHKeyType::RSA2048,
            },
            KeyType::P224 => CHKeyType::P224,
            KeyType::P256 => CHKeyType::P256,
            KeyType::P384 => CHKeyType::P384,
            KeyType::P521 => CHKeyType::P521,
            KeyType::Ed25519 => CHKeyType::Ed25519,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Deserialize, Clone)]
pub enum Usage {
    certsign,
    crlsign,
    encipherment,
    clientauth,
    serverauth,
    signature,
    contentcommitment,
}
impl From<Usage> for CHUsage {
    fn from(u: Usage) -> Self {
        match u {
            Usage::serverauth => CHUsage::serverauth,
            Usage::clientauth => CHUsage::clientauth,
            Usage::certsign => CHUsage::certsign,
            Usage::contentcommitment => CHUsage::contentcommitment,
            Usage::crlsign => CHUsage::crlsign,
            Usage::encipherment => CHUsage::encipherment,
            Usage::signature => CHUsage::signature,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Certificates {
    certificates: Vec<CertificateWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct CertificateWrapper {
    pub certificate: Certificate,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Certificate {
    pub id: String,
    pub parent: Option<String>,
    pub signer: Option<Signer>,
    pub ca: Option<bool>,
    pub pkix: Pkix,
    pub keytype: KeyType,
    pub altnames: Option<Vec<String>>,
    pub hashalg: Option<HashAlg>,
    pub keylength: Option<u32>,
    pub validto: Option<String>,
    pub usage: Option<Vec<Usage>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Signer {
    pub cert_pem_file: String,
    pub private_key_pem_file: String,
}
#[derive(Debug, Deserialize, Default, Clone)]
pub struct Pkix {
    pub commonname: String,
    pub country: String,
    pub organization: String,
}
#[derive(Clone)]
pub struct CreatedCertificate {
    pub id: String,
    pub cert: CHCertificate,
}

pub fn read_config<C: AsRef<Path>>(
    config: C,
) -> Result<Vec<Certificate>, Box<dyn std::error::Error>> {
    let yaml_str = fs::read_to_string(config).expect("No config file found");

    let certs: Certificates = serde_yaml::from_str(&yaml_str)?;
    let flat_certs: Vec<Certificate> = certs
        .certificates
        .into_iter()
        .map(|wrapper| wrapper.certificate)
        .collect();
    Ok(flat_certs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_config_valid_yaml() {
        let yaml_content = r#"
certificates:
  - certificate:
      id: "cert1"
      parent: null
      signer: null
      ca: true
      pkix:
        commonname: "Example CN"
        country: "SE"
        organization: "Example Org"
        organizationunit: "IT"
      keytype: RSA
      altnames:
        - example.com,
        - www.example.com
      hashalg: SHA256
      keylength: 2048
      validto: "2030-01-01"
      usage: [serverauth, clientauth]
"#;

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        write!(temp_file, "{}", yaml_content).expect("Failed to write to temp file");

        let result = read_config(temp_file.path());
        assert!(result.is_ok());

        let certs = result.unwrap();
        assert_eq!(certs.len(), 1);

        let cert = &certs[0];
        assert_eq!(cert.id, "cert1");
        assert_eq!(cert.ca, Some(true));
        assert_eq!(cert.pkix.commonname, "Example CN");
        assert_eq!(cert.keytype, KeyType::RSA);
        assert_eq!(cert.hashalg, Some(HashAlg::SHA256));
        assert_eq!(cert.keylength, Some(2048));
        assert_eq!(cert.usage.as_ref().unwrap().len(), 2);
    }
}
