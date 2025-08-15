use cert_helper::certificate::{
    Certificate as CHCertificate, HashAlg as CHHashAlg, KeyType as CHKeyType, Usage as CHUsage,
};
use cert_helper::crl::CrlReason;
use num_bigint::BigUint;
use num_traits::Num;
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

#[derive(Debug, Deserialize)]
pub struct CsrWrapper {
    pub csr: Csr,
}

#[derive(Debug, Deserialize)]
pub struct SigningRequestWrapper {
    pub signing_request: SigningRequest,
}

#[derive(Debug, Deserialize)]
pub struct Csrs {
    #[serde(default)]
    csrs: Vec<CsrWrapper>,

    #[serde(default)]
    signing_requests: Vec<SigningRequestWrapper>,
}
#[derive(Debug, Deserialize, Clone)]
pub struct Csr {
    pub id: String,
    pub pkix: Pkix,
    pub keytype: KeyType,
    pub altnames: Option<Vec<String>>,
    pub hashalg: Option<HashAlg>,
    pub keylength: Option<u32>,
    pub usage: Option<Vec<Usage>>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct SigningRequest {
    pub csr_pem_file: String,
    pub signer: Signer,
    pub validto: Option<String>,
    pub ca: Option<bool>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
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
pub struct CsrData {
    pub csrs: Vec<Csr>,
    pub to_sign: Vec<SigningRequest>,
}

#[derive(Debug, Deserialize, Clone)]
pub enum Reason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
}

impl From<Reason> for CrlReason {
    fn from(reason: Reason) -> Self {
        match reason {
            Reason::Unspecified => CrlReason::Unspecified,
            Reason::KeyCompromise => CrlReason::KeyCompromise,
            Reason::CaCompromise => CrlReason::CaCompromise,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct CRL {
    pub crl_file: String,
    pub signer: Signer,
    #[serde(default)]
    pub revoked: Vec<RevokedCert>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RevokedCert {
    pub cert_info: CertInfo,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CertInfo {
    #[serde(deserialize_with = "deserialize_serial")]
    pub serial: BigUint,
    pub reason: Reason,
}

fn deserialize_serial<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let normalized = s.replace(":", "");
    BigUint::from_str_radix(&normalized, 16).map_err(serde::de::Error::custom)
}
/// Reads a certificate configuration YAML file and returns a flat list of certificates.
///
/// # Arguments
///
/// * `config` - A path to the YAML configuration file.
///
/// # Returns
///
/// A `Result` containing a vector of `Certificate` objects if successful, or an error if the file
/// cannot be read or parsed.
///
/// # Errors
///
/// Returns an error if the file does not exist or if the YAML content is invalid.
pub fn read_certificate_config<C: AsRef<Path>>(
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

/// Reads a CSR (Certificate Signing Request) configuration YAML file and returns structured CSR data.
///
/// # Arguments
///
/// * `config` - A path to the YAML configuration file.
///
/// # Returns
///
/// A `Result` containing a `CsrData` object with parsed CSRs and signing requests, or an error.
///
/// # Errors
///
/// Returns an error if the file does not exist or if the YAML content is invalid.
pub fn read_csr_config<C: AsRef<Path>>(config: C) -> Result<CsrData, Box<dyn std::error::Error>> {
    let yaml_str = fs::read_to_string(config).expect("No config file found");

    let csrs: Csrs = serde_yaml::from_str(&yaml_str)?;
    let flat_csr: Vec<Csr> = csrs.csrs.into_iter().map(|wrapper| wrapper.csr).collect();
    let flat_requests_to_sign: Vec<SigningRequest> = csrs
        .signing_requests
        .into_iter()
        .map(|f| f.signing_request)
        .collect();
    Ok(CsrData {
        csrs: flat_csr,
        to_sign: flat_requests_to_sign,
    })
}

/// Reads a CRL (Certificate Revocation List) configuration YAML file and returns the parsed CRL object.
///
/// # Arguments
///
/// * `config` - A path to the YAML configuration file.
///
/// # Returns
///
/// A `Result` containing a `CRL` object if successful, or an error if the file cannot be read or parsed.
///
/// # Errors
///
/// Returns an error if the file does not exist or if the YAML content is invalid.
pub fn read_crl_config<C: AsRef<Path>>(config: C) -> Result<CRL, Box<dyn std::error::Error>> {
    let yaml_str = fs::read_to_string(config).expect("No config file found");
    match serde_yaml::from_str(&yaml_str) {
        Ok(data) => Ok(data),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_certificate_config_valid_yaml() {
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

        let result = read_certificate_config(temp_file.path());
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

    #[test]
    fn test_read_csr_config_valid_yaml() {
        let yaml_content = r#"
csrs:
  - csr:
      id: csr1
      pkix:
        commonname: "Example CN"
        country: "SE"
        organization: "Example Org"
      keytype: RSA
      altnames:
        - example.com,
        - www.example.com
      hashalg: SHA256
      keylength: 2048
      usage: [serverauth, clientauth]
"#;

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        write!(temp_file, "{}", yaml_content).expect("Failed to write to temp file");

        let result = read_csr_config(temp_file.path());
        assert!(result.is_ok());

        let data = result.unwrap();
        let csrs = data.csrs;
        assert_eq!(csrs.len(), 1);

        let csr = &csrs[0];
        assert_eq!(csr.pkix.commonname, "Example CN");
        assert_eq!(csr.keytype, KeyType::RSA);
        assert_eq!(csr.hashalg, Some(HashAlg::SHA256));
        assert_eq!(csr.keylength, Some(2048));
        assert_eq!(csr.usage.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_read_csr_config_for_signing_valid_yaml() {
        let yaml_content = r#"
signing_requests:
  - signing_request:
        csr_pem_file: "csr.pem"
        validto: "2030-01-01"
        ca: true
        signer:
            cert_pem_file: signer_cert.pem
            private_key_pem_file: signer_pkey.pem
"#;

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        write!(temp_file, "{}", yaml_content).expect("Failed to write to temp file");

        let result = read_csr_config(temp_file.path());
        assert!(result.is_ok());

        let data = result.unwrap();
        let to_sign = data.to_sign;
        assert_eq!(to_sign.len(), 1);

        let first = &to_sign[0];

        assert_eq!(
            first,
            &SigningRequest {
                csr_pem_file: "csr.pem".to_string(),
                validto: Some("2030-01-01".to_string()),
                ca: Some(true),
                signer: Signer {
                    cert_pem_file: "signer_cert.pem".to_string(),
                    private_key_pem_file: "signer_pkey.pem".to_string()
                }
            }
        );
    }

    #[test]
    fn test_read_crl_config_valid_yaml() {
        let yaml_content = r#"
crl_file: file_cer.pem
signer:
    cert_pem_file: signer_cert.pem
    private_key_pem_file: signer_pkey.pem
revoked:
  - cert_info:
      serial: 20:4a:77:d3:38:09:ab:2f:65:24:c7:cd:a6:ae:22:e1:ce:1e:7a:d9
      reason: KeyCompromise
  - cert_info:
      serial: 224a77d33809ab2f6524c7cda6ae22e1ce1e7ad9
      reason: CaCompromise
"#;

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        write!(temp_file, "{}", yaml_content).expect("Failed to write to temp file");

        let result = read_crl_config(temp_file.path());
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.crl_file, "file_cer.pem".to_string());
        assert_eq!(
            data.signer,
            Signer {
                cert_pem_file: "signer_cert.pem".to_string(),
                private_key_pem_file: "signer_pkey.pem".to_string()
            }
        )
    }
}
