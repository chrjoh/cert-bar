use cert_helper::certificate::{
    Certificate as CHCertificate, HashAlg as CHHashAlg, KeyType as CHKeyType, Usage as CHUsage,
};
use cert_helper::crl::CrlReason;
use num_bigint::BigUint;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
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
            HashAlg::SHA384 => CHHashAlg::SHA384,
            HashAlg::SHA512 => CHHashAlg::SHA512,
            _ => CHHashAlg::SHA256,
        }
    }
}
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub enum KeyType {
    RSA,
    P224,
    P256,
    P384,
    P521,
    Ed25519,
    #[cfg(feature = "pqc")]
    MlDsa44,
    #[cfg(feature = "pqc")]
    MlDsa65,
    #[cfg(feature = "pqc")]
    MlDsa87,
    #[cfg(feature = "pqc")]
    SlhDsaSha2_128s,
    #[cfg(feature = "pqc")]
    SlhDsaSha2_192s,
    #[cfg(feature = "pqc")]
    SlhDsaSha2_256s,
}

impl KeyType {
    /// Whether a separate signature hash algorithm (`hashalg`) applies to this
    /// key type.
    ///
    /// RSA and the NIST ECDSA curves sign over an externally chosen hash, so a
    /// `hashalg` is meaningful. Ed25519 (EdDSA) and the PQC algorithms (ML-DSA,
    /// SLH-DSA) have their hashing built in, so no `hashalg` applies — it should
    /// be left unset and omitted from a generated config.
    #[must_use]
    pub fn uses_hash_alg(&self) -> bool {
        matches!(
            self,
            KeyType::RSA | KeyType::P224 | KeyType::P256 | KeyType::P384 | KeyType::P521
        )
    }
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
            #[cfg(feature = "pqc")]
            KeyType::MlDsa44 => CHKeyType::MlDsa44,
            #[cfg(feature = "pqc")]
            KeyType::MlDsa65 => CHKeyType::MlDsa65,
            #[cfg(feature = "pqc")]
            KeyType::MlDsa87 => CHKeyType::MlDsa87,
            #[cfg(feature = "pqc")]
            KeyType::SlhDsaSha2_128s => CHKeyType::SlhDsaSha2_128s,
            #[cfg(feature = "pqc")]
            KeyType::SlhDsaSha2_192s => CHKeyType::SlhDsaSha2_192s,
            #[cfg(feature = "pqc")]
            KeyType::SlhDsaSha2_256s => CHKeyType::SlhDsaSha2_256s,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Deserialize, Serialize, Clone)]
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

#[derive(Debug, Deserialize, Serialize)]
pub struct Certificates {
    certificates: Vec<CertificateWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CertificateWrapper {
    pub certificate: Certificate,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Certificate {
    pub id: String,
    pub parent: Option<String>,
    pub signer: Option<Signer>,
    pub ca: Option<bool>,
    pub pkix: Pkix,
    pub keytype: KeyType,
    pub altnames: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashalg: Option<HashAlg>,
    pub keylength: Option<u32>,
    pub validto: Option<String>,
    pub usage: Option<Vec<Usage>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CsrWrapper {
    pub csr: Csr,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SigningRequestWrapper {
    pub signing_request: SigningRequest,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Csrs {
    #[serde(default)]
    csrs: Vec<CsrWrapper>,

    #[serde(default)]
    signing_requests: Vec<SigningRequestWrapper>,
}
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Csr {
    pub id: String,
    pub pkix: Pkix,
    pub keytype: KeyType,
    pub altnames: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashalg: Option<HashAlg>,
    pub keylength: Option<u32>,
    pub usage: Option<Vec<Usage>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SigningRequest {
    pub csr_pem_file: String,
    pub signer: Signer,
    pub validto: Option<String>,
    pub ca: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Signer {
    pub cert_pem_file: String,
    pub private_key_pem_file: String,
}
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
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

#[derive(Debug, Deserialize, Serialize, Clone)]
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Crl {
    pub crl_file: String,
    pub signer: Signer,
    #[serde(default)]
    pub revoked: Vec<RevokedCert>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RevokedCert {
    pub cert_info: CertInfo,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CertInfo {
    #[serde(
        deserialize_with = "deserialize_serial",
        serialize_with = "serialize_serial"
    )]
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

fn serialize_serial<S>(serial: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let hex = serial.to_str_radix(16);
    serializer.serialize_str(&hex)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Cmss {
    cmss: Vec<CmsWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CmsWrapper {
    pub cms: Cms,
}
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Cms {
    pub id: String,
    pub signer: Option<Signer>,
    pub recipient: Option<String>,
    pub data_file: String,
    pub detached: Option<bool>,
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
    let yaml_str = fs::read_to_string(config)?;

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
    let yaml_str = fs::read_to_string(config)?;

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
pub fn read_crl_config<C: AsRef<Path>>(config: C) -> Result<Crl, Box<dyn std::error::Error>> {
    let yaml_str = fs::read_to_string(config)?;
    match serde_yaml::from_str(&yaml_str) {
        Ok(data) => Ok(data),
        Err(e) => Err(e.into()),
    }
}

pub fn read_cms_config<C: AsRef<Path>>(config: C) -> Result<Vec<Cms>, Box<dyn std::error::Error>> {
    let yaml_str = fs::read_to_string(config)?;

    let cmss: Cmss = serde_yaml::from_str(&yaml_str)?;
    let flat_cmss: Vec<Cms> = cmss.cmss.into_iter().map(|wrapper| wrapper.cms).collect();
    Ok(flat_cmss)
}

/// Writes a list of certificates to a YAML configuration file in the shape
/// expected by [`read_certificate_config`].
///
/// # Arguments
///
/// * `certificates` - The certificates to serialize.
/// * `config` - A path to the YAML configuration file to write.
///
/// # Errors
///
/// Returns an error if the certificates cannot be serialized to YAML or if the
/// file cannot be written.
pub fn write_certificate_config<C: AsRef<Path>>(
    certificates: Vec<Certificate>,
    config: C,
) -> Result<(), Box<dyn std::error::Error>> {
    let wrapped = Certificates {
        certificates: certificates
            .into_iter()
            .map(|certificate| CertificateWrapper { certificate })
            .collect(),
    };
    let yaml_str = serde_yaml::to_string(&wrapped)?;
    fs::write(config, yaml_str)?;
    Ok(())
}

/// Writes CSRs and signing requests to a YAML configuration file in the shape
/// expected by [`read_csr_config`].
///
/// # Arguments
///
/// * `data` - The CSRs and signing requests to serialize.
/// * `config` - A path to the YAML configuration file to write.
///
/// # Errors
///
/// Returns an error if the data cannot be serialized to YAML or if the file
/// cannot be written.
pub fn write_csr_config<C: AsRef<Path>>(
    data: CsrData,
    config: C,
) -> Result<(), Box<dyn std::error::Error>> {
    let wrapped = Csrs {
        csrs: data
            .csrs
            .into_iter()
            .map(|csr| CsrWrapper { csr })
            .collect(),
        signing_requests: data
            .to_sign
            .into_iter()
            .map(|signing_request| SigningRequestWrapper { signing_request })
            .collect(),
    };
    let yaml_str = serde_yaml::to_string(&wrapped)?;
    fs::write(config, yaml_str)?;
    Ok(())
}

/// Writes a CRL to a YAML configuration file in the shape expected by
/// [`read_crl_config`].
///
/// # Arguments
///
/// * `crl` - The CRL to serialize.
/// * `config` - A path to the YAML configuration file to write.
///
/// # Errors
///
/// Returns an error if the CRL cannot be serialized to YAML or if the file
/// cannot be written.
pub fn write_crl_config<C: AsRef<Path>>(
    crl: Crl,
    config: C,
) -> Result<(), Box<dyn std::error::Error>> {
    let yaml_str = serde_yaml::to_string(&crl)?;
    fs::write(config, yaml_str)?;
    Ok(())
}

/// Writes a list of CMS entries to a YAML configuration file in the shape
/// expected by [`read_cms_config`].
///
/// # Arguments
///
/// * `cmss` - The CMS entries to serialize.
/// * `config` - A path to the YAML configuration file to write.
///
/// # Errors
///
/// Returns an error if the CMS entries cannot be serialized to YAML or if the
/// file cannot be written.
pub fn write_cms_config<C: AsRef<Path>>(
    cmss: Vec<Cms>,
    config: C,
) -> Result<(), Box<dyn std::error::Error>> {
    let wrapped = Cmss {
        cmss: cmss.into_iter().map(|cms| CmsWrapper { cms }).collect(),
    };
    let yaml_str = serde_yaml::to_string(&wrapped)?;
    fs::write(config, yaml_str)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hash_alg_maps_to_cert_helper_variant() {
        // Each config HashAlg must convert to its matching cert_helper CHHashAlg.
        // CHHashAlg has no PartialEq, so match on the resulting variant instead.
        assert!(matches!(CHHashAlg::from(HashAlg::SHA1), CHHashAlg::SHA1));
        assert!(matches!(
            CHHashAlg::from(HashAlg::SHA256),
            CHHashAlg::SHA256
        ));
        assert!(matches!(
            CHHashAlg::from(HashAlg::SHA384),
            CHHashAlg::SHA384
        ));
        assert!(matches!(
            CHHashAlg::from(HashAlg::SHA512),
            CHHashAlg::SHA512
        ));
    }

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

    #[test]
    fn test_read_cms_config_valid_yaml() {
        let yaml_content = r#"
cmss:
  - cms:
      id: test1
      signer:
        cert_pem_file: "signer_cert.pem"
        private_key_pem_file: "signer_pkey.pem"
      recipient: client2encrypt_cert.pem
      data_file: ./examples/message.txt
"#;

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        write!(temp_file, "{}", yaml_content).expect("Failed to write to temp file");

        let result = read_cms_config(temp_file.path());
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].id, "test1".to_string());
        assert_eq!(
            data[0].recipient,
            Some("client2encrypt_cert.pem".to_string())
        );
        assert_eq!(data[0].data_file, "./examples/message.txt".to_string());
        assert_eq!(
            data[0].signer,
            Some(Signer {
                cert_pem_file: "signer_cert.pem".to_string(),
                private_key_pem_file: "signer_pkey.pem".to_string()
            })
        )
    }

    #[test]
    fn test_write_certificate_config_round_trips() {
        let cert = Certificate {
            id: "cert1".to_string(),
            parent: None,
            signer: None,
            ca: Some(true),
            pkix: Pkix {
                commonname: "Example CN".to_string(),
                country: "SE".to_string(),
                organization: "Example Org".to_string(),
            },
            keytype: KeyType::RSA,
            altnames: Some(vec!["example.com".to_string()]),
            hashalg: Some(HashAlg::SHA256),
            keylength: Some(2048),
            validto: Some("2030-01-01".to_string()),
            usage: Some(vec![Usage::serverauth, Usage::clientauth]),
        };

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        write_certificate_config(vec![cert], temp_file.path()).unwrap();

        let certs = read_certificate_config(temp_file.path()).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].id, "cert1");
        assert_eq!(certs[0].ca, Some(true));
        assert_eq!(certs[0].pkix.commonname, "Example CN");
        assert_eq!(certs[0].keytype, KeyType::RSA);
        assert_eq!(certs[0].hashalg, Some(HashAlg::SHA256));
        assert_eq!(certs[0].keylength, Some(2048));
        assert_eq!(certs[0].usage.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn hashalg_is_omitted_from_yaml_when_none() {
        // An Ed25519 cert has no hash algorithm; the serialized config must omit
        // the `hashalg` key entirely (not write `hashalg: null`), and still
        // round-trip back to `None`.
        let cert = Certificate {
            id: "ed".to_string(),
            parent: None,
            signer: None,
            ca: Some(false),
            pkix: Pkix {
                commonname: "Ed CN".to_string(),
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

        let wrapped = Certificates {
            certificates: vec![CertificateWrapper {
                certificate: cert.clone(),
            }],
        };
        let yaml = serde_yaml::to_string(&wrapped).unwrap();
        assert!(
            !yaml.contains("hashalg"),
            "hashalg must be omitted when None, got:\n{yaml}"
        );

        // Sanity: a cert WITH a hashalg still serializes it.
        let mut with_hash = cert;
        with_hash.hashalg = Some(HashAlg::SHA256);
        let wrapped = Certificates {
            certificates: vec![CertificateWrapper {
                certificate: with_hash,
            }],
        };
        let yaml = serde_yaml::to_string(&wrapped).unwrap();
        assert!(yaml.contains("hashalg"), "hashalg must serialize when Some");
    }

    #[test]
    fn test_write_csr_config_round_trips() {
        let csr = Csr {
            id: "csr1".to_string(),
            pkix: Pkix {
                commonname: "Example CN".to_string(),
                country: "SE".to_string(),
                organization: "Example Org".to_string(),
            },
            keytype: KeyType::RSA,
            altnames: None,
            hashalg: Some(HashAlg::SHA256),
            keylength: Some(2048),
            usage: None,
        };
        let signing_request = SigningRequest {
            csr_pem_file: "csr.pem".to_string(),
            signer: Signer {
                cert_pem_file: "signer_cert.pem".to_string(),
                private_key_pem_file: "signer_pkey.pem".to_string(),
            },
            validto: Some("2030-01-01".to_string()),
            ca: Some(true),
        };

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        write_csr_config(
            CsrData {
                csrs: vec![csr],
                to_sign: vec![signing_request.clone()],
            },
            temp_file.path(),
        )
        .unwrap();

        let data = read_csr_config(temp_file.path()).unwrap();
        assert_eq!(data.csrs.len(), 1);
        assert_eq!(data.csrs[0].id, "csr1");
        assert_eq!(data.to_sign.len(), 1);
        assert_eq!(data.to_sign[0], signing_request);
    }

    #[test]
    fn test_write_crl_config_round_trips_serial_as_hex() {
        let serial =
            BigUint::from_str_radix("224a77d33809ab2f6524c7cda6ae22e1ce1e7ad9", 16).unwrap();
        let crl = Crl {
            crl_file: "file_cer.pem".to_string(),
            signer: Signer {
                cert_pem_file: "signer_cert.pem".to_string(),
                private_key_pem_file: "signer_pkey.pem".to_string(),
            },
            revoked: vec![RevokedCert {
                cert_info: CertInfo {
                    serial: serial.clone(),
                    reason: Reason::KeyCompromise,
                },
            }],
        };

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        write_crl_config(crl, temp_file.path()).unwrap();

        let data = read_crl_config(temp_file.path()).unwrap();
        assert_eq!(data.crl_file, "file_cer.pem");
        assert_eq!(data.revoked.len(), 1);
        assert_eq!(data.revoked[0].cert_info.serial, serial);
    }

    #[test]
    fn test_write_cms_config_round_trips() {
        let cms = Cms {
            id: "test1".to_string(),
            signer: Some(Signer {
                cert_pem_file: "signer_cert.pem".to_string(),
                private_key_pem_file: "signer_pkey.pem".to_string(),
            }),
            recipient: Some("client2encrypt_cert.pem".to_string()),
            data_file: "./examples/message.txt".to_string(),
            detached: None,
        };

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        write_cms_config(vec![cms], temp_file.path()).unwrap();

        let data = read_cms_config(temp_file.path()).unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].id, "test1");
        assert_eq!(
            data[0].recipient,
            Some("client2encrypt_cert.pem".to_string())
        );
        assert_eq!(data[0].data_file, "./examples/message.txt");
    }
}
