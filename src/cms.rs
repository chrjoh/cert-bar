use crate::config::Cms;
use cert_helper::certificate::Certificate as CHCertificate;
use cms::builder::{
    ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyEncryptionInfo,
    KeyTransRecipientInfoBuilder, SignedDataBuilder, SignerInfoBuilder,
};
use cms::cert::x509::Certificate;
use cms::cert::x509::der::{Decode, Encode};
use cms::content_info::ContentInfo;
use cms::enveloped_data::RecipientIdentifier;
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use der::asn1::ObjectIdentifier;
use der::{Any, Tag, TagNumber};
use ecdsa::SigningKey as EcdsaSigningKey;
use ecdsa::der::Signature as EcdsaDerSignature;
use p256::{NistP256, SecretKey as P256SecretKey};
use p384::{NistP384, SecretKey as P384SecretKey};
use rand::thread_rng;
use rsa::pkcs1::der::DecodePem;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::DecodeRsaPublicKey};
use sha2::Sha256;
use spki::AlgorithmIdentifierOwned;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use x509_cert::Certificate as X509Certificate;

pub fn handle<C: AsRef<Path>>(
    cms_data: Vec<Cms>,
    output_dir: C,
) -> Result<(), Box<dyn std::error::Error>> {
    for cms in &cms_data {
        match create_cms(&cms) {
            Ok(res) => {
                if let Some(signer) = &cms.signer {
                    let signer_cert = CHCertificate::load_cert_and_key(
                        &signer.cert_pem_file,
                        &signer.private_key_pem_file,
                    )?;
                    match create_pkcs7_signed_data(&res, &signer_cert) {
                        Ok(pkcs7_der) => {
                            save_file_with_extension(&output_dir, &cms.id, "pkcs7", pkcs7_der)
                                .expect("failed to save cms file");
                        }
                        Err(e) => {
                            eprintln!("Failed to create pkcs7 signed data: {}", e);
                            continue;
                        }
                    }
                } else {
                    save_file_with_extension(&output_dir, &cms.id, "cms", res)
                        .expect("failed to save");
                }
            }
            Err(e) => {
                eprintln!("Failed to create cms: {}", e);
                continue;
            }
        }
    }
    Ok(())
}

fn create_cms(cms: &Cms) -> Result<Vec<u8>, cms::builder::Error> {
    let cert_pem =
        std::fs::read(&cms.recipient).map_err(|e| cms::builder::Error::Builder(e.to_string()))?;
    let cert = Certificate::from_pem(&cert_pem)?;

    let plaintext = if std::path::Path::new(&cms.data_file).exists() {
        std::fs::read(&cms.data_file).map_err(|e| cms::builder::Error::Builder(e.to_string()))?
    } else {
        return Err(cms::builder::Error::Builder(
            "Found no file with message data".to_string(),
        ));
    };
    const RSA_ENCRYPTION_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    let algorithm_oid = &cert.tbs_certificate.subject_public_key_info.algorithm.oid;
    if *algorithm_oid != RSA_ENCRYPTION_OID {
        eprintln!(
            "Certificate does not use RSA encryption. Found OID: {}",
            algorithm_oid
        );
        return Err(cms::builder::Error::Builder(
            "Can only create CMS using RSA key".to_string(),
        ));
    }
    let recipient_id =
        RecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        });

    let public_key_der = &cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    let rsa_public_key = RsaPublicKey::from_pkcs1_der(public_key_der)
        .map_err(|e| cms::builder::Error::Builder(e.to_string()))?;

    // Create key encryption info for RSA
    let key_encryption_info = KeyEncryptionInfo::Rsa(rsa_public_key);

    let mut rng = thread_rng();

    // Create the recipient info builder first
    let recipient_builder =
        KeyTransRecipientInfoBuilder::new(recipient_id, key_encryption_info, &mut rng)?;

    // Create the EnvelopedDataBuilder and add recipient in one go
    let mut builder = EnvelopedDataBuilder::new(
        None,                                  // originator_info - typically None for basic usage
        &plaintext,                            // unencrypted_content
        ContentEncryptionAlgorithm::Aes256Cbc, // content_encryption_algorithm
        None, // unprotected_attributes - typically None for basic usage
    )?;

    // Add the recipient to the builder
    builder.add_recipient_info(recipient_builder)?;
    const ENVELOPED_DATA_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
    // Build the EnvelopedData with a fresh RNG
    let mut rng2 = thread_rng();
    let enveloped = builder.build_with_rng(&mut rng2)?;
    let enveloped_der = enveloped.to_der()?;
    let explicit_tag = TagNumber::N0.context_specific(true);
    let content = Any::from_der(&enveloped_der)?;

    let content_info = ContentInfo {
        content_type: ENVELOPED_DATA_OID,
        content,
    };

    // Serialize the EnvelopedData directly
    let der_encoded = content_info.to_der()?;

    Ok(der_encoded)
}

//fn create_pkcs7_signed_data(
//    data: &[u8],
//    signer: &CHCertificate,
//) -> Result<Vec<u8>, cms::builder::Error> {
//    const DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
//    let encapsulated_content = EncapsulatedContentInfo {
//        econtent_type: DATA_OID, // This is key!
//        econtent: Some(Any::new(Tag::OctetString, data)?),
//    };
//    let private_key = signer
//        .pkey
//        .as_ref()
//        .ok_or("Private key is required for signing")
//        .map_err(|e| cms::builder::Error::Builder(e.to_string()))?;
//
//    let pem_bytes = private_key
//        .private_key_to_pem_pkcs8()
//        .map_err(|e| format!("Failed to convert private key to PEM: {}", e))
//        .map_err(|e| cms::builder::Error::Builder(e.to_string()))?;
//
//    let pem_string = String::from_utf8(pem_bytes)
//        .map_err(|e| format!("Failed to convert PEM bytes to string: {}", e))
//        .map_err(|e| cms::builder::Error::Builder(e.to_string()))?;
//
//    let rsa_private_key = RsaPrivateKey::from_pkcs8_pem(&pem_string)
//        .map_err(|e| format!("Failed to parse RSA private key: {}", e))
//        .map_err(|e| cms::builder::Error::Builder(e.to_string()))?;
//
//    let signer_key = SigningKey::<Sha256>::new(rsa_private_key);
//    let signer_cert = Certificate::from_pem(signer.x509.to_pem().unwrap())?;
//    let signer_identifier =
//        SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
//            issuer: signer_cert.tbs_certificate.issuer.clone(),
//            serial_number: signer_cert.tbs_certificate.serial_number.clone(),
//        });
//    const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
//    let digest_algorithm = AlgorithmIdentifierOwned {
//        oid: SHA256_OID,
//        parameters: None,
//    };
//
//    let signer_info_builder = SignerInfoBuilder::new(
//        &signer_key,
//        signer_identifier,
//        digest_algorithm.clone(),
//        &encapsulated_content,
//        None, // No signed attributes for now
//    )?;
//    let openssl_pem = signer.x509.to_pem().map_err(|e| {
//        cms::builder::Error::Builder(format!("Failed to convert certificate to PEM: {}", e))
//    })?;
//    let x509_cert = X509Certificate::from_pem(&openssl_pem).map_err(|e| {
//        cms::builder::Error::Builder(format!("Failed to parse x509 certificate: {}", e))
//    })?;
//    let mut signed_builder = SignedDataBuilder::new(&encapsulated_content);
//    let signed_data = signed_builder
//        .add_digest_algorithm(digest_algorithm)?
//        .add_certificate(cms::cert::CertificateChoices::Certificate(x509_cert))?
//        .add_signer_info::<SigningKey<Sha256>, rsa::pkcs1v15::Signature>(signer_info_builder)?
//        .build()?;
//
//    let signed_der = signed_data.to_der()?;
//
//    Ok(signed_der)
//}
/////////
#[derive(Debug)]
enum DetectedKey {
    Rsa(SigningKey<Sha256>),
    P256(EcdsaSigningKey<NistP256>),
    P384(EcdsaSigningKey<NistP384>),
    // Easy to add new variants here
}
impl DetectedKey {
    fn from_pem(pem_string: &str) -> Result<Self, cms::builder::Error> {
        // Try RSA first
        if let Ok(rsa_private_key) = RsaPrivateKey::from_pkcs8_pem(pem_string) {
            let signing_key = SigningKey::<Sha256>::new(rsa_private_key);
            return Ok(DetectedKey::Rsa(signing_key));
        }

        // Try P-256 ECDSA
        if let Ok(p256_key) = P256SecretKey::from_pkcs8_pem(pem_string) {
            let signing_key = EcdsaSigningKey::<NistP256>::from(p256_key);
            return Ok(DetectedKey::P256(signing_key));
        }

        // Try P-384 ECDSA
        if let Ok(p384_key) = P384SecretKey::from_pkcs8_pem(pem_string) {
            let signing_key = EcdsaSigningKey::<NistP384>::from(p384_key);
            return Ok(DetectedKey::P384(signing_key));
        }

        Err(cms::builder::Error::Builder(
            "Unsupported key type or invalid key format".to_string(),
        ))
    }
    fn create_signed_data(
        &self,
        encapsulated_content: &EncapsulatedContentInfo,
        signer_identifier: SignerIdentifier,
        digest_algorithm: AlgorithmIdentifierOwned,
        x509_cert: X509Certificate,
    ) -> Result<Vec<u8>, cms::builder::Error> {
        // Return Vec<u8> instead of SignedData
        match self {
            DetectedKey::Rsa(signing_key) => {
                let signer_info_builder = SignerInfoBuilder::new(
                    signing_key,
                    signer_identifier,
                    digest_algorithm.clone(),
                    encapsulated_content,
                    None,
                )?;

                let mut signed_builder = SignedDataBuilder::new(encapsulated_content);
                let signed_data = signed_builder
                    .add_digest_algorithm(digest_algorithm)?
                    .add_certificate(cms::cert::CertificateChoices::Certificate(x509_cert))?
                    .add_signer_info::<SigningKey<Sha256>, rsa::pkcs1v15::Signature>(
                        signer_info_builder,
                    )?
                    .build()?;

                signed_data.to_der().map_err(|e| {
                    cms::builder::Error::Builder(format!("Failed to serialize to DER: {}", e))
                })
            }

            DetectedKey::P256(signing_key) => {
                let signer_info_builder = SignerInfoBuilder::new(
                    signing_key,
                    signer_identifier,
                    digest_algorithm.clone(),
                    encapsulated_content,
                    None,
                )?;

                let mut signed_builder = SignedDataBuilder::new(encapsulated_content);
                let signed_data = signed_builder
                    .add_digest_algorithm(digest_algorithm)?
                    .add_certificate(cms::cert::CertificateChoices::Certificate(x509_cert))?
                    .add_signer_info::<EcdsaSigningKey<NistP256>, EcdsaDerSignature<NistP256>>(
                        signer_info_builder,
                    )?
                    .build()?;

                signed_data.to_der().map_err(|e| {
                    cms::builder::Error::Builder(format!("Failed to serialize to DER: {}", e))
                })
            }
            DetectedKey::P384(signing_key) => {
                let signer_info_builder = SignerInfoBuilder::new(
                    signing_key,
                    signer_identifier,
                    digest_algorithm.clone(),
                    encapsulated_content,
                    None,
                )?;

                let mut signed_builder = SignedDataBuilder::new(encapsulated_content);
                let signed_data = signed_builder
                    .add_digest_algorithm(digest_algorithm)?
                    .add_certificate(cms::cert::CertificateChoices::Certificate(x509_cert))?
                    .add_signer_info::<EcdsaSigningKey<NistP384>, EcdsaDerSignature<NistP384>>(
                        signer_info_builder,
                    )?
                    .build()?;

                signed_data.to_der().map_err(|e| {
                    cms::builder::Error::Builder(format!("Failed to serialize to DER: {}", e))
                })
            }
        }
    }
}
fn create_pkcs7_signed_data(
    data: &[u8],
    signer: &CHCertificate,
) -> Result<Vec<u8>, cms::builder::Error> {
    const DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
    let encapsulated_content = EncapsulatedContentInfo {
        econtent_type: DATA_OID,
        econtent: Some(Any::new(Tag::OctetString, data)?),
    };

    let private_key = signer
        .pkey
        .as_ref()
        .ok_or("Private key is required for signing")
        .map_err(|e| cms::builder::Error::Builder(e.to_string()))?;

    let pem_bytes = private_key
        .private_key_to_pem_pkcs8()
        .map_err(|e| format!("Failed to convert private key to PEM: {}", e))
        .map_err(|e| cms::builder::Error::Builder(e.to_string()))?;

    let pem_string = String::from_utf8(pem_bytes)
        .map_err(|e| format!("Failed to convert PEM bytes to string: {}", e))
        .map_err(|e| cms::builder::Error::Builder(e.to_string()))?;

    // Detect the key type
    let detected_key = DetectedKey::from_pem(&pem_string)?;

    let signer_cert = Certificate::from_pem(signer.x509.to_pem().unwrap())?;
    let signer_identifier =
        SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
            issuer: signer_cert.tbs_certificate.issuer.clone(),
            serial_number: signer_cert.tbs_certificate.serial_number.clone(),
        });

    const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: SHA256_OID,
        parameters: None,
    };

    let openssl_pem = signer.x509.to_pem().map_err(|e| {
        cms::builder::Error::Builder(format!("Failed to convert certificate to PEM: {}", e))
    })?;
    let x509_cert = X509Certificate::from_pem(&openssl_pem).map_err(|e| {
        cms::builder::Error::Builder(format!("Failed to parse x509 certificate: {}", e))
    })?;

    // Create signed data using the detected key
    detected_key.create_signed_data(
        &encapsulated_content,
        signer_identifier,
        digest_algorithm,
        x509_cert,
    )
}

/// Saves a Vec<u8> to a file at the specified path with the given filename and extension.
///
/// # Arguments
/// * `path` - The directory path where the file should be saved
/// * `filename` - The base filename (without extension)
/// * `extension` - The file extension (without the dot)
/// * `data` - The data to write to the file
///
/// # Examples
/// ```
/// let data = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello" in bytes
/// save_file_with_extension("./output", "message", "txt", data).unwrap();
/// // Creates: ./output/message.txt
/// ```
pub fn save_file_with_extension<P: AsRef<Path>>(
    path: P,
    filename: &str,
    extension: &str,
    data: Vec<u8>,
) -> Result<PathBuf, io::Error> {
    let dir_path = path.as_ref();
    if !dir_path.exists() {
        fs::create_dir_all(dir_path)?;
    }

    let file_path = dir_path.join(filename).with_extension(extension);

    fs::write(&file_path, data)?;

    Ok(file_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Cms;
    use cert_helper::certificate::{CertBuilder, UseesBuilderFields};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn dummy_certificate() -> CHCertificate {
        CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .build_and_self_sign()
            .unwrap()
    }

    fn dummy_rsa_certificate() -> CHCertificate {
        CertBuilder::new()
            .common_name("RSA Test Cert")
            .key_type(cert_helper::certificate::KeyType::RSA2048)
            .is_ca(false)
            .build_and_self_sign()
            .unwrap()
    }

    fn dummy_p256_certificate() -> CHCertificate {
        CertBuilder::new()
            .common_name("P256 Test Cert")
            .key_type(cert_helper::certificate::KeyType::P256)
            .is_ca(false)
            .build_and_self_sign()
            .unwrap()
    }

    fn dummy_p384_certificate() -> CHCertificate {
        CertBuilder::new()
            .common_name("P384 Test Cert")
            .key_type(cert_helper::certificate::KeyType::P384)
            .is_ca(false)
            .build_and_self_sign()
            .unwrap()
    }

    fn create_test_cms_config_with_files(
        recipient_cert: &CHCertificate,
        data: &str,
    ) -> (Cms, NamedTempFile, NamedTempFile) {
        // Create temporary files for the test
        let mut cert_file = NamedTempFile::new().unwrap();
        let mut data_file = NamedTempFile::new().unwrap();

        // Write certificate to temp file
        let cert_pem = recipient_cert.x509.to_pem().unwrap();
        cert_file.write_all(&cert_pem).unwrap();
        cert_file.flush().unwrap();

        // Write test data to temp file
        data_file.write_all(data.as_bytes()).unwrap();
        data_file.flush().unwrap();

        let cms_config = Cms {
            id: "test".to_string(),
            recipient: cert_file.path().to_string_lossy().to_string(),
            data_file: data_file.path().to_string_lossy().to_string(),
            signer: None,
        };

        // Return the config AND the temp files to keep them alive
        (cms_config, cert_file, data_file)
    }

    #[test]
    fn test_create_cms_with_rsa_certificate() {
        let rsa_cert = dummy_rsa_certificate();
        let test_data = "Hello, RSA CMS world!";
        let (cms_config, _cert_file, _data_file) =
            create_test_cms_config_with_files(&rsa_cert, test_data);

        let result = create_cms(&cms_config);

        assert!(
            result.is_ok(),
            "Failed to create CMS with RSA certificate: {:?}",
            result.err()
        );
        let cms_der = result.unwrap();
        assert!(!cms_der.is_empty(), "CMS DER data should not be empty");

        // Basic validation - should start with SEQUENCE tag (0x30)
        assert_eq!(cms_der[0], 0x30, "CMS should start with SEQUENCE tag");
    }

    #[test]
    fn test_create_cms_with_p256_certificate_should_fail() {
        let p256_cert = dummy_p256_certificate();
        let test_data = "Hello, P256 CMS world!";
        let (cms_config, _cert_file, _data_file) =
            create_test_cms_config_with_files(&p256_cert, test_data);

        let result = create_cms(&cms_config);

        assert!(
            result.is_err(),
            "CMS creation with P256 certificate should fail"
        );
        let error_msg = result.err().unwrap().to_string();
        assert!(
            error_msg.contains("not supported") || error_msg.contains("RSA"),
            "Error should mention lack of ECDSA support: {}",
            error_msg
        );
    }

    #[test]
    fn test_create_cms_with_p384_certificate_should_fail() {
        let p384_cert = dummy_p384_certificate();
        let test_data = "Hello, P384 CMS world!";
        let (cms_config, _cert_file, _data_file) =
            create_test_cms_config_with_files(&p384_cert, test_data);

        let result = create_cms(&cms_config);

        assert!(
            result.is_err(),
            "CMS creation with P384 certificate should fail"
        );
        let error_msg = result.err().unwrap().to_string();
        assert!(
            error_msg.contains("not supported") || error_msg.contains("RSA"),
            "Error should mention lack of ECDSA support: {}",
            error_msg
        );
    }

    #[test]
    fn test_create_cms_with_nonexistent_files() {
        let cms_config = Cms {
            id: "test".to_string(),
            recipient: "nonexistent_cert.pem".to_string(),
            data_file: "nonexistent_data.txt".to_string(),
            signer: None,
        };

        let result = create_cms(&cms_config);

        assert!(
            result.is_err(),
            "Should return error when certificate file doesn't exist"
        );
    }

    #[test]
    fn test_create_pkcs7_signed_data_with_rsa() {
        let rsa_cert = dummy_rsa_certificate();
        let test_data = b"Hello, RSA PKCS7 world!";

        let result = create_pkcs7_signed_data(test_data, &rsa_cert);

        assert!(
            result.is_ok(),
            "Failed to create PKCS7 with RSA certificate: {:?}",
            result.err()
        );
        let pkcs7_der = result.unwrap();
        assert!(!pkcs7_der.is_empty(), "PKCS7 DER data should not be empty");

        // Basic validation - should start with SEQUENCE tag (0x30)
        assert_eq!(pkcs7_der[0], 0x30, "PKCS7 should start with SEQUENCE tag");
    }

    #[test]
    fn test_create_pkcs7_signed_data_with_p256() {
        let p256_cert = dummy_p256_certificate();
        let test_data = b"Hello, P256 PKCS7 world!";

        let result = create_pkcs7_signed_data(test_data, &p256_cert);

        assert!(
            result.is_ok(),
            "Failed to create PKCS7 with P256 certificate: {:?}",
            result.err()
        );
        let pkcs7_der = result.unwrap();
        assert!(!pkcs7_der.is_empty(), "PKCS7 DER data should not be empty");

        // Basic validation - should start with SEQUENCE tag (0x30)
        assert_eq!(pkcs7_der[0], 0x30, "PKCS7 should start with SEQUENCE tag");
    }

    #[test]
    fn test_create_pkcs7_signed_data_with_p384() {
        let p384_cert = dummy_p384_certificate();
        let test_data = b"Hello, P384 PKCS7 world!";

        let result = create_pkcs7_signed_data(test_data, &p384_cert);

        assert!(
            result.is_ok(),
            "Failed to create PKCS7 with P384 certificate: {:?}",
            result.err()
        );
        let pkcs7_der = result.unwrap();
        assert!(!pkcs7_der.is_empty(), "PKCS7 DER data should not be empty");

        // Basic validation - should start with SEQUENCE tag (0x30)
        assert_eq!(pkcs7_der[0], 0x30, "PKCS7 should start with SEQUENCE tag");
    }

    #[test]
    fn test_create_pkcs7_signed_data_with_empty_data() {
        let rsa_cert = dummy_rsa_certificate();
        let test_data = b"";

        let result = create_pkcs7_signed_data(test_data, &rsa_cert);

        assert!(result.is_ok(), "Should be able to sign empty data");
        let pkcs7_der = result.unwrap();
        assert!(
            !pkcs7_der.is_empty(),
            "PKCS7 DER data should not be empty even for empty input"
        );
    }

    #[test]
    fn test_create_pkcs7_signed_data_with_large_data() {
        let rsa_cert = dummy_rsa_certificate();
        let large_data = vec![0x42u8; 10000]; // 10KB of data

        let result = create_pkcs7_signed_data(&large_data, &rsa_cert);

        assert!(result.is_ok(), "Should be able to sign large data");
        let pkcs7_der = result.unwrap();
        assert!(!pkcs7_der.is_empty(), "PKCS7 DER data should not be empty");
    }

    #[test]
    fn test_detected_key_from_pem_rsa() {
        let rsa_cert = dummy_rsa_certificate();
        let pem_bytes = rsa_cert
            .pkey
            .as_ref()
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        let pem_string = String::from_utf8(pem_bytes).unwrap();

        let result = DetectedKey::from_pem(&pem_string);

        assert!(result.is_ok(), "Should detect RSA key from PEM");
        match result.unwrap() {
            DetectedKey::Rsa(_) => {}
            _ => panic!("Expected RSA key type"),
        }
    }

    #[test]
    fn test_detected_key_from_pem_p256() {
        let p256_cert = dummy_p256_certificate();
        let pem_bytes = p256_cert
            .pkey
            .as_ref()
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        let pem_string = String::from_utf8(pem_bytes).unwrap();

        let result = DetectedKey::from_pem(&pem_string);

        assert!(result.is_ok(), "Should detect P256 key from PEM");
        match result.unwrap() {
            DetectedKey::P256(_) => {}
            _ => panic!("Expected P256 key type"),
        }
    }

    #[test]
    fn test_detected_key_from_pem_p384() {
        let p384_cert = dummy_p384_certificate();
        let pem_bytes = p384_cert
            .pkey
            .as_ref()
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        let pem_string = String::from_utf8(pem_bytes).unwrap();

        let result = DetectedKey::from_pem(&pem_string);

        assert!(result.is_ok(), "Should detect P384 key from PEM");
        match result.unwrap() {
            DetectedKey::P384(_) => {}
            _ => panic!("Expected P384 key type"),
        }
    }

    #[test]
    fn test_detected_key_from_invalid_pem() {
        let invalid_pem = "-----BEGIN PRIVATE KEY-----\ninvalid data\n-----END PRIVATE KEY-----";

        let result = DetectedKey::from_pem(invalid_pem);

        assert!(result.is_err(), "Should fail with invalid PEM data");
    }

    #[test]
    fn test_detected_key_from_unsupported_key_type() {
        // This test assumes you might have other key types in the future
        let unsupported_pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----";

        let result = DetectedKey::from_pem(unsupported_pem);

        assert!(result.is_err(), "Should fail with unsupported key type");
    }

    #[test]
    fn test_cms_and_pkcs7_integration() {
        // Test creating CMS and then signing it
        let rsa_cert = dummy_rsa_certificate();
        let test_data = "Integration test data";
        let (cms_config, _cert_file, _data_file) =
            create_test_cms_config_with_files(&rsa_cert, test_data);

        // Create CMS envelope
        let cms_result = create_cms(&cms_config);
        assert!(cms_result.is_ok(), "CMS creation should succeed");
        let cms_der = cms_result.unwrap();

        // Sign the CMS data
        let pkcs7_result = create_pkcs7_signed_data(&cms_der, &rsa_cert);
        assert!(pkcs7_result.is_ok(), "PKCS7 signing should succeed");
        let pkcs7_der = pkcs7_result.unwrap();

        // Both should produce valid DER data
        assert!(!cms_der.is_empty());
        assert!(!pkcs7_der.is_empty());
        assert_ne!(cms_der, pkcs7_der, "CMS and PKCS7 data should be different");
    }
}
