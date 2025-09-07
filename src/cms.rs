use crate::config::Cms;
use cert_helper::certificate::Certificate as CHCertificate;
use chrono::{DateTime, Utc};
use cms::builder::{
    ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyEncryptionInfo,
    KeyTransRecipientInfoBuilder, SignedDataBuilder, SignerInfoBuilder,
};
use cms::cert::x509::Certificate;
use cms::cert::x509::der::{Decode, Encode};
use cms::content_info::ContentInfo;
use cms::enveloped_data::RecipientIdentifier;
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der::{Any, Tag, TagNumber};
use ecdsa::SigningKey as EcdsaSigningKey;
use ecdsa::der::Signature as EcdsaDerSignature;
use p256::{NistP256, SecretKey as P256SecretKey};
use p384::{NistP384, SecretKey as P384SecretKey};
use rand::{RngCore, thread_rng};
use rsa::pkcs1::der::DecodePem;
use rsa::pkcs1v15;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::DecodeRsaPublicKey};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use x509_cert::Certificate as X509Certificate;
use x509_cert::attr::{Attribute, AttributeValue};
use x509_cert::ext::pkix::KeyUsage;
use x509_cert::time::Time;

/// Processes a list of CMS configurations and generates corresponding CMS files.
///
/// This function handles the complete CMS generation workflow:
/// 1. Creates encrypted CMS messages (EnvelopedData) for each configuration
/// 2. Optionally creates signed CMS messages (SignedData) if a signer is provided
/// 3. Saves the generated files to the specified output directory
///
/// # Arguments
///
/// * `cms_data` - A vector of CMS configurations to process
/// * `output_dir` - The directory where generated CMS files will be saved
///
/// # Returns
///
/// * `Ok(())` - If all CMS configurations were processed successfully
/// * `Err(Box<dyn std::error::Error>)` - If there was an error loading signer certificates
///
/// # Generated Files
///
/// For each CMS configuration with ID "example":
/// * `{output_dir}/{id}.cms` - Encrypted CMS message in DER format
/// * `{output_dir}/{id}.pkcs7` - Signed CMS message in PKCS#7 format (only if signer is provided)
///
/// # Behavior
///
/// * **Non-fatal errors**: If CMS creation fails for one configuration, the function continues
///   processing remaining configurations and logs the error to stderr
/// * **Fatal errors**: Only signer certificate loading errors cause the function to return early
/// * **File overwriting**: Existing files with the same names will be overwritten
///
/// # Cryptographic Operations
///
/// * **Encryption**: Uses AES-256-CBC for content encryption, RSA key transport for key encryption
/// * **Signing**: Supports RSA, P-256, and P-384 keys with SHA-256 hashing
/// * **Recipient limitations**: Only RSA certificates are supported for encryption recipients
///
/// # Error Handling
///
/// Individual CMS generation failures are logged but don't stop processing:
/// ```text
/// Failed to create cms: Unsupported key algorithm for encryption. Found OID: 1.2.840.10045.3.1.7
/// Failed to create pkcs7 signed data: Invalid key format
/// ```
///
/// Only signer certificate loading errors cause early termination.
pub fn handle<C: AsRef<Path>>(
    cms_data: Vec<Cms>,
    output_dir: C,
) -> Result<(), Box<dyn std::error::Error>> {
    for cms in &cms_data {
        match create_cms(&cms) {
            Ok(res) => {
                save_file_with_extension(&output_dir, &cms.id, "cms", &res)
                    .expect("failed to save");
                if let Some(signer) = &cms.signer {
                    let signer_cert = CHCertificate::load_cert_and_key(
                        &signer.cert_pem_file,
                        &signer.private_key_pem_file,
                    )?;
                    let detached = cms.detached.unwrap_or(false);
                    match create_pkcs7_signed_data(&res, &signer_cert, detached) {
                        Ok(pkcs7_der) => {
                            let extension = if detached { "p7s" } else { "pkcs7" };
                            save_file_with_extension(&output_dir, &cms.id, extension, &pkcs7_der)
                                .expect("failed to save cms file");
                        }
                        Err(e) => {
                            eprintln!("Failed to create pkcs7 signed data: {}", e);
                            continue;
                        }
                    }
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
    match verify_encrypting_certificate(&cert) {
        Ok(_) => {}
        Err(e) => {
            return Err(cms::builder::Error::Builder(format!(
                "Recipient certificate can not be used for encryption: {}",
                e
            )));
        }
    }
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

    let key_encryption_info = KeyEncryptionInfo::Rsa(rsa_public_key);

    let mut rng = thread_rng();

    let recipient_builder =
        KeyTransRecipientInfoBuilder::new(recipient_id, key_encryption_info, &mut rng)?;

    // Create the EnvelopedDataBuilder and add recipient in one go
    let mut builder = EnvelopedDataBuilder::new(
        None,                                  // originator_info
        &plaintext,                            // unencrypted_content
        ContentEncryptionAlgorithm::Aes256Cbc, // content_encryption_algorithm
        None,                                  // unprotected_attributes
    )?;

    builder.add_recipient_info(recipient_builder)?;
    const ENVELOPED_DATA_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
    // Build the EnvelopedData with a fresh RNG to avoid issues with the cms crate
    let mut rng2 = thread_rng();
    let enveloped = builder.build_with_rng(&mut rng2)?;
    let enveloped_der = enveloped.to_der()?;
    let explicit_tag = TagNumber::N0.context_specific(true);
    let content = Any::from_der(&enveloped_der)?;

    let content_info = ContentInfo {
        content_type: ENVELOPED_DATA_OID,
        content,
    };

    let der_encoded = content_info.to_der()?;

    Ok(der_encoded)
}

#[derive(Debug)]
enum DetectedKey {
    Rsa(pkcs1v15::SigningKey<Sha256>),
    P256(EcdsaSigningKey<NistP256>),
    P384(EcdsaSigningKey<NistP384>),
}

impl DetectedKey {
    fn from_pem(pem_string: &str) -> Result<Self, cms::builder::Error> {
        // Try RSA first
        if let Ok(rsa_private_key) = RsaPrivateKey::from_pkcs8_pem(pem_string) {
            let signing_key = pkcs1v15::SigningKey::<Sha256>::new(rsa_private_key);
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
        data: Option<&[u8]>,
    ) -> Result<Vec<u8>, cms::builder::Error> {
        const RFC8894_ID_SENDER_NONCE: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.5");
        let mut nonce_bytes = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut nonce_bytes);
        let mut sender_nonce_value: SetOfVec<AttributeValue> = Default::default();
        let nonce = OctetString::new(nonce_bytes).unwrap();
        sender_nonce_value
            .insert(Any::new(Tag::OctetString, nonce.as_bytes()).unwrap())
            .unwrap();
        let sender_nonce = Attribute {
            oid: RFC8894_ID_SENDER_NONCE,
            values: sender_nonce_value,
        };

        match self {
            DetectedKey::Rsa(signing_key) => {
                let mut signer_info_builder = SignerInfoBuilder::new(
                    signing_key,
                    signer_identifier,
                    digest_algorithm.clone(),
                    encapsulated_content,
                    None,
                )?;
                signer_info_builder
                    .add_signed_attribute(sender_nonce)
                    .unwrap();
                if let Some(original_data) = data {
                    signer_info_builder
                        .add_signed_attribute(DetectedKey::add_content_type_attribute()?)
                        .unwrap();
                    signer_info_builder
                        .add_signed_attribute(DetectedKey::add_signing_time_attribute()?)
                        .unwrap();
                    let message_digest_attr =
                        DetectedKey::detached_hash_calculated_attribute(original_data)?;
                    signer_info_builder
                        .add_signed_attribute(message_digest_attr)
                        .unwrap();
                }
                let mut signed_builder = SignedDataBuilder::new(encapsulated_content);
                let signed_data = signed_builder
                    .add_digest_algorithm(digest_algorithm)?
                    .add_certificate(cms::cert::CertificateChoices::Certificate(x509_cert))?
                    .add_signer_info::<pkcs1v15::SigningKey<Sha256>, rsa::pkcs1v15::Signature>(
                        signer_info_builder,
                    )?
                    .build()?;

                signed_data.to_der().map_err(|e| {
                    cms::builder::Error::Builder(format!("Failed to serialize to DER: {}", e))
                })
            }

            DetectedKey::P256(signing_key) => {
                let mut signer_info_builder = SignerInfoBuilder::new(
                    signing_key,
                    signer_identifier,
                    digest_algorithm.clone(),
                    encapsulated_content,
                    None,
                )?;
                signer_info_builder
                    .add_signed_attribute(sender_nonce)
                    .unwrap();
                if let Some(original_data) = data {
                    signer_info_builder
                        .add_signed_attribute(DetectedKey::add_content_type_attribute()?)
                        .unwrap();
                    signer_info_builder
                        .add_signed_attribute(DetectedKey::add_signing_time_attribute()?)
                        .unwrap();
                    let message_digest_attr =
                        DetectedKey::detached_hash_calculated_attribute(original_data)?;
                    signer_info_builder
                        .add_signed_attribute(message_digest_attr)
                        .unwrap();
                }
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
                let mut signer_info_builder = SignerInfoBuilder::new(
                    signing_key,
                    signer_identifier,
                    digest_algorithm.clone(),
                    encapsulated_content,
                    None,
                )?;
                signer_info_builder
                    .add_signed_attribute(sender_nonce)
                    .unwrap();
                if let Some(original_data) = data {
                    signer_info_builder
                        .add_signed_attribute(DetectedKey::add_content_type_attribute()?)
                        .unwrap();
                    signer_info_builder
                        .add_signed_attribute(DetectedKey::add_signing_time_attribute()?)
                        .unwrap();
                    let message_digest_attr =
                        DetectedKey::detached_hash_calculated_attribute(original_data)?;
                    signer_info_builder
                        .add_signed_attribute(message_digest_attr)
                        .unwrap();
                }
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
    fn add_signing_time_attribute() -> Result<Attribute, cms::builder::Error> {
        const SIGNING_TIME_OID: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

        let time_string = format!("{}Z", chrono::Utc::now().format("%y%m%d%H%M%S"));
        let time_bytes = time_string.as_bytes();

        let mut signing_time_value: SetOfVec<AttributeValue> = Default::default();
        let time_any = Any::new(Tag::UtcTime, time_bytes)
            .map_err(|e| cms::builder::Error::Builder(format!("Time Any creation error: {}", e)))?;
        signing_time_value
            .insert(time_any)
            .map_err(|e| cms::builder::Error::Builder(format!("Time insertion error: {}", e)))?;
        Ok(Attribute {
            oid: SIGNING_TIME_OID,
            values: signing_time_value,
        })
    }
    fn add_content_type_attribute() -> Result<Attribute, cms::builder::Error> {
        const CONTENT_TYPE_OID: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
        const DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

        let mut content_type_value: SetOfVec<AttributeValue> = Default::default();
        let content_type_oid =
            Any::new(Tag::ObjectIdentifier, DATA_OID.as_bytes()).map_err(|e| {
                cms::builder::Error::Builder(format!("Failed to create content type OID: {}", e))
            })?;
        content_type_value.insert(content_type_oid).map_err(|e| {
            cms::builder::Error::Builder(format!("Failed to insert content type: {}", e))
        })?;

        let content_type_attr = Attribute {
            oid: CONTENT_TYPE_OID,
            values: content_type_value,
        };
        Ok(content_type_attr)
    }
    fn detached_hash_calculated_attribute(data: &[u8]) -> Result<Attribute, cms::builder::Error> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let message_digest_attr = cms::builder::create_message_digest_attribute(&digest)?;
        Ok(message_digest_attr)
    }
}
fn create_pkcs7_signed_data(
    data: &[u8],
    signer: &CHCertificate,
    detached: bool,
) -> Result<Vec<u8>, cms::builder::Error> {
    const DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
    let encapsulated_content = if detached {
        EncapsulatedContentInfo {
            econtent_type: DATA_OID,
            econtent: None, // No content for detached signature
        }
    } else {
        EncapsulatedContentInfo {
            econtent_type: DATA_OID,
            econtent: Some(Any::new(Tag::OctetString, data)?),
        }
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
    match verify_signing_certificate(&signer_cert) {
        Ok(_) => {}
        Err(e) => {
            return Err(cms::builder::Error::Builder(format!(
                "Signing certificate can not be used for signing: {}",
                e
            )));
        }
    }
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
    let original_data = if detached { Some(data) } else { None };

    detected_key.create_signed_data(
        &encapsulated_content,
        signer_identifier,
        digest_algorithm,
        x509_cert,
        original_data,
    )
}

pub fn save_file_with_extension<P: AsRef<Path>>(
    path: P,
    filename: &str,
    extension: &str,
    data: &[u8],
) -> Result<PathBuf, io::Error> {
    let dir_path = path.as_ref();
    if !dir_path.exists() {
        fs::create_dir_all(dir_path)?;
    }

    let file_path = dir_path.join(filename).with_extension(extension);

    fs::write(&file_path, data)?;

    Ok(file_path)
}

fn verify_encrypting_certificate(cert: &Certificate) -> Result<(), String> {
    verify_certificate_dates(cert)?;
    verify_key_usage_for_encryption(cert)?;
    Ok(())
}
fn verify_signing_certificate(cert: &Certificate) -> Result<(), String> {
    verify_certificate_dates(cert)?;
    verify_key_usage_for_signing(cert)?;
    Ok(())
}

/// Verifies that the certificate is currently within its validity period
fn verify_certificate_dates(cert: &Certificate) -> Result<(), String> {
    let now = Utc::now();

    let not_before = match &cert.tbs_certificate.validity.not_before {
        Time::UtcTime(utc_time) => {
            DateTime::from_timestamp(utc_time.to_unix_duration().as_secs() as i64, 0)
                .ok_or("Invalid not_before time format")?
        }
        Time::GeneralTime(gen_time) => {
            DateTime::from_timestamp(gen_time.to_unix_duration().as_secs() as i64, 0)
                .ok_or("Invalid not_before time format")?
        }
    };

    let not_after = match &cert.tbs_certificate.validity.not_after {
        Time::UtcTime(utc_time) => {
            DateTime::from_timestamp(utc_time.to_unix_duration().as_secs() as i64, 0)
                .ok_or("Invalid not_after time format")?
        }
        Time::GeneralTime(gen_time) => {
            DateTime::from_timestamp(gen_time.to_unix_duration().as_secs() as i64, 0)
                .ok_or("Invalid not_after time format")?
        }
    };

    if now < not_before {
        return Err(format!(
            "Certificate is not yet valid. Valid from: {}, Current time: {}",
            not_before.format("%Y-%m-%d %H:%M:%S UTC"),
            now.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }

    if now > not_after {
        return Err(format!(
            "Certificate has expired. Valid until: {}, Current time: {}",
            not_after.format("%Y-%m-%d %H:%M:%S UTC"),
            now.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }

    Ok(())
}

fn verify_key_usage_for_signing(cert: &Certificate) -> Result<(), String> {
    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return Err("Certificate must have extensions for security compliance".to_string());
    };

    for ext in extensions {
        // Key Usage extension OID: 2.5.29.15
        if ext.extn_id.to_string() == "2.5.29.15" {
            match KeyUsage::from_der(ext.extn_value.as_bytes()) {
                Ok(key_usage) => {
                    // Check if any signing-related usage is allowed
                    if key_usage.digital_signature()
                        || key_usage.key_cert_sign()
                        || key_usage.non_repudiation()
                    {
                        return Ok(());
                    }

                    return Err(format!(
                        "Certificate has Key Usage extension but does not allow signing."
                    ));
                }
                Err(e) => {
                    return Err(format!("Failed to parse Key Usage extension: {}", e));
                }
            }
        }
    }

    Err(
        "Certificate does not have a Key Usage extension, which is required for signing operations"
            .to_string(),
    )
}

fn verify_key_usage_for_encryption(cert: &Certificate) -> Result<(), String> {
    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return Err("Certificate must have extensions for security compliance".to_string());
    };

    for ext in extensions {
        // Key Usage extension OID: 2.5.29.15
        if ext.extn_id.to_string() == "2.5.29.15" {
            match KeyUsage::from_der(ext.extn_value.as_bytes()) {
                Ok(key_usage) => {
                    // Check if any signing-related usage is allowed
                    if key_usage.encipher_only()
                        || key_usage.key_encipherment()
                        || key_usage.data_encipherment()
                    {
                        return Ok(());
                    }

                    return Err(format!(
                        "Certificate has Key Usage extension but does not allow encryption."
                    ));
                }
                Err(e) => {
                    return Err(format!("Failed to parse Key Usage extension: {}", e));
                }
            }
        }
    }

    Err(
        "Certificate does not have a Key Usage extension, which is required for signing operations"
            .to_string(),
    )
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
            .key_usage(
                [
                    cert_helper::certificate::Usage::signature,
                    cert_helper::certificate::Usage::encipherment,
                ]
                .into_iter()
                .collect(),
            )
            .build_and_self_sign()
            .unwrap()
    }

    fn dummy_rsa_no_sig_key_certificate() -> CHCertificate {
        CertBuilder::new()
            .common_name("RSA Test Cert")
            .key_type(cert_helper::certificate::KeyType::RSA2048)
            .is_ca(false)
            .build_and_self_sign()
            .unwrap()
    }
    fn dummy_rsa_certificate() -> CHCertificate {
        CertBuilder::new()
            .common_name("RSA Test Cert")
            .key_type(cert_helper::certificate::KeyType::RSA2048)
            .is_ca(false)
            .key_usage(
                [
                    cert_helper::certificate::Usage::signature,
                    cert_helper::certificate::Usage::encipherment,
                ]
                .into_iter()
                .collect(),
            )
            .build_and_self_sign()
            .unwrap()
    }

    fn dummy_p256_certificate() -> CHCertificate {
        CertBuilder::new()
            .common_name("P256 Test Cert")
            .key_type(cert_helper::certificate::KeyType::P256)
            .is_ca(false)
            .key_usage(
                [cert_helper::certificate::Usage::signature]
                    .into_iter()
                    .collect(),
            )
            .build_and_self_sign()
            .unwrap()
    }

    fn dummy_p384_certificate() -> CHCertificate {
        CertBuilder::new()
            .common_name("P384 Test Cert")
            .key_type(cert_helper::certificate::KeyType::P384)
            .is_ca(false)
            .key_usage(
                [cert_helper::certificate::Usage::signature]
                    .into_iter()
                    .collect(),
            )
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
            detached: None,
        };

        // Return the config AND the temp files to keep them alive
        (cms_config, cert_file, data_file)
    }
    fn create_test_pkcs7_config_with_files(
        detached: bool,
    ) -> (
        crate::config::Cms,
        tempfile::NamedTempFile,
        tempfile::NamedTempFile,
        tempfile::NamedTempFile,
    ) {
        use std::io::Write;

        // Create temporary files
        let mut data_file =
            tempfile::NamedTempFile::new().expect("Failed to create temp data file");
        let mut cert_file =
            tempfile::NamedTempFile::new().expect("Failed to create temp cert file");
        let mut key_file = tempfile::NamedTempFile::new().expect("Failed to create temp key file");

        // Write test data
        let test_data = b"Test data for CMS operations";
        data_file
            .write_all(test_data)
            .expect("Failed to write test data");
        data_file.flush().expect("Failed to flush test data");

        // Write certificate content
        let cert_content = dummy_certificate().x509.to_pem().unwrap();
        cert_file
            .write_all(&cert_content)
            .expect("Failed to write cert");
        cert_file.flush().expect("Failed to flush cert");

        // Write key content (simplified - should be private key)
        let key_content = dummy_certificate()
            .pkey
            .as_ref()
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        key_file
            .write_all(&key_content)
            .expect("Failed to write key");
        key_file.flush().expect("Failed to flush key");

        let config = crate::config::Cms {
            id: "test1".to_string(),
            signer: Some(crate::config::Signer {
                cert_pem_file: cert_file.path().to_string_lossy().to_string(),
                private_key_pem_file: key_file.path().to_string_lossy().to_string(),
            }),
            recipient: cert_file.path().to_string_lossy().to_string(),
            data_file: data_file.path().to_string_lossy().to_string(),
            detached: Some(detached),
        };

        (config, data_file, cert_file, key_file)
    }
    #[test]
    fn test_cms_integration_with_detached_signature() {
        let (config, _data_file, _cert_file, _key_file) = create_test_pkcs7_config_with_files(true);

        // Create temporary output directory
        let output_dir = tempfile::tempdir().expect("Failed to create temp output dir");

        // This tests the full integration through the handle function
        match handle(vec![config], output_dir.path()) {
            Ok(_) => {
                // Check that files were created
                let p7s_path = output_dir.path().join("test1.p7s");
                assert!(
                    p7s_path.exists(),
                    "Detached signature file should be created"
                );

                // Verify it's a detached signature by checking file size
                let metadata = std::fs::metadata(&p7s_path).unwrap();
                assert!(metadata.len() > 0, "Signature file should not be empty");
                assert!(
                    metadata.len() < 2048,
                    "Detached signature should be relatively small"
                );
            }
            Err(e) => panic!("CMS integration test with detached signature failed: {}", e),
        }
        // Temp files are automatically cleaned up when they go out of scope
    }

    #[test]
    fn test_cms_integration_attached_vs_detached() {
        let (attached_config, _data_file1, _cert_file1, _key_file1) =
            create_test_pkcs7_config_with_files(false);
        let (detached_config, _data_file2, _cert_file2, _key_file2) =
            create_test_pkcs7_config_with_files(true);

        let output_dir = tempfile::tempdir().expect("Failed to create temp output dir");

        // Test attached signature
        match handle(vec![attached_config], output_dir.path()) {
            Ok(_) => {
                let pkcs7_path = output_dir.path().join("test1.pkcs7");
                assert!(
                    pkcs7_path.exists(),
                    "Attached signature file should be created"
                );
                let attached_size = std::fs::metadata(&pkcs7_path).unwrap().len();

                // Test detached signature
                match handle(vec![detached_config], output_dir.path()) {
                    Ok(_) => {
                        let p7s_path = output_dir.path().join("test1.p7s");
                        assert!(
                            p7s_path.exists(),
                            "Detached signature file should be created"
                        );
                        let detached_size = std::fs::metadata(&p7s_path).unwrap().len();

                        // Detached should be smaller (no embedded content)
                        assert!(
                            detached_size < attached_size,
                            "Detached signature ({} bytes) should be smaller than attached ({} bytes)",
                            detached_size,
                            attached_size
                        );
                    }
                    Err(e) => panic!("Failed to create detached signature: {}", e),
                }
            }
            Err(e) => panic!("Failed to create attached signature: {}", e),
        }
    }
    //
    #[test]
    fn test_create_pkcs7_detached_signature_basic() {
        let data = b"Test data for detached signature";
        let cert = dummy_p256_certificate();

        // Test detached signature
        let detached_result = create_pkcs7_signed_data(data, &cert, true);
        assert!(
            detached_result.is_ok(),
            "Should create detached signature successfully"
        );

        let detached_data = detached_result.unwrap();
        assert!(
            !detached_data.is_empty(),
            "Signature data should not be empty"
        );

        // Test attached signature for comparison
        let attached_result = create_pkcs7_signed_data(data, &cert, false);
        assert!(
            attached_result.is_ok(),
            "Should create attached signature successfully"
        );

        let attached_data = attached_result.unwrap();

        // Detached should be smaller than attached (no embedded content)
        assert!(
            detached_data.len() < attached_data.len(),
            "Detached signature should be smaller than attached"
        );
    }

    // test
    #[test]
    fn test_create_pkcs7_detached_signature_with_p256() {
        let data = b"Test data for detached signature";
        let cert = dummy_p256_certificate();

        match create_pkcs7_signed_data(data, &cert, true) {
            Ok(signed_data) => {
                // Basic validation
                assert!(!signed_data.is_empty(), "Signature should not be empty");
                assert!(
                    signed_data.len() > 100,
                    "Signature should be substantial size"
                );
                assert!(
                    signed_data.len() < 2048,
                    "Detached signature should be reasonably sized"
                );

                // Check it starts with correct ASN.1 SEQUENCE tag for CMS
                assert_eq!(signed_data[0], 0x30, "Should start with SEQUENCE tag");

                // For detached signatures, should be smaller than if we included the data
                let attached_result = create_pkcs7_signed_data(data, &cert, false);
                if let Ok(attached_data) = attached_result {
                    assert!(
                        signed_data.len() < attached_data.len(),
                        "Detached signature should be smaller than attached"
                    );
                }
            }
            Err(e) => panic!("Failed to create detached signature: {}", e),
        }
    }

    #[test]
    fn test_create_pkcs7_detached_signature_with_rsa() {
        let data = b"RSA test data for detached signature";
        let cert = dummy_rsa_certificate();

        match create_pkcs7_signed_data(data, &cert, true) {
            Ok(signed_data) => {
                assert!(!signed_data.is_empty());
                assert!(signed_data[0] == 0x30, "Should be valid ASN.1 structure");

                // RSA signatures tend to be larger than ECDSA
                assert!(
                    signed_data.len() > 200,
                    "RSA signature should be substantial"
                );
            }
            Err(e) => panic!("Failed to create RSA detached signature: {}", e),
        }
    }

    #[test]
    fn test_detached_vs_attached_signature_size() {
        let data = b"Compare attached vs detached signatures";
        let cert = dummy_p256_certificate();

        // Create both types
        let attached = create_pkcs7_signed_data(data, &cert, false).unwrap();
        let detached = create_pkcs7_signed_data(data, &cert, true).unwrap();

        // Detached should be smaller (no embedded content)
        assert!(
            detached.len() < attached.len(),
            "Detached ({} bytes) should be smaller than attached ({} bytes)",
            detached.len(),
            attached.len()
        );

        // Both should be valid ASN.1 structures
        assert_eq!(attached[0], 0x30, "Attached should start with SEQUENCE");
        assert_eq!(detached[0], 0x30, "Detached should start with SEQUENCE");
    }

    #[test]
    fn test_detached_signature_with_different_data_sizes() {
        let cert = dummy_p256_certificate();

        // Test with small data
        let small_data = b"small";
        let small_sig = create_pkcs7_signed_data(small_data, &cert, true).unwrap();

        // Test with large data (10KB)
        let large_data: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect();
        let large_sig = create_pkcs7_signed_data(&large_data, &cert, true).unwrap();

        // For detached signatures, size should be similar regardless of data size
        let size_diff = (large_sig.len() as i32 - small_sig.len() as i32).abs();
        assert!(
            size_diff < 100,
            "Detached signature sizes should be similar: small={}, large={}",
            small_sig.len(),
            large_sig.len()
        );

        // Both should be much smaller than the large data
        assert!(
            large_sig.len() < large_data.len() / 4,
            "Signature should be much smaller than data"
        );
    }

    #[test]
    fn test_detached_signature_with_empty_data() {
        let empty_data = b"";
        let cert = dummy_p256_certificate();

        match create_pkcs7_signed_data(empty_data, &cert, true) {
            Ok(signed_data) => {
                assert!(
                    !signed_data.is_empty(),
                    "Should create signature even for empty data"
                );
                assert_eq!(signed_data[0], 0x30, "Should be valid ASN.1 structure");
            }
            Err(e) => panic!("Failed to create detached signature with empty data: {}", e),
        }
    }

    #[test]
    fn test_detached_signature_deterministic_structure() {
        let data = b"Test deterministic behavior";
        let cert = dummy_p256_certificate();

        // Create two signatures of the same data
        let sig1 = create_pkcs7_signed_data(data, &cert, true).unwrap();
        let sig2 = create_pkcs7_signed_data(data, &cert, true).unwrap();

        // Sizes may differ slightly due to timestamps and ECDSA randomness
        let size_diff = (sig1.len() as i32 - sig2.len() as i32).abs();
        assert!(
            size_diff <= 5,
            "Signature sizes should be very similar: {} vs {} (diff: {})",
            sig1.len(),
            sig2.len(),
            size_diff
        );

        // Both should have the same ASN.1 structure start
        assert_eq!(sig1[0], sig2[0], "Should have same ASN.1 structure");
        // Don't check length byte as it might differ slightly due to size variations

        // Both should be reasonable signature sizes
        assert!(
            sig1.len() > 500 && sig1.len() < 1500,
            "Signature 1 should be reasonable size"
        );
        assert!(
            sig2.len() > 500 && sig2.len() < 1500,
            "Signature 2 should be reasonable size"
        );
    }

    #[test]
    fn test_detached_signature_with_real_file_content() {
        use std::io::Write;

        // Create a temporary file with larger content (signatures are typically 800+ bytes)
        let mut temp_file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        let test_content = b"This is test content for detached signature verification. \
                             We need enough content to make the file larger than the signature. \
                             Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod \
                             tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim \
                             veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea \
                             commodo consequat. Duis aute irure dolor in reprehenderit in voluptate \
                             velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint \
                             occaecat cupidatat non proident, sunt in culpa qui officia deserunt \
                             mollit anim id est laborum. Sed ut perspiciatis unde omnis iste natus \
                             error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, \
                             eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae \
                             vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit \
                             aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos \
                             qui ratione voluptatem sequi nesciunt.";

        temp_file
            .write_all(test_content)
            .expect("Failed to write test content");
        temp_file.flush().expect("Failed to flush");

        // Create certificate for signing
        let cert = dummy_p256_certificate();

        // Read the file content (as the actual implementation would)
        let file_content = std::fs::read(temp_file.path()).expect("Failed to read temp file");

        match create_pkcs7_signed_data(&file_content, &cert, true) {
            Ok(signed_data) => {
                // Verify basic properties
                assert!(!signed_data.is_empty());
                assert_eq!(signed_data[0], 0x30, "Should be valid CMS structure");

                println!("File content size: {} bytes", file_content.len());
                println!("Signature size: {} bytes", signed_data.len());

                // Now the signature should be smaller than the larger content
                assert!(
                    signed_data.len() < file_content.len(),
                    "Detached signature ({} bytes) should be smaller than original content ({} bytes)",
                    signed_data.len(),
                    file_content.len()
                );

                // Signature should still be substantial
                assert!(
                    signed_data.len() > 500,
                    "Signature should be substantial size"
                );
            }
            Err(e) => panic!("Failed to create detached signature: {}", e),
        }
    }

    #[test]
    fn test_detached_signature_size_independence() {
        let cert = dummy_p256_certificate();

        // Small content
        let small_content = b"small";
        let small_sig = create_pkcs7_signed_data(small_content, &cert, true).unwrap();

        // Large content (5KB)
        let large_content = vec![b'A'; 5120];
        let large_sig = create_pkcs7_signed_data(&large_content, &cert, true).unwrap();

        // Very large content (50KB)
        let very_large_content = vec![b'B'; 51200];
        let very_large_sig = create_pkcs7_signed_data(&very_large_content, &cert, true).unwrap();

        println!(
            "Small content: {} bytes, signature: {} bytes",
            small_content.len(),
            small_sig.len()
        );
        println!(
            "Large content: {} bytes, signature: {} bytes",
            large_content.len(),
            large_sig.len()
        );
        println!(
            "Very large content: {} bytes, signature: {} bytes",
            very_large_content.len(),
            very_large_sig.len()
        );

        // Store the sizes in a variable first
        let sizes = [small_sig.len(), large_sig.len(), very_large_sig.len()];
        let max_size = sizes.iter().max().unwrap();
        let min_size = sizes.iter().min().unwrap();
        let size_variance = max_size - min_size;

        assert!(
            size_variance <= 10,
            "Detached signature sizes should be very similar regardless of content size. Variance: {} bytes",
            size_variance
        );

        // All signatures should be much smaller than large content
        assert!(
            large_sig.len() < large_content.len() / 4,
            "Signature should be much smaller than large content"
        );
        assert!(
            very_large_sig.len() < very_large_content.len() / 10,
            "Signature should be much smaller than very large content"
        );
    }

    #[test]
    fn test_detached_signature_has_required_attributes_fixed() {
        let data = b"Test required attributes";
        let cert = dummy_p256_certificate();

        match create_pkcs7_signed_data(data, &cert, true) {
            Ok(signed_data) => {
                // Parse as ContentInfo first
                let content_info = cms::content_info::ContentInfo::from_der(&signed_data).unwrap();
                let inner_content = content_info.content.value();

                // The inner content needs to be wrapped in a SEQUENCE to be valid SignedData
                // reate the proper SEQUENCE wrapper
                let mut signed_data_with_wrapper = Vec::new();
                signed_data_with_wrapper.push(0x30); // SEQUENCE tag

                // Calculate and encode the length, for data that is longer than 127 bytes
                // the length starts with 0x80 and you or in the number of bytes used for length
                // i.e 0x81 for 1 byte, 0x82 for 2 bytes etc.So 0x81 means that one byte after this tells
                // the length of the content. See my der-test github repo for examples
                if inner_content.len() < 128 {
                    signed_data_with_wrapper.push(inner_content.len() as u8);
                } else if inner_content.len() < 256 {
                    signed_data_with_wrapper.push(0x81); // Long form, 1 byte length
                    signed_data_with_wrapper.push(inner_content.len() as u8);
                } else {
                    signed_data_with_wrapper.push(0x82); // Long form, 2 byte length
                    signed_data_with_wrapper.push((inner_content.len() >> 8) as u8);
                    signed_data_with_wrapper.push((inner_content.len() & 0xFF) as u8);
                }

                signed_data_with_wrapper.extend_from_slice(inner_content);

                match cms::signed_data::SignedData::from_der(&signed_data_with_wrapper) {
                    Ok(signed) => {
                        println!("✓ SignedData parsed successfully with wrapper!");

                        let signer = &signed.signer_infos.0;
                        let signed_attrs = signer.get(0).unwrap().signed_attrs.as_ref().unwrap();

                        // Check for required attributes
                        let required_oids = vec![
                            "1.2.840.113549.1.9.3",    // contentType
                            "1.2.840.113549.1.9.5",    // signingTime
                            "1.2.840.113549.1.9.4",    // messageDigest
                            "2.16.840.1.113733.1.9.5", // senderNonce
                        ];

                        for oid in required_oids {
                            let has_attr =
                                signed_attrs.iter().any(|attr| attr.oid.to_string() == oid);
                            assert!(has_attr, "Missing required attribute: {}", oid);
                        }
                    }
                    Err(e) => {
                        panic!("Failed to create detached signature: {}", e)
                    }
                }
            }
            Err(e) => panic!("Failed to create detached signature: {}", e),
        }
    }

    // used for debugging ASN.1 structure issues
    #[test]
    fn debug_asn1_structure() {
        let data = b"Debug ASN.1 structure";
        let cert = dummy_p256_certificate();

        match create_pkcs7_signed_data(data, &cert, true) {
            Ok(signed_data) => {
                println!("=== ASN.1 Structure Debug ===");
                println!("Total size: {} bytes", signed_data.len());

                // Print first 32 bytes in hex
                let hex_preview = hex::encode(&signed_data[..32.min(signed_data.len())]);
                println!("First 32 bytes: {}", hex_preview);

                // Try to parse as ContentInfo first
                println!("\n1. Trying to parse as ContentInfo...");
                match cms::content_info::ContentInfo::from_der(&signed_data) {
                    Ok(content_info) => {
                        println!("✓ ContentInfo parsed successfully");
                        println!("ContentInfo OID: {}", content_info.content_type);

                        // Get the inner content
                        let inner_content = content_info.content.value();
                        println!("Inner content size: {} bytes", inner_content.len());

                        let inner_hex = hex::encode(&inner_content[..32.min(inner_content.len())]);
                        println!("Inner content first 32 bytes: {}", inner_hex);

                        // Try to parse the inner content as SignedData
                        println!("\n2. Trying to parse inner content as SignedData...");
                        match cms::signed_data::SignedData::from_der(inner_content) {
                            Ok(signed) => {
                                println!("✓ SignedData parsed successfully!");
                                println!("Number of signers: {}", signed.signer_infos.0.len());
                            }
                            Err(e) => {
                                println!("✗ SignedData parsing failed: {:?}", e);

                                // Let's examine what's at the position where it failed
                                if inner_content.len() >= 10 {
                                    println!("Bytes at error position:");
                                    for i in 0..10.min(inner_content.len()) {
                                        println!(
                                            "  [{}] = 0x{:02x} ({})",
                                            i,
                                            inner_content[i],
                                            if inner_content[i].is_ascii_graphic() {
                                                inner_content[i] as char
                                            } else {
                                                '.'
                                            }
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        println!("✗ ContentInfo parsing failed: {:?}", e);

                        // Try parsing directly as SignedData (maybe no ContentInfo wrapper?)
                        println!("\n3. Trying to parse directly as SignedData...");
                        match cms::signed_data::SignedData::from_der(&signed_data) {
                            Ok(signed) => {
                                println!("✓ Direct SignedData parsing worked!");
                                println!("Number of signers: {}", signed.signer_infos.0.len());
                            }
                            Err(e2) => {
                                println!("✗ Direct SignedData parsing also failed: {:?}", e2);

                                // Show the exact bytes at the positions mentioned in the error
                                println!("\nRaw bytes analysis:");
                                for i in 0..20.min(signed_data.len()) {
                                    println!(
                                        "  [{}] = 0x{:02x} (tag: {})",
                                        i,
                                        signed_data[i],
                                        match signed_data[i] {
                                            0x30 => "SEQUENCE",
                                            0x02 => "INTEGER",
                                            0x04 => "OCTET STRING",
                                            0x06 => "OBJECT IDENTIFIER",
                                            0x31 => "SET",
                                            0xa0 => "CONTEXT [0]",
                                            _ => "OTHER",
                                        }
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => panic!("Failed to create signature: {}", e),
        }
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
    fn test_create_cms_with_rsa_certificate_with_no_encryption_key_usage() {
        let rsa_cert = dummy_rsa_no_sig_key_certificate();
        let test_data = "Hello, RSA CMS world!";
        let (cms_config, _cert_file, _data_file) =
            create_test_cms_config_with_files(&rsa_cert, test_data);

        let result = create_cms(&cms_config);

        assert!(
            result.is_err(),
            "Should Fail to create CMS with RSA certificate that have no encryption in key usage",
        );
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
    }

    #[test]
    fn test_create_cms_with_nonexistent_files() {
        let cms_config = Cms {
            id: "test".to_string(),
            recipient: "nonexistent_cert.pem".to_string(),
            data_file: "nonexistent_data.txt".to_string(),
            signer: None,
            detached: None,
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

        let result = create_pkcs7_signed_data(test_data, &rsa_cert, false);

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
    fn test_create_pkcs7_signed_with_invalid_cert_data_with_rsa() {
        let rsa_cert = dummy_rsa_no_sig_key_certificate();
        let test_data = b"Hello, RSA PKCS7 world!";

        let result = create_pkcs7_signed_data(test_data, &rsa_cert, false);

        assert!(
            result.is_err(),
            "Should Fail to create PKCS7 with RSA certificate"
        );
    }

    #[test]
    fn test_create_pkcs7_signed_data_with_p256() {
        let p256_cert = dummy_p256_certificate();
        let test_data = b"Hello, P256 PKCS7 world!";

        let result = create_pkcs7_signed_data(test_data, &p256_cert, false);

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

        let result = create_pkcs7_signed_data(test_data, &p384_cert, false);

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

        let result = create_pkcs7_signed_data(test_data, &rsa_cert, false);

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

        let result = create_pkcs7_signed_data(&large_data, &rsa_cert, false);

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
        let pkcs7_result = create_pkcs7_signed_data(&cms_der, &rsa_cert, false);
        assert!(pkcs7_result.is_ok(), "PKCS7 signing should succeed");
        let pkcs7_der = pkcs7_result.unwrap();

        // Both should produce valid DER data
        assert!(!cms_der.is_empty());
        assert!(!pkcs7_der.is_empty());
        assert_ne!(cms_der, pkcs7_der, "CMS and PKCS7 data should be different");
    }
}
