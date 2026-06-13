#![allow(dead_code)]
use crate::config::{Certificate, CreatedCertificate, FromKeyType, Signer};
use cert_helper::certificate::{
    CertBuilder, Certificate as CHCertificate, HashAlg as CHHashAlg, KeyType as CHKeyType,
    Usage as CHUsage, UseesBuilderFields, X509Common,
};
use std::path::Path;

use std::collections::{HashMap, HashSet, VecDeque};

/// Trait for loading a signer certificate and key.
pub trait SignerLoader {
    fn load(&self, signer: &Signer) -> Result<CreatedCertificate, Box<dyn std::error::Error>>;
}

/// Trait for creating certificates using a signer (parent) if provided.
pub trait CertificateCreator {
    fn create<'a>(
        &self,
        cert: &Certificate,
        signer: Option<&'a CreatedCertificate>,
    ) -> Result<CreatedCertificate, Box<dyn std::error::Error>>;
}

/// Trait for saving certificates to disk.
pub trait CertificateSaver {
    fn save(
        &self,
        cert: &CreatedCertificate,
        path: &str,
        id: &str,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

pub struct RealSignerLoader;

impl SignerLoader for RealSignerLoader {
    fn load(&self, signer: &Signer) -> Result<CreatedCertificate, Box<dyn std::error::Error>> {
        load_signer_from_file(signer)
    }
}

pub struct RealCertificateCreator;

impl CertificateCreator for RealCertificateCreator {
    fn create<'a>(
        &self,
        cert: &Certificate,
        signer: Option<&'a CreatedCertificate>,
    ) -> Result<CreatedCertificate, Box<dyn std::error::Error>> {
        create_certificate(cert, signer)
    }
}

pub struct RealCertificateSaver;

impl CertificateSaver for RealCertificateSaver {
    fn save(
        &self,
        cert: &CreatedCertificate,
        path: &str,
        id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        cert.cert.save(path, id).map_err(|e| e.into())
    }
}

/// Creates certificates using the provided configuration and saves them to the specified output directory.
///
/// This function initializes the required components for certificate creation, including:
/// - A signer loader to retrieve signing credentials.
/// - A certificate creator to generate certificates.
/// - A certificate saver to persist the certificates to disk.
///
/// It delegates the actual creation logic to `create_inner`.
///
/// # Arguments
///
/// * `flat_certs` - A vector of `Certificate` objects to be created.
/// * `output_dir` - The directory where the generated certificates will be saved.
///
/// # Returns
///
/// A `Result` indicating success or containing an error if the creation or saving process fails.
///
/// # Errors
///
/// Returns an error if certificate creation or saving fails.
pub fn create<C: AsRef<Path>>(
    flat_certs: Vec<Certificate>,
    output_dir: C,
) -> Result<(), Box<dyn std::error::Error>> {
    let signer_loader = RealSignerLoader;
    let cert_creator = RealCertificateCreator;
    let cert_saver = RealCertificateSaver;
    create_inner(
        flat_certs,
        &signer_loader,
        &cert_creator,
        &cert_saver,
        output_dir,
    )?;
    Ok(())
}

fn create_inner<C: AsRef<Path>>(
    flat_certs: Vec<Certificate>,
    signer_loader: &dyn SignerLoader,
    cert_creator: &dyn CertificateCreator,
    cert_saver: &dyn CertificateSaver,
    output_dir: C,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut cert_map: HashMap<String, &Certificate> = HashMap::new();
    let mut dependents: HashMap<String, Vec<String>> = HashMap::new();
    let mut ready_queue: VecDeque<String> = VecDeque::new();
    let mut external_signers: HashMap<String, CreatedCertificate> = HashMap::new();
    let mut created: HashMap<String, CreatedCertificate> = HashMap::new();
    let mut queued: HashSet<String> = HashSet::new();

    // Index certificates and build dependency map
    for cert in &flat_certs {
        cert_map.insert(cert.id.clone(), &cert);
        if let Some(parent_id) = &cert.parent {
            dependents
                .entry(parent_id.clone())
                .or_default()
                .push(cert.id.clone());
            if parent_id == &cert.id {
                ready_queue.push_back(cert.id.clone());
                queued.insert(cert.id.clone());
            }
        } else if cert.signer.is_some() {
            ready_queue.push_back(cert.id.clone());
            queued.insert(cert.id.clone());
        }
    }
    // Process certificates in dependency order
    while let Some(id) = ready_queue.pop_front() {
        let cert = &cert_map[&id];

        let signer_cert = if let Some(signer) = &cert.signer {
            let signer_id = format!("file:{}", signer.cert_pem_file);
            if !external_signers.contains_key(&signer_id) {
                let loaded = signer_loader.load(signer)?;
                external_signers.insert(signer_id.clone(), loaded);
            }
            external_signers.get(&signer_id)
        } else if let Some(parent_id) = &cert.parent {
            created.get(parent_id)
        } else {
            None
        };

        let new_cert = cert_creator.create(cert, signer_cert)?;
        created.insert(cert.id.clone(), new_cert);

        if let Some(children) = dependents.get(&cert.id) {
            for child_id in children {
                if !created.contains_key(child_id) && !queued.contains(child_id) {
                    let child = &cert_map[child_id];
                    if let Some(parent_id) = &child.parent {
                        if created.contains_key(parent_id) {
                            ready_queue.push_back(child_id.clone());
                            queued.insert(child_id.clone());
                        }
                    }
                }
            }
        }
    }
    println!("\nAll certificates created:");
    for (id, v) in &created {
        let path = output_dir
            .as_ref()
            .to_str()
            .ok_or("Output directory path is not a valid UTF-8 string")?;
        cert_saver.save(v, path, id)?;
    }
    Ok(())
}

fn create_certificate<'a>(
    cert: &Certificate,
    signer: Option<&'a CreatedCertificate>,
) -> Result<CreatedCertificate, Box<dyn std::error::Error>> {
    let usage: HashSet<CHUsage> = cert
        .usage
        .as_ref()
        .map(|vec| vec.iter().cloned().map(CHUsage::from).collect())
        .unwrap_or_default();
    let alt_names_as_str_vec: Vec<&str> = cert
        .altnames
        .as_ref()
        .map(|vec| vec.iter().map(|s| s.as_str()).collect())
        .unwrap_or_else(|| Vec::new());
    let key_type = CHKeyType::from_key_type(cert.keytype.clone(), cert.keylength);

    // Skip hash check for Ed25519 and PQC keys (they handle hashing internally via cert_helper)
    let skip_hash_check = match key_type {
        CHKeyType::Ed25519 => true,
        #[cfg(feature = "pqc")]
        CHKeyType::MlDsa44
        | CHKeyType::MlDsa65
        | CHKeyType::MlDsa87
        | CHKeyType::SlhDsaSha2_128s
        | CHKeyType::SlhDsaSha2_192s
        | CHKeyType::SlhDsaSha2_256s => true,
        _ => false,
    };
    if !skip_hash_check && cert.hashalg.is_none() {
        return Err("Hash algorithm must be set for non-Ed25519 or PQC keys".into());
    }

    let mut builder = CertBuilder::new()
        .common_name(&cert.pkix.commonname)
        .country_name(&cert.pkix.country)
        .organization(&cert.pkix.organization)
        .alternative_names(alt_names_as_str_vec)
        .key_usage(usage)
        .key_type(CHKeyType::from(key_type))
        .is_ca(cert.ca.unwrap_or(false));
    if let Some(hash_alg) = &cert.hashalg {
        builder = builder.signature_alg(CHHashAlg::from(hash_alg.clone()));
    }
    if let Some(valid_to) = &cert.validto {
        builder = builder.valid_to(valid_to);
    }
    let ch_cert = match signer {
        Some(signer) => builder.build_and_sign(&signer.cert),
        _ => builder.build_and_self_sign(),
    };
    Ok(CreatedCertificate {
        id: cert.id.clone(),
        cert: ch_cert?,
    })
}

fn load_signer_from_file(
    signer: &Signer,
) -> Result<CreatedCertificate, Box<dyn std::error::Error>> {
    let loaded_cert =
        CHCertificate::load_cert_and_key(&signer.cert_pem_file, &signer.private_key_pem_file)?;
    Ok(CreatedCertificate {
        id: format!("file:{}", signer.cert_pem_file),
        cert: loaded_cert,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::{KeyType, Pkix};

    use cert_helper::certificate::{CertBuilder, UseesBuilderFields};
    use mockall::{mock, predicate::*};

    mock! {
      pub SignerLoader {}

      impl SignerLoader for SignerLoader {
          fn load(&self, signer: &Signer) -> Result<CreatedCertificate, Box<dyn std::error::Error>>;
        }
    }

    mock! {
      pub CertificateCreator{}
      impl CertificateCreator for CertificateCreator{
          fn create<'a>(
               &self,
              cert: &Certificate,
              signer: Option<&'a CreatedCertificate>,
            ) -> Result<CreatedCertificate, Box<dyn std::error::Error>>;
        }
    }

    mock! {
      pub CertificateSaver{}
      impl CertificateSaver for CertificateSaver{
          fn save(
               &self,
              cert: &CreatedCertificate,
              path: &str,
              id: &str,
            ) -> Result<(), Box<dyn std::error::Error>>;
        }
    }

    #[test]
    fn test_create_with_mocked_dependencies() {
        let root_cert = Certificate {
            ca: Some(true),
            keytype: KeyType::Ed25519,
            id: "root".to_string(),
            pkix: Pkix::default(),
            altnames: None,
            hashalg: None,
            keylength: None,
            validto: None,
            usage: None,
            parent: None,
            signer: Some(Signer {
                cert_pem_file: "root.pem".to_string(),
                private_key_pem_file: "root_key.pem".to_string(),
            }),
        };
        let inter_cert = Certificate {
            ca: Some(true),
            keytype: KeyType::P224,
            id: "inter".to_string(),
            parent: Some("root".to_string()),
            pkix: Pkix::default(),
            altnames: None,
            hashalg: Some(crate::config::HashAlg::SHA256),
            keylength: None,
            validto: None,
            usage: None,
            signer: None,
        };

        let child_cert = Certificate {
            id: "child".to_string(),
            parent: Some("inter".to_string()),
            ca: None,
            keytype: KeyType::P224,
            pkix: Pkix::default(),
            altnames: None,
            hashalg: Some(crate::config::HashAlg::SHA256),
            keylength: None,
            validto: None,
            usage: None,
            signer: None,
        };

        // store them in wrong order, to check that correct signer is found
        let certs = vec![root_cert.clone(), child_cert.clone(), inter_cert.clone()];

        let mut mock_loader = MockSignerLoader::new();
        let mut mock_creator = MockCertificateCreator::new();
        let mut mock_saver = MockCertificateSaver::new();

        let root = CertBuilder::new()
            .is_ca(true)
            .common_name("root")
            .build_and_self_sign()
            .unwrap();
        let inter = CertBuilder::new()
            .is_ca(true)
            .common_name("inter")
            .build_and_sign(&root)
            .unwrap();
        let child = CertBuilder::new()
            .common_name("child")
            .build_and_sign(&inter)
            .unwrap();
        let created_root = CreatedCertificate {
            id: "root".to_string(),
            cert: root,
        };
        let created_inter = CreatedCertificate {
            id: "inter".to_string(),
            cert: inter,
        };

        let created_child = CreatedCertificate {
            id: "child".to_string(),
            cert: child,
        };

        // Expect signer to be loaded — each mock needs its own owned clone variable
        let root_for_loader = created_root.clone();
        let root_for_creator = created_root.clone();
        let inter_for_creator = created_inter.clone();
        let child_for_creator = created_child.clone();

        mock_loader
            .expect_load()
            .withf(|signer| signer.cert_pem_file == "root.pem")
            .returning(move |_| Ok(root_for_loader.clone()));

        // Expect root certificate to be created
        mock_creator
            .expect_create()
            .withf(|cert, _| cert.id == "root")
            .returning(move |_, _| Ok(root_for_creator.clone()));

        // Expect inter certificate to be created
        mock_creator
            .expect_create()
            .withf(|cert, signer| {
                cert.id == "inter" && signer.map(|s| s.id.as_str()) == Some("root")
            })
            .returning(move |_, _| Ok(inter_for_creator.clone()));

        // Expect child certificate to be created
        mock_creator
            .expect_create()
            .withf(|cert, signer| {
                cert.id == "child" && signer.map(|s| s.id.as_str()) == Some("inter")
            })
            .returning(move |_, _| Ok(child_for_creator.clone()));

        // Expect all certificates to be saved
        mock_saver
            .expect_save()
            .times(3)
            .returning(|_, _, _| Ok(()));

        let result = create_inner(certs, &mock_loader, &mock_creator, &mock_saver, "");

        assert!(result.is_ok());
    }
}
