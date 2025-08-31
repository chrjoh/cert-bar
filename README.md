# Cert-Bar (Rust Version of CertificateBar)

**Cert-Bar** is a Rust-based tool designed to simplify the generation and signing of certificates and certificate chains for use in development and staging environments. Added more functionality than exist
in the go version CertificateBar.

---

## Goals

- Provide a flexible and scriptable way to generate certificates and chains.
- Support customization of:
  - Key types (e.g., RSA, ECDSA, Ed25519)
  - Key usages (e.g., server authentication, client authentication)
  - Subject Alternative Names (SANs)
- Allow use of pre-existing certificates and private keys for signing.
- Enable automated workflows for generating and signing certificates.

---

## Features

- **CSR Generation**: Easily generate Certificate Signing Requests (CSRs) with customizable subject fields, key types, and extensions.
- **Certificate Construction**: Automatically construct certificates from CSRs using specified signing credentials.
- **Combined Workflow**: When both CSR definitions and signing requests are provided, the tool can generate sign certificates in a single run.
- **Configurable via YAML**: Define CSRs and signing operations in a single configuration file.
- **CRL generation**: Create or update CRL with revoked certificates.
- **CMS creating and PKCS7 signing**: Note due to limitations in crates used only RSA can be used for encrypting the AES key used to encrypt the content. Also for signing only RSA, P256, P384 with SHA256, can be used.

---

## Dependencies

### Dependency: `cert-helper` v0.4.0

This project uses `cert-helper`, a utility designed to simplify the creation and management of X.509 certificates using OpenSSL. It provides a structured and automated approach to:

- Setting up a certificate authority (CA)
- Generating certificate signing requests (CSRs)
- Issuing certificates for both client and server use

#### Key Features

- Automates common OpenSSL tasks
- Supports hierarchical CA structures
- Simplifies configuration for PKI setups
- Suitable for development and testing

**Version:** `0.4.0`
**License:** MIT
**Crate:** https://crates.io/crates/cert-helper

## Usage

The program takes three arguments type to create, the yaml config that defines what to create and an output directory for the created items.

```bash
cargo run -- cert --config-file ./examples/test.yaml --output-dir ./certs
cargo run -- csr --config-file ./examples/test_csr.yaml --output-dir ./certs
cargo run -- crl --config-file ./examples/test_crl.yaml --output-dir ./certs
cargo run -- cms --config-file ./examples/cms_config.yaml --output-dir ./cms_data
```

## Config

## Certificates

The structure of the config file is given bellow, certificates label conatins a list of certificate.
(See config directory for a basic example setup.) The example below is a self signed certificate valid
for domains `www.foo.se, www.dront.se, www.fro.se` and using a 2048 RSA key.

```yaml
certificates:
  - certificate:
      id: mainca
      parent: mainca
      ca: true
      pkix:
        commonname: www.foo.se
        country: SE
        organization: test
        organizationunit: testca
      altnames:
        - www.dront.se
        - www.fro.se
      keytype: RSA
      keylength: 2048
      hashalg: SHA256
      validfrom: 2010-01-01
      validto: 2020-01-01
      usage:
        - certsign
```

example with CA on file and use that to generate a middle certificate with a leaf

```yaml
certificates:
  - certificate:
      id: intercdfromfile
      signer:
        cert_pem_file: "./examples/maincadoc_cert.pem"
        private_key_pem_file: "./examples/maincadoc_pkey.pem"
      ca: true
      pkix:
        commonname: www.bar-with-file.se
        country: SE
        organization: test
      keytype: P224
      hashalg: SHA256
  - certificate:
      id: client3fromfilesign
      parent: intercdfromfile
      pkix:
        commonname: www.baz.se
        country: SE
        organization: test
      keytype: P224
      hashalg: SHA256
      usage:
        - contentcommitment
```

Create CA certificate with Ed25519 for signing see `examples/test_ed25519.yaml`

## Certificate Signing Requests (CSR)

This configuration file supports two main sections:

An example configuration file

```yaml
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
  - csr:
      id: csr2
      pkix:
        commonname: "Example"
        country: "SE"
        organization: "Example2"
      keytype: RSA
      altnames:
        - example2.com,
        - www.example2.com
      hashalg: SHA256
      keylength: 2048
      usage: [serverauth, clientauth]
signing_requests:
  - signing_request:
      csr_pem_file: ./certs/csr1_csr.pem
      validto: "2030-01-01"
      ca: true
      signer:
        cert_pem_file: ./examples/maincadoc_cert.pem
        private_key_pem_file: ./examples/maincadoc_pkey.pem
```

- **`csrs`**: Defines one or more Certificate Signing Request (CSR) specifications.
- **`signing_requests`**: Defines one or more signing operations for existing CSR files.

---

### `csrs` Section

The `csrs` section allows you to define CSR templates that the program can use to generate `.pem` files. Each entry includes:

- `id`: A unique identifier for the CSR.
- `pkix`: Subject details like:
  - `commonname`
  - `country`
  - `organization`
- `keytype`: Type of key (e.g., RSA).
- `keylength`: Key size in bits.
- `hashalg`: Hash algorithm used for signing.
- `altnames`: Subject Alternative Names (SANs).
- `usage`: Extended key usages (e.g., `serverauth`, `clientauth`).

These CSRs can be generated independently by the program and saved to a specified output directory.

---

### `signing_requests` Section

The `signing_requests` section defines how to sign existing CSR files. Each entry includes:

- `csr_pem_file`: Path to the CSR file to be signed.
- `validto`: Expiration date of the signed certificate.
- `ca`: Boolean indicating whether the certificate should be a CA.
- `signer`: Contains paths to the signing certificate and private key:
  - `cert_pem_file`
  - `private_key_pem_file`

This section can be used independently to sign pre-existing CSR files.

---

### Combined Usage

When both `csrs` and `signing_requests` are used together, the program can **automatically generate and sign certificates in one go**.

### Automatic Linking

If a `signing_request` references a CSR file like:

```yaml
csr_pem_file: ./certs/csr1_csr.pem
```

where `csr1` is the id for the generated certificate signing request

# Certificate revocation list (CRL)

This YAML configuration file defines the structure for generating a Certificate Revocation List (CRL).

## Structure

```yaml
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
```

## Fields

### `crl_file`

- **Type**: `String`
- **Description**: Specifies the output filename for the generated CRL.
  If the file already exists, it will be updated.
  The file must be in PEM format.

### `signer`

- **Type**: `Object`
- **Description**: Contains the certificate and private key used to sign the CRL.

#### `cert_pem_file`

- **Type**: `String`
- **Description**: Path to the PEM-encoded certificate used for signing.

#### `private_key_pem_file`

- **Type**: `String`
- **Description**: Path to the PEM-encoded private key used for signing.

### `revoked`

- **Type**: `List`
- **Description**: A list of revoked certificates.

Each entry contains:

#### `cert_info`

- **Type**: `Object`
- **Fields**:
  - **`serial`**: Serial number in hexadecimal format of the revoked certificate. Can be in colon-separated hex or plain hex format.
  - **`reason`**: Reason for revocation. Must be one of:
    - `Unspecified`
    - `KeyCompromise`
    - `CaCompromise`

# Cryptographic Message Syntax (CMS)

This YAML configuration file defines the structure for generating CMS (Cryptographic Message Syntax) messages, which provide encrypted and optionally signed data containers.

## Structure

```yaml
cmss:
  - cms:
      id: test1
      signer:
        cert_pem_file: "./certs/maincadoc_cert.pem"
        private_key_pem_file: "./certs/maincadoc_pkey.pem"
      recipient: ./certs/client2encrypt_cert.pem
      data_file: ./examples/message.txt
```

## Fields

### cmss

- Type: List
- Description: A list of CMS message configurations to be generated.

Each CMS entry contains:

#### cms

- Type: Object
- Description: Defines a single CMS message configuration.

### id

- Type: String
- Description: A unique identifier for this CMS configuration. Used for logging and identification purposes.
- Example: "test1"

### signer (Optional)

- Type: Object
- Description: Contains the certificate and private key used to create a digital signature for the CMS message. If provided, the CMS message will be both encrypted and signed.
- Supported Key Types: RSA, P-256 (secp256r1), P-384 (secp384r1)
- Hash Algorithm: SHA-256
- If not present the CMS message will only be encrypted.

#### cert_pem_file

- Type: String
- Description: Path to the PEM-encoded certificate used for signing the CMS message.

#### private_key_pem_file

- Type: String
- Description: Path to the PEM-encoded private key corresponding to the signing certificate.

### recipient

- Type: String
- Description: Path to the PEM-encoded certificate of the recipient who will be able to decrypt the CMS message.
- Supported Key Types: RSA only (for AES key encryption)
- Note: Currently, only RSA certificates are supported for CMS envelope encryption due to library limitations.
- Due to limitations in the cms crate multiple recipients are not supported.

### data_file

- Type: String
- Description: Path to the file containing the data to be encrypted in the CMS message. If the file doesn't exist, a default message "Hello CMS world!" will be used.

## Generated Output

The CMS generation process creates the following files:

1. test1.der: The encrypted CMS message in DER (Distinguished Encoding Rules) format
2. test1.pkcs7: If a signer is provided, this file contains the signed version of the CMS message in PKCS#7 format

## Cryptographic Details

### Encryption (EnvelopedData)

- Content Encryption: AES-256-CBC
- Key Encryption: RSA key transport
- Supported Recipient Key Types: RSA only

### Signing (SignedData) - Optional

- Supported Signer Key Types: RSA, P-256 (secp256r1), P-384 (secp384r1)
- Hash Algorithm: SHA-256
- Signature Algorithm:
  - RSA: RSASSA-PKCS1-v1_5 with SHA-256
  - ECDSA: ECDSA with SHA-256

## Limitations

- Recipient certificates must use RSA keys for envelope encryption
- ECDSA recipient certificates are not supported for encryption due to current library limitations
- Signing supports multiple key types but encryption is limited to RSA

# Options

The options for each keywords is(\* denote required values)

| keyword         | description                                                                                                          | options                                      |
| --------------- | -------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| id \*           | id used to identify the certificate and also the name used then saving the certificate and the private key to a file | string: mainca                               |
| parent          | certificate to be used then signing, must be a valid id if not signer is used id                                     | string: mainca                               |
| keytype \*      | key type to be used                                                                                                  | string: RSA, P224, P256, P384, P512, Ed25519 |
| commonname \*   | the common name this certificate shoud have                                                                          | string: www.foo.se                           |
| country \*      | the country code to use                                                                                              | string: SE                                   |
| organization \* | organisation name                                                                                                    | string: test                                 |
| hashalg         | which algorithm to be used for signature, default is SHA256                                                          | string: SHA1, SHA256, SHA384, SHA512         |
| ca              | is this certificate used to sign other certificates, default value is false                                          | boolean: true or false                       |
| altnames        | list of alternative DNS names this certificate is valid for                                                          | string: valid dns names                      |
| keylength       | key length, only used with RSA key(2048 or 4096), default is 2048                                                    | int: 2048                                    |
| validfrom       | Start date then the certificate is valid, default is now                                                             | string: 2010-01-01                           |
| validto         | End date then the certificate is not valid, default is 1 year                                                        | string: 2020-01-01                           |
| signer          | if points to signer cert and private key file key                                                                    | see above for example                        |
| usage           | Key usage to ad to the certificates, see list below for options                                                      | list of strings                              |

### Key usage

If empty, if CA is true keys to sign certificates and crl lista are added, otherwise client and
server authentications are added.

| keyword           | description                                                |
| ----------------- | ---------------------------------------------------------- |
| certsign          | allowed to sign certificates                               |
| crlsign           | allowed to sign crl                                        |
| encipherment      | allowed to enciphering private or secret keys              |
| clientauth        | allowed to authenticate as client                          |
| serverauth        | allowed ot be used for server authenthication              |
| signature         | allowed to perfom digital signature (For auth)             |
| contentcommitment | allowed to perfom document signature (prev non repudation) |
