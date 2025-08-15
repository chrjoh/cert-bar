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
- **Combined Workflow**: When both CSR definitions and signing requests are provided, the tool can generate and sign certificates in a single run.
- **Configurable via YAML**: Define CSRs and signing operations in a single configuration file.

---

## Dependencies

### Dependency: `cert-helper` v0.3.10

This project uses `cert-helper`, a utility designed to simplify the creation and management of X.509 certificates using OpenSSL. It provides a structured and automated approach to:

- Setting up a certificate authority (CA)
- Generating certificate signing requests (CSRs)
- Issuing certificates for both client and server use

#### Key Features

- Automates common OpenSSL tasks
- Supports hierarchical CA structures
- Simplifies configuration for PKI setups
- Suitable for development and testing

**Version:** `0.3.10`
**License:** MIT
**Crate:** https://crates.io/crates/cert-helper

## Usage

The program takes three arguments type to create, the yaml config that defines what to create and an output directory for the created items.

```bash
cargo run -- cert--config-file ./examples/test.yaml --output-dir ./certs
cargo run -- csr --config-file ./examples/test_csr.yaml --output-dir ./certs
# crl not added yet
cargo run -- crl --config-file ./examples/test_crl.yaml --output-dir ./certs
```

## Config

## Certificates

The structure of the config file is given bellow, certificates label conatins a list of certificate.
(See config directory for a basic example setup.) The example below is a self signed certificate valid
for domains `www.foo.se, www.dront.se, www.fro.se` and using a 2048 RSA key.

```
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

```
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

## CSR

This configuration file supports two main sections:

An example configuration file is available at:
[examples/test_csr.yaml](examples/test_csr.yaml)

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
