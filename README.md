# cert-bar

A rust version of CertificateBar the goal is to create a simple tool to generate certificate and chains to perform test in
development/stage environments. The setup should allow you to be able to change key types,
key usages, alternative names, use alreadey created certificates and private keys for signing.
The project is work in progress.

## Dependencies

### Dependency: `cert-helper` v0.3.8

This project uses `cert-helper`, a utility designed to simplify the creation and management of X.509 certificates using OpenSSL. It provides a structured and automated approach to:

- Setting up a certificate authority (CA)
- Generating certificate signing requests (CSRs)
- Issuing certificates for both client and server use

#### Key Features

- Automates common OpenSSL tasks
- Supports hierarchical CA structures
- Simplifies configuration for PKI setups
- Suitable for development and testing

**Version:** `0.3.1`
**License:** MIT
**Crate:** https://crates.io/crates/cert-helper

## Usage

The program takes two arguments the yaml config that defines what certificates to create and an output directory for the created certificates and keys.

## Config

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

The options for each keywords is(\* denote required values)

| keyword         | description                                                                                                          | options                              |
| --------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| id \*           | id used to identify the certificate and also the name used then saving the certificate and the private key to a file | string: mainca                       |
| parent          | certificate to be used then signing, must be a valid id if not signer is used id                                     | string: mainca                       |
| keytype \*      | key type to be used                                                                                                  | string: RSA, P224, P256, P384, P512  |
| hashalg \*      | which algorithm to be used for signature, default is SHA256                                                          | string: SHA1, SHA256, SHA384, SHA512 |
| commonname \*   | the common name this certificate shoud have                                                                          | string: www.foo.se                   |
| country \*      | the country code to use                                                                                              | string: SE                           |
| organization \* | organisation name                                                                                                    | string: test                         |
| ca              | is this certificate used to sign other certificates, default value is false                                          | boolean: true or false               |
| altnames        | list of alternative DNS names this certificate is valid for                                                          | string: valid dns names              |
| keylength       | key length, only used with RSA key(2048 or 4096), default is 2048                                                    | int: 2048                            |
| validfrom       | Start date then the certificate is valid, default is now                                                             | string: 2010-01-01                   |
| validto         | End date then the certificate is not valid, default is 1 year                                                        | string: 2020-01-01                   |
| signer          | if points to signer cert and private key file key                                                                    | see above for example                |
| usage           | Key usage to ad to the certificates, see list below for options                                                      | list of strings                      |

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
