# Check CMS with openssl

Verify the signature of pkcs7/cms message with openssl(not detached signature)

Assume that the needed certificates are generated from `test.yaml`

```bash
openssl cms -verify \
 -in ./cms_data/test1.pkcs7 \
 -inform DER \
 -CAfile ./certs/maincadoc_cert.pem \
 -signer ./certs/maincadoc_cert.pem \
 -out ./cms_data/verified_content.dat
```

Decrypt the verified content with the private key that matches the public key.

```bash
openssl cms -decrypt \
 -in ./cms_data/verified_content.dat \
 -inform DER \
 -inkey ./certs/client2encrypt_pkey.pem \
 -out ./cms_data/decrypted_message.txt

```

Verify a detached signature using cms, `-binary` is needed to avoid openssl to parse
the `pkcs7-envelopedData` that the cms is constructed as.

```bash
openssl cms -verify -in ./cms_data/test1.p7s -inform der \
-content ./cms_data/test1.cms \
-CAfile ./certs/maincadoc_cert.pem -binary > /dev/null
```

Verfification of the detached signature can also be done with `openssl smime` that is
more forgiving when it comes to the input format.

```bash
openssl smime -verify -in ./cms_data/test1.p7s -inform der \
-content ./cms_data/test1.cms \
-CAfile ./certs/maincadoc_cert.pem > /dev/null
```
