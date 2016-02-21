# certfetch

A simple CLI program to fetch an entire certificate chain in PEM format.


## About

I whipped this up because I could never remember all the OpenSSL CLI args to pull down a certificate.

    echo | openssl s_client -verify 8 -showcerts -connect github.com:443

Even if you do remember all that, the version of `openssl` that ships with Mac OS X is so ancient that it would filp out on sites that only supported TLS 1.2.

The tool also prints out some common info about the certs to STDERR so that you don't have to run `openssl x509 -text` on every single certificate.

The last line of output indicates whether the chain passed verification.  If there was a problem verifying the chain, it will  have exit code 4.


## Usage

Usually, all you need to do is this:

    certfetch github.com

Additional options:

    -domain STRING      specify different domain used during TLS handshake
    -cafile STRING      path to a CA file (PEM) to verify with instead of the default system root certs
    -exp DURATION       warn if certificate will expire in this period of time (default 720h0m0s)
    -file STRING        read domain+addr pairs from this CSV file

The certificates are output to STDOUT.  Info about the certs is output to STDERR.


## Example

    ## Certificate 0: github.com
    
    Subject:
      Common Name:          github.com
      Organization:         GitHub, Inc.
      Street Address:       548 4th Street
      Locality:             San Francisco
      Province:             California
      PostalCode:           94107
      Country:              US
      Serial Number:        5157550
    
    Issuer:
      Common Name:          DigiCert SHA2 Extended Validation Server CA
      Organization:         DigiCert Inc
      Organizational Unit:  www.digicert.com
      Country:              US
    
    Validity Period:
      Not Before:  2014-04-07 18:00:00 -0600 MDT
      Not After:   2016-04-12 06:00:00 -0600 MDT
    
    Serial: C009310D206DBE337553580118DDC87
    Version: 3
    Signature:
      Algorithm: SHA-256 with RSA
    
    Public Key:
      Algorithm: RSA
      Key Size: 2048
      Usage:
        - Digital Signature
        - Key Encipherment
    
    Extension: Subject Alternative Name
      - DNS: github.com
      - DNS: www.github.com
    
    Extension: Key Usage
      - Server Auth
      - Client Auth
    
    -----BEGIN CERTIFICATE-----
    MIIF4DCCBMigAwIBAgIQDACTENIG2+M3VTWAEY3chzANBgkqhkiG9w0BAQsFADB1
    ... >8 snip
    XX4C2NesiZcLYbc2n7B9O+63M2k=
    -----END CERTIFICATE-----
    
    \/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
    
    ## Certificate 1: DigiCert SHA2 Extended Validation Server CA
    
    === CERTIFICATE AUTHORITY ===
    
    Subject:
      Common Name:          DigiCert SHA2 Extended Validation Server CA
      Organization:         DigiCert Inc
      Organizational Unit:  www.digicert.com
      Country:              US
    
    Issuer:
      Common Name:          DigiCert High Assurance EV Root CA
      Organization:         DigiCert Inc
      Organizational Unit:  www.digicert.com
      Country:              US
    
    Validity Period:
      Not Before:  2013-10-22 06:00:00 -0600 MDT
      Not After:   2028-10-22 06:00:00 -0600 MDT
    
    Serial: C79A944B08C11952092615FE26B1D83
    Version: 3
    Signature:
      Algorithm: SHA-256 with RSA
    
    Public Key:
      Algorithm: RSA
      Key Size: 2048
      Usage:
        - Digital Signature
        - Key Cert Sign
        - CRL Sign
    
    Extension: Key Usage
      - Server Auth
      - Client Auth
    
    -----BEGIN CERTIFICATE-----
    MIIEtjCCA56gAwIBAgIQDHmpRLCMEZUgkmFf4msdgzANBgkqhkiG9w0BAQsFADBs
    ... >8 snip
    8TUoE6smftX3eg==
    -----END CERTIFICATE-----
    
    \/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
    
    Verify PASSED


## Known Issues

- Broken ciphers not supported because they're not supported by Go TLS lib.
- SSLv2 not supported because it's not supported by the Go TLS lib.


## Todo

- It desperately needs a refactor and tests.


## Authors

- J. Brandt Buckley
- Began as a fork of [artyom/certcheck](https://github.com/artyom/certcheck).
