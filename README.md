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

    -domain STRING      use this domain name during TLS handshake
    -cafile STRING      path to a CA file (PEM) to verify with instead of the default system root certs
    -exp DURATION       warn if certificate will expire in this period of time (default 720h0m0s)
    -file STRING        read domain+addr pairs from this CSV file

The certificates are output to STDOUT.  Info about the certs is output to STDERR.


## Example

    [brandt@absinthe ~]$ certfetch github.com
    Issuer:
      Country:              US
      Organization:         DigiCert Inc
      OrganizationalUnit:   www.digicert.com
      CommonName:           DigiCert SHA2 Extended Validation Server CA
    Subject:
      Country:              US
      Organization:         GitHub, Inc.
      Locality:             San Francisco
      Province:             California
      StreetAddress:        548 4th Street
      PostalCode:           94107
      SerialNumber:         5157550
      CommonName:           github.com
    Serial:     15953718796281471505685363726901697671
    NotBefore:  2014-04-08 00:00:00 +0000 UTC
    NotAfter:   2016-04-12 12:00:00 +0000 UTC
    SubjectAlternativeName:
    - DNS: github.com
    - DNS: www.github.com
    -----BEGIN CERTIFICATE-----
    MIIF4DCCBMigAwIBAgIQDACTENIG2+M3VTWAEY3chzANBgkqhkiG9w0BAQsFADB1
    ... >8 snip
    XX4C2NesiZcLYbc2n7B9O+63M2k=
    -----END CERTIFICATE-----
    
    === CERTIFICATE AUTHORITY ===
    Issuer:
      Country:              US
      Organization:         DigiCert Inc
      OrganizationalUnit:   www.digicert.com
      CommonName:           DigiCert High Assurance EV Root CA
    Subject:
      Country:              US
      Organization:         DigiCert Inc
      OrganizationalUnit:   www.digicert.com
      CommonName:           DigiCert SHA2 Extended Validation Server CA
    Serial:     16582437038678467094619379592629788035
    NotBefore:  2013-10-22 12:00:00 +0000 UTC
    NotAfter:   2028-10-22 12:00:00 +0000 UTC
    -----BEGIN CERTIFICATE-----
    MIIEtjCCA56gAwIBAgIQDHmpRLCMEZUgkmFf4msdgzANBgkqhkiG9w0BAQsFADBs
    ... >8 snip
    8TUoE6smftX3eg==
    -----END CERTIFICATE-----
    
    Verify PASSED


## Todo

- It desperately needs a refactor and tests.


## Authors

- J. Brandt Buckley
- Began as a fork of [artyom/certcheck](https://github.com/artyom/certcheck).
