# certfetch

A simple CLI program to fetch an entire certificate chain in PEM format.

## About

I whipped this up because I was tired of trying to remember `echo | openssl s_client -verify 8 -showcerts -connect google.com:443` for such a simple task.

The tool also prints out some common info about the certs to STDERR so that you don't have to run `openssl x509 -text` on every single certificate.

## Usage

Usually, all you need to do is this:

    certfetch -domain google.com

Additional options:

    -addr STRING        host:port to connect to (defaults to domain:443)
    -domain STRING      use this domain name during TLS handshake
    -exp DURATION       warn if certificate will expire in this period of time (default 720h0m0s)
    -file STRING        read domain+addr pairs from this CSV file


## Authors

- J. Brandt Buckley
- Began as a fork of [artyom/certcheck](https://github.com/artyom/certcheck).
