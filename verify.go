package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
)

// Validates a certificate chain
func Verify(dnsName string, chain []*x509.Certificate, cafile string) error {
	if len(chain) == 0 {
		return errors.New("no certificates provided")
	}

	opts := x509.VerifyOptions{DNSName: dnsName}

	// Cert Pool for intermediates
	intermediatesPool := x509.NewCertPool()
	var leaf *x509.Certificate

	for _, c := range chain {
		// If a CA cert, add it to the intermediates pool, otherwise it's the leaf
		if c.IsCA {
			intermediatesPool.AddCert(c)
			continue
		}
		// Cert not a CA, assume it's our leaf. If we already found a leaf, error.
		if leaf != nil {
			return errors.New("more than one leaf certificate found")
		}
		leaf = c
	}

	if leaf == nil {
		return errors.New("no leaf certificates found")
	}

	opts.Intermediates = intermediatesPool

	if cafile != "" {
		opts.Roots = readCAfile(cafile)
	}

	chains, err := leaf.Verify(opts)
	if len(chains) == 0 || err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}
	return nil
}

func readCAfile(path string) *x509.CertPool {
	pool := x509.NewCertPool()

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	ok := pool.AppendCertsFromPEM([]byte(raw))
	if !ok {
		panic(ok)
	}

	return pool
}
