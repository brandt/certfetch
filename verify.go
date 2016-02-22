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

	if cafile != "" {
		roots, err := readCAfile(cafile)
		if err != nil {
			return err
		}
		opts.Roots = roots
	}

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

	chains, err := leaf.Verify(opts)
	if len(chains) == 0 || err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}

	printStderr("Found %d path(s) to verification...\n", len(chains))
	printChainPaths(chains)

	return nil
}

// Read in a CA file and return a pool of root certs
func readCAfile(path string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading CA file: %v", err)
	}

	ok := pool.AppendCertsFromPEM([]byte(raw))
	if !ok {
		return nil, fmt.Errorf("error parsing CA file certificates: %v", ok)
	}

	return pool, nil
}
