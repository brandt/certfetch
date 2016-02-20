package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

func printStderr(fmtstr string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, fmtstr, a...)
}

func printCerts(chain []*x509.Certificate) {
	for i, c := range chain {
		if c.IsCA {
			printStderr("=== CERTIFICATE AUTHORITY ===\n\n")
		}
		printStderr("## Certificate %d: %s\n\n", i, c.Subject.CommonName)

		printName("Subject", c.Subject)
		printName("Issuer", c.Issuer)

		printValidityPeriod(c)

		printStderr("Serial#: %d\n", c.SerialNumber)
		printStderr("Version: %d\n", c.Version)
		printSignatureInfo(c)

		printPubKeyInfo(c)

		printSAN(c)
		printStderr("\n")
		printPEM(c)
		printSeparator()
		printStderr("\n")
	}
}

func printSeparator() {
	printStderr("\n---------------------------------------------------------\n")
}

func printValidityPeriod(c *x509.Certificate) {
	expiration := c.NotAfter.Local().String()
	if time.Now().After(c.NotAfter) {
		expiration = expiration + " (EXPIRED)"
	}
	printStderr("ValidityPeriod:\n")
	printStderr("  NotBefore: %s\n", c.NotBefore.Local().String())
	printStderr("  NotAfter:  %s\n", expiration)
}

type KeyUsage x509.KeyUsage

// TODO: Maybe add OSX usages: http://security.stackexchange.com/a/30216/11113
// https://tools.ietf.org/html/rfc5280#section-4.2.1.3
func (a KeyUsage) Split() (s []string) {
	if x509.KeyUsage(a)&x509.KeyUsageDigitalSignature != 0 {
		s = append(s, "Digital Signature")
	}
	if x509.KeyUsage(a)&x509.KeyUsageContentCommitment != 0 {
		s = append(s, "Content Commitment (Non-Repudiation)")
	}
	if x509.KeyUsage(a)&x509.KeyUsageKeyEncipherment != 0 {
		s = append(s, "Key Encipherment")
	}
	if x509.KeyUsage(a)&x509.KeyUsageDataEncipherment != 0 {
		s = append(s, "Data Encipherment")
	}
	if x509.KeyUsage(a)&x509.KeyUsageKeyAgreement != 0 {
		s = append(s, "Key Agreement")
	}
	if x509.KeyUsage(a)&x509.KeyUsageCertSign != 0 {
		s = append(s, "Key Cert Sign")
	}
	if x509.KeyUsage(a)&x509.KeyUsageCRLSign != 0 {
		s = append(s, "CRL Sign")
	}
	if x509.KeyUsage(a)&x509.KeyUsageEncipherOnly != 0 {
		s = append(s, "Encipher Only")
	}
	if x509.KeyUsage(a)&x509.KeyUsageDecipherOnly != 0 {
		s = append(s, "Decipher Only")
	}
	return s
}

type SignatureAlgorithm x509.SignatureAlgorithm

func (a SignatureAlgorithm) String() string {
	switch x509.SignatureAlgorithm(a) {
	case x509.UnknownSignatureAlgorithm:
		return "Unknown Signature Algorithm"
	case x509.MD2WithRSA:
		return "MD2 with RSA"
	case x509.MD5WithRSA:
		return "MD5 with RSA"
	case x509.SHA1WithRSA:
		return "SHA-1 with RSA"
	case x509.SHA256WithRSA:
		return "SHA-256 with RSA"
	case x509.SHA384WithRSA:
		return "SHA-384 with RSA"
	case x509.SHA512WithRSA:
		return "SHA-512 with RSA"
	case x509.DSAWithSHA1:
		return "DSA with SHA1"
	case x509.DSAWithSHA256:
		return "DSA with SHA-256"
	case x509.ECDSAWithSHA1:
		return "ECDSA with SHA-1"
	case x509.ECDSAWithSHA256:
		return "ECDSA with SHA-256"
	case x509.ECDSAWithSHA384:
		return "ECDSA with SHA-384"
	case x509.ECDSAWithSHA512:
		return "ECDSA with SHA-512"
	}
	return ""
}

type PublicKeyAlgorithm x509.PublicKeyAlgorithm

func (a PublicKeyAlgorithm) String() string {
	switch x509.PublicKeyAlgorithm(a) {
	case x509.UnknownPublicKeyAlgorithm:
		return "Unknown"
	case x509.RSA:
		return "RSA"
	case x509.DSA:
		return "DSA"
	case x509.ECDSA:
		return "ECDSA"
	}
	return "Unknown"
}

func printPubKeyInfo(c *x509.Certificate) {
	printStderr("PublicKey:\n")
	algorithm := PublicKeyAlgorithm(c.PublicKeyAlgorithm).String()
	printStderr("  Algorithm: %s\n", algorithm)

	bitlen := 0
	switch algorithm {
	case "Unknown":
		bitlen = 0
	case "RSA":
		publicKey := c.PublicKey.(*rsa.PublicKey)
		bitlen = publicKey.N.BitLen()
	case "DSA":
		publicKey := c.PublicKey.(*dsa.PublicKey)
		bitlen = publicKey.Y.BitLen()
	case "ECDSA":
		publicKey := c.PublicKey.(*ecdsa.PublicKey)
		bitlen = publicKey.Y.BitLen()
	}

	printStderr("  KeySize: %d\n", bitlen)

	usage := KeyUsage(c.KeyUsage).Split()
	if len(usage) > 0 {
		printStderr("  Usage:\n")
		for _, u := range usage {
			printStderr("    - %s\n", u)
		}
	}
}

func printSignatureInfo(c *x509.Certificate) {
	printStderr("Signature:\n")
	algorithm := SignatureAlgorithm(c.SignatureAlgorithm).String()
	printStderr("  Algorithm: %s\n", algorithm)
}

func printPEM(c *x509.Certificate) {
	pem := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	}))
	fmt.Printf("%s", pem)
}

func printSAN(c *x509.Certificate) {
	if len(c.DNSNames)+len(c.EmailAddresses)+len(c.IPAddresses) == 0 {
		return
	}
	printStderr("SubjectAlternativeName:\n")
	for _, d := range c.DNSNames {
		printStderr("  - DNS: %s\n", d)
	}
	for _, e := range c.EmailAddresses {
		printStderr("  - Email: %s\n", e)
	}
	for _, i := range c.IPAddresses {
		printStderr("  - IP: %s\n", i.String())
	}
}

func printName(title string, n pkix.Name) {
	printStderr("%s:\n", title)

	if len(n.CommonName) != 0 {
		printStderr("  CommonName:\t\t%s\n", n.CommonName)
	}
	if len(n.Organization) != 0 {
		printStderr("  Organization:\t\t%s\n", strings.Join(n.Organization, " / "))
	}
	if len(n.OrganizationalUnit) != 0 {
		printStderr("  OrganizationalUnit:\t%s\n", strings.Join(n.OrganizationalUnit, " / "))
	}
	if len(n.StreetAddress) != 0 {
		printStderr("  StreetAddress:\t%s\n", strings.Join(n.StreetAddress, " / "))
	}
	if len(n.Locality) != 0 { // City
		printStderr("  Locality:\t\t%s\n", strings.Join(n.Locality, " / "))
	}
	if len(n.Province) != 0 { // State
		printStderr("  Province:\t\t%s\n", strings.Join(n.Province, " / "))
	}
	if len(n.PostalCode) != 0 {
		printStderr("  PostalCode:\t\t%s\n", strings.Join(n.PostalCode, " / "))
	}
	if len(n.Country) != 0 {
		printStderr("  Country:\t\t%s\n", strings.Join(n.Country, " / "))
	}
	if len(n.SerialNumber) != 0 {
		printStderr("  SerialNumber:\t\t%s\n", n.SerialNumber)
	}
}
