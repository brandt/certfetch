package main

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/brandt/certfetch/isatty"
)

type KeyUsage x509.KeyUsage
type ExtKeyUsage x509.ExtKeyUsage
type SignatureAlgorithm x509.SignatureAlgorithm
type PublicKeyAlgorithm x509.PublicKeyAlgorithm

// NoColor set to true if STDOUT's file descriptor doesn't refer to a terminal.
// This prevents us from redirecting the ANSI escape sequences to a file.
var NoColor = !isatty.IsTerminal(os.Stdout.Fd())

const esc = "\x1b"

// Base attributes
const (
	Reset = iota
	Bold
	Faint
	Italic
	Underline
	BlinkSlow
	BlinkRapid
	ReverseVideo
	Concealed
	CrossedOut
)

// Foreground text colors
const (
	FgBlack = iota + 30
	FgRed
	FgGreen
	FgYellow
	FgBlue
	FgMagenta
	FgCyan
	FgWhite
)

func printStderr(fmtstr string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, fmtstr, a...)
}

func colorize(color int, str string) string {
	if NoColor {
		return str
	}
	return fmt.Sprintf("%s[%dm%s%s[%dm", esc, color, str, esc, Reset)
}

func printCerts(chain []*x509.Certificate) {
	for i, c := range chain {
		header := fmt.Sprintf("## Certificate %d: %s\n\n", i, c.Subject.CommonName)
		printStderr(colorize(FgCyan, header))

		if c.IsCA {
			printStderr(colorize(FgRed, "=== CERTIFICATE AUTHORITY ===\n\n"))
		}

		if c.Subject.CommonName == c.Issuer.CommonName {
			printStderr(colorize(FgYellow, "=== SELF-SIGNED ===\n\n"))
		}

		printName("Subject", c.Subject)
		printName("Issuer", c.Issuer)

		printValidityPeriod(c)
		printSerialNumber(c)
		printVersion(c)
		printSignatureInfo(c)
		printPubKeyInfo(c)
		printSAN(c)
		printExtKeyUsage(c)
		printPEM(c)
		printSeparator()
		printNewline()
	}
}

func printNewline() {
	printStderr("\n")
}

func printName(title string, n pkix.Name) {
	printStderr("%s\n", colorize(FgBlue, title+":"))

	if len(n.CommonName) != 0 {
		printStderr("  Common Name:          %s\n", colorize(FgMagenta, n.CommonName))
	}
	if len(n.Organization) != 0 {
		printStderr("  Organization:         %s\n", strings.Join(n.Organization, " / "))
	}
	if len(n.OrganizationalUnit) != 0 {
		printStderr("  Organizational Unit:  %s\n", strings.Join(n.OrganizationalUnit, " / "))
	}
	if len(n.StreetAddress) != 0 {
		printStderr("  Street Address:       %s\n", strings.Join(n.StreetAddress, " / "))
	}
	if len(n.Locality) != 0 { // City
		printStderr("  Locality:             %s\n", strings.Join(n.Locality, " / "))
	}
	if len(n.Province) != 0 { // State
		printStderr("  Province:             %s\n", strings.Join(n.Province, " / "))
	}
	if len(n.PostalCode) != 0 {
		printStderr("  PostalCode:           %s\n", strings.Join(n.PostalCode, " / "))
	}
	if len(n.Country) != 0 {
		printStderr("  Country:              %s\n", strings.Join(n.Country, " / "))
	}
	if len(n.SerialNumber) != 0 {
		printStderr("  Serial Number:        %s\n", n.SerialNumber)
	}

	printNewline()
}

func printValidityPeriod(c *x509.Certificate) {
	start := c.NotBefore.Local().String()
	expiration := c.NotAfter.Local().String()
	if time.Now().Before(c.NotBefore) {
		start = start + colorize(FgRed, " (FUTURE)")
	}
	if time.Now().After(c.NotAfter) {
		expiration = expiration + colorize(FgRed, " (EXPIRED)")
	}
	header := colorize(FgBlue, "Validity Period\n")
	printStderr(header)
	printStderr("  Not Before:  %s\n", start)
	printStderr("  Not After:   %s\n", expiration)
	printNewline()
}

func printSerialNumber(c *x509.Certificate) {
	printStderr("%s %s\n", colorize(FgBlue, "Serial:"), BigIntToString(c.SerialNumber))
}

// Converts *big.Int to hex string
// If the number can be expressed as a decimal uint64, it will be.
func BigIntToString(bigint *big.Int) string {
	if len(bigint.Bytes()) > 8 {
		return fmt.Sprintf("% X", bigint.Bytes())
	} else {
		return fmt.Sprintf("%d", bigint)
	}
}

func printVersion(c *x509.Certificate) {
	printStderr("%s %d\n", colorize(FgBlue, "Version:"), c.Version)
}

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

func printSignatureInfo(c *x509.Certificate) {
	header := colorize(FgBlue, "Signature:\n")
	printStderr(header)
	algorithm := SignatureAlgorithm(c.SignatureAlgorithm).String()
	printStderr("  Algorithm: %s\n", algorithm)
	printNewline()
}

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

// Defined in: https://tools.ietf.org/html/rfc5280#section-4.2.1.3
//
// Note: Key Usage has a long history of being ignored by software and being
// implemented incorrectly by CAs.  We're talking holy-shit-facepalm-level
// screwups.
func (a KeyUsage) Split() (s []string) {
	if x509.KeyUsage(a)&x509.KeyUsageDigitalSignature != 0 {
		// Short-term authentication signature (performed automatically and
		// frequently). Can sign any kind of document, except other certs.
		s = append(s, "Digital Signature")
	}
	if x509.KeyUsage(a)&x509.KeyUsageContentCommitment != 0 {
		// Different people have different interpretations of what this means.
		s = append(s, "Content Commitment (Non-Repudiation)")
	}
	if x509.KeyUsage(a)&x509.KeyUsageKeyEncipherment != 0 {
		// Exchange of encrypted session keys (RSA)
		s = append(s, "Key Encipherment")
	}
	if x509.KeyUsage(a)&x509.KeyUsageDataEncipherment != 0 {
		// For directly encrypting data; not commonly used.
		s = append(s, "Data Encipherment")
	}
	if x509.KeyUsage(a)&x509.KeyUsageKeyAgreement != 0 {
		// Used by DH
		// Required for ECDH TLS
		// Not *strictly* required for ECDHE TLS
		s = append(s, "Key Agreement")
	}
	if x509.KeyUsage(a)&x509.KeyUsageCertSign != 0 {
		// If keyCertSign is set then BasicConstraints CA true MUST also be set,
		// however if BasicConstraints CA TRUE is present then KeyUsage keyCertSign
		// need not be present.
		s = append(s, "Certificate Sign")
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

func printPubKeyInfo(c *x509.Certificate) {
	header := colorize(FgBlue, "Public Key:\n")
	printStderr(header)
	algorithm := PublicKeyAlgorithm(c.PublicKeyAlgorithm).String()
	printStderr("  Algorithm: %s\n", algorithm)

	bitlen := 0
	switch algorithm {
	case "Unknown":
		bitlen = 0
	case "RSA":
		publicKey := c.PublicKey.(*rsa.PublicKey)
		bitlen = publicKey.N.BitLen()
		publicExp := publicKey.E
		printStderr("  Public Exponent: %d\n", publicExp)
	case "DSA":
		publicKey := c.PublicKey.(*dsa.PublicKey)
		bitlen = publicKey.Y.BitLen()
	case "ECDSA":
		publicKey := c.PublicKey.(*ecdsa.PublicKey)
		bitlen = publicKey.Curve.Params().BitSize
	}

	printStderr("  Key Size: %d\n", bitlen)

	usage := KeyUsage(c.KeyUsage).Split()
	if len(usage) > 0 {
		printStderr("  Usage:\n")
		for _, u := range usage {
			printStderr("    - %s\n", u)
		}
	}

	printNewline()
}

func printSAN(c *x509.Certificate) {
	if len(c.DNSNames)+len(c.EmailAddresses)+len(c.IPAddresses) == 0 {
		return
	}
	header := colorize(FgBlue, "Extension: Subject Alternative Name\n")
	printStderr(header)
	for _, d := range c.DNSNames {
		printStderr("  - %s %s\n", colorize(FgYellow, "DNS:"), d)
	}
	for _, e := range c.EmailAddresses {
		printStderr("  - %s %s\n", colorize(FgYellow, "Email:"), e)
	}
	for _, i := range c.IPAddresses {
		printStderr("  - %s %s\n", colorize(FgYellow, "IP:"), i.String())
	}
	printNewline()
}

func (a ExtKeyUsage) String() string {
	switch x509.ExtKeyUsage(a) {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		// valid with digitalSignature, keyEncipherment or keyAgreement
		return "SSL/TLS Web Server Authentication"
	case x509.ExtKeyUsageClientAuth:
		// valid with digitalSignature or keyAgreement
		return "SSL/TLS Web Client Authentication"
	case x509.ExtKeyUsageCodeSigning:
		// valid with digitalSignature
		return "Code Signing"
	case x509.ExtKeyUsageEmailProtection:
		// valid with digitalSignature, nonRepudiation, and/or (keyEncipherment or keyAgreement)
		return "Email Protection (S/MIME)"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSEC End System"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSEC Tunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSEC User"
	case x509.ExtKeyUsageTimeStamping:
		// valid with digitalSignature and/or nonRepudiation
		return "Time Stamping"
	case x509.ExtKeyUsageOCSPSigning:
		// valid with digitalSignature and/or nonRepudiation
		return "OCSP Signing"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "Microsoft Server Gated Crypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "Netscape Server Gated Crypto"
	}
	return "Unknown"
}

func printExtKeyUsage(c *x509.Certificate) {
	usage := c.ExtKeyUsage
	if len(usage) > 0 {
		header := colorize(FgBlue, "Extension: Key Usage\n")
		printStderr(header)
		for _, u := range usage {
			printStderr("  - %s\n", ExtKeyUsage(u).String())
		}
		printNewline()
	}
}

func printPEM(c *x509.Certificate) {
	pem := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	}))
	fmt.Printf("%s", pem)
}

func printSeparator() {
	printStderr("\n%s\n", colorize(FgYellow, strings.Repeat("\\/", 32)))
}

func printChainPaths(chains [][]*x509.Certificate) {
	var cert_type string

	for i, path := range chains {
		if i > 0 {
			printNewline()
		}
		printStderr("Path %d:\n", i)

		for n, cert := range path {
			if n == 0 {
				cert_type = colorize(FgCyan, "LEAF")
			} else if n == (len(path) - 1) {
				cert_type = colorize(FgMagenta, "ROOT")
			} else {
				cert_type = colorize(FgBlue, "INTR")
			}
			dn := wrapString(NamesToDN(cert.Subject.Names), 58, 11)
			printStderr("  %d.  %-6s %s\n", n, cert_type, dn)
		}
	}

	printNewline()
}

// Note: This doesn't produce a strict RFC-2253 DN.
//
// For that, you'd at least need to escape existing commas and omit the space
// between objects.
//
// See: openssl x509 -subject -nameopt RFC2253 -noout -in /tmp/foo.pem
func NamesToDN(names []pkix.AttributeTypeAndValue) string {
	var b bytes.Buffer

	for i, v := range names {
		b.WriteString(getTagForOid(v.Type))
		b.WriteString("=")
		b.WriteString(fmt.Sprint(v.Value))
		if i < len(names)-1 {
			b.WriteString(", ")
		}
	}

	return b.String()
}

func getTagForOid(oid asn1.ObjectIdentifier) string {
	type oidNameMap struct {
		oid  []int
		name string
	}

	// See: https://github.com/openssl/openssl/blob/da15ce/crypto/objects/objects.txt
	oidTags := []oidNameMap{
		{[]int{2, 5, 4, 3}, "CN"},
		{[]int{2, 5, 4, 4}, "SN"},
		{[]int{2, 5, 4, 5}, "serialNumber"},
		{[]int{2, 5, 4, 6}, "C"},
		{[]int{2, 5, 4, 7}, "L"},
		{[]int{2, 5, 4, 8}, "ST"},
		{[]int{2, 5, 4, 9}, "street"},
		{[]int{2, 5, 4, 10}, "O"},
		{[]int{2, 5, 4, 11}, "OU"},
		{[]int{2, 5, 4, 12}, "title"},
		{[]int{2, 5, 4, 13}, "description"},
		{[]int{2, 5, 4, 14}, "searchGuide"},
		{[]int{2, 5, 4, 15}, "businessCategory"},
		{[]int{2, 5, 4, 16}, "postalAddress"},
		{[]int{2, 5, 4, 17}, "postalCode"},
		{[]int{2, 5, 4, 18}, "postOfficeBox"},
		{[]int{2, 5, 4, 19}, "physicalDeliveryOfficeName"},
		{[]int{2, 5, 4, 20}, "telephoneNumber"},
		{[]int{2, 5, 4, 21}, "telexNumber"},
		{[]int{2, 5, 4, 22}, "teletexTerminalIdentifier"},
		{[]int{2, 5, 4, 23}, "facsimileTelephoneNumber"},
		{[]int{2, 5, 4, 24}, "x121Address"},
		{[]int{2, 5, 4, 25}, "internationaliSDNNumber"},
		{[]int{2, 5, 4, 26}, "registeredAddress"},
		{[]int{2, 5, 4, 27}, "destinationIndicator"},
		{[]int{2, 5, 4, 28}, "preferredDeliveryMethod"},
		{[]int{2, 5, 4, 29}, "presentationAddress"},
		{[]int{2, 5, 4, 30}, "supportedApplicationContext"},
		{[]int{2, 5, 4, 31}, "member"},
		{[]int{2, 5, 4, 32}, "owner"},
		{[]int{2, 5, 4, 33}, "roleOccupant"},
		{[]int{2, 5, 4, 34}, "seeAlso"},
		{[]int{2, 5, 4, 35}, "userPassword"},
		{[]int{2, 5, 4, 36}, "userCertificate"},
		{[]int{2, 5, 4, 37}, "cACertificate"},
		{[]int{2, 5, 4, 38}, "authorityRevocationList"},
		{[]int{2, 5, 4, 39}, "certificateRevocationList"},
		{[]int{2, 5, 4, 40}, "crossCertificatePair"},
		{[]int{2, 5, 4, 41}, "name"},
		{[]int{2, 5, 4, 42}, "GN"},
		{[]int{2, 5, 4, 43}, "initials"},
		{[]int{2, 5, 4, 44}, "generationQualifier"},
		{[]int{2, 5, 4, 45}, "x500UniqueIdentifier"},
		{[]int{2, 5, 4, 46}, "dnQualifier"},
		{[]int{2, 5, 4, 47}, "enhancedSearchGuide"},
		{[]int{2, 5, 4, 48}, "protocolInformation"},
		{[]int{2, 5, 4, 49}, "distinguishedName"},
		{[]int{2, 5, 4, 50}, "uniqueMember"},
		{[]int{2, 5, 4, 51}, "houseIdentifier"},
		{[]int{2, 5, 4, 52}, "supportedAlgorithms"},
		{[]int{2, 5, 4, 53}, "deltaRevocationList"},
		{[]int{2, 5, 4, 54}, "dmdName"},
		{[]int{2, 5, 4, 65}, "pseudonym"},
		{[]int{2, 5, 4, 72}, "role"},
		{[]int{1, 2, 840, 113549, 1, 9, 1}, "E"},
		{[]int{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1}, "jurisdictionL"},
		{[]int{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2}, "jurisdictionST"},
		{[]int{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}, "jurisdictionC"},
		{[]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, "ct_precert_scts"},
		{[]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}, "ct_precert_poison"},
		{[]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}, "ct_precert_signer"},
		{[]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}, "ct_cert_scts"},
	}

	for _, v := range oidTags {
		if oid.Equal(v.oid) {
			return v.name
		}
	}

	return fmt.Sprint(oid)
}
