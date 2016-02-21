package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
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
		return "Server Auth"
	case x509.ExtKeyUsageClientAuth:
		return "Client Auth"
	case x509.ExtKeyUsageCodeSigning:
		return "Code Signing"
	case x509.ExtKeyUsageEmailProtection:
		return "Email Protection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSEC End System"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSEC Tunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSEC User"
	case x509.ExtKeyUsageTimeStamping:
		return "Time Stamping"
	case x509.ExtKeyUsageOCSPSigning:
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
