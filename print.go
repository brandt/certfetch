package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

func printStderr(fmtstr string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, fmtstr, a...)
}

func printPEM(c *x509.Certificate) {
	pem := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	}))
	fmt.Printf("%s", pem)
}

func printCertInfo(c *x509.Certificate) {
	if c.IsCA {
		printStderr("=== CERTIFICATE AUTHORITY ===\n")
	}
	printName("Issuer", c.Issuer)
	printName("Subject", c.Subject)
	printStderr("Serial:     %d\n", c.SerialNumber)
	printStderr("NotBefore:  %v\n", c.NotBefore)
	printStderr("NotAfter:   %v\n", c.NotAfter)
	printSAN(c)
}

func printSAN(c *x509.Certificate) {
	if len(c.DNSNames)+len(c.EmailAddresses)+len(c.IPAddresses) == 0 {
		return
	}
	printStderr("SubjectAlternativeName:\n")
	for _, d := range c.DNSNames {
		printStderr("- DNS: %s\n", d)
	}
	for _, e := range c.EmailAddresses {
		printStderr("- Email: %s\n", e)
	}
	for _, i := range c.IPAddresses {
		printStderr("- IP: %s\n", i.String())
	}
}

func printName(title string, n pkix.Name) {
	printStderr("%s:\n", title)

	if len(n.Country) != 0 {
		printStderr("  Country:\t\t%s\n", strings.Join(n.Country, " / "))
	}
	if len(n.Organization) != 0 {
		printStderr("  Organization:\t\t%s\n", strings.Join(n.Organization, " / "))
	}
	if len(n.OrganizationalUnit) != 0 {
		printStderr("  OrganizationalUnit:\t%s\n", strings.Join(n.OrganizationalUnit, " / "))
	}
	if len(n.Locality) != 0 {
		printStderr("  Locality:\t\t%s\n", strings.Join(n.Locality, " / "))
	}
	if len(n.Province) != 0 {
		printStderr("  Province:\t\t%s\n", strings.Join(n.Province, " / "))
	}
	if len(n.StreetAddress) != 0 {
		printStderr("  StreetAddress:\t%s\n", strings.Join(n.StreetAddress, " / "))
	}
	if len(n.PostalCode) != 0 {
		printStderr("  PostalCode:\t\t%s\n", strings.Join(n.PostalCode, " / "))
	}
	if len(n.SerialNumber) != 0 {
		printStderr("  SerialNumber:\t\t%s\n", n.SerialNumber)
	}
	if len(n.CommonName) != 0 {
		printStderr("  CommonName:\t\t%s\n", n.CommonName)
	}
}
