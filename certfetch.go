// Fetches the entire certificate chain and prints some common info about them

package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type Host struct {
	domain, addr, port string
}

var conf struct {
	Domain string
	Addr   string
	File   string
	CAfile string
	Before time.Duration
}

func init() {
	flag.StringVar(&conf.Domain, "domain", "", "specify different domain used during TLS handshake")
	flag.StringVar(&conf.CAfile, "cafile", "", "path to a CA file (PEM) to verify with instead of the default root certs")
	flag.DurationVar(&conf.Before, "exp", 30*24*time.Hour, "warn if certificate will expire in this period of time")
	log.SetFlags(0)
}

func main() {
	var expirationWarnings []string
	now := time.Now()

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("No host specified")
		os.Exit(2)
	} else if flag.NArg() > 1 {
		fmt.Println("Too many arguments")
		os.Exit(2)
	}
	target := parseURL(flag.Args()[0])
	if conf.Domain != "" {
		target.domain = conf.Domain
	}

	chain, err := target.getChain()
	if err != nil {
		printStderr("ERROR: %s/%s: %v\n", target.domain, err)
		os.Exit(1)
	}

	for _, c := range chain {
		printCertInfo(c)
		printPEM(c)
		printStderr("\n")

		if now.Before(c.NotBefore) {
			bw := fmt.Sprintf("WARNING: %s is not valid until %v", target.domain, c.NotBefore)
			expirationWarnings = append(expirationWarnings, bw)
		}

		if now.Add(conf.Before).After(c.NotAfter) {
			aw := fmt.Sprintf("WARNING: %s will expire on %v", target.domain, c.NotAfter)
			expirationWarnings = append(expirationWarnings, aw)
		}
	}

	for _, w := range expirationWarnings {
		printStderr("%s\n", w)
	}
	if len(expirationWarnings) != 0 {
		printStderr("\n")
	}

	res := Verify(target.domain, chain, conf.CAfile)
	if res != nil {
		printStderr("Verify FAILED! Here's why: %s\n", res)
		os.Exit(4)
	}

	printStderr("Verify PASSED\n")
}

func parseURL(arg string) (h Host) {
	var hostport string
	domainRegex := "^([a-zA-Z0-9]|[a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9])([.]([a-zA-Z0-9]|[a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]))*[.]?$"

	if strings.Contains(arg, "//") {
		u, err := url.Parse(arg)
		if err != nil {
			panic(err)
		}
		hostport = u.Host
	} else {
		hostport = arg
	}

	host, port, err := parseHostport(hostport)
	if err != nil {
		printStderr("Invalid hostport: %s", hostport)
		os.Exit(2)
	}

	res, _ := regexp.MatchString(domainRegex, host)
	if res {
		h.domain = host
	} else {
		h.domain = ""
	}

	h.addr = host
	h.port = port

	return h
}

func (h Host) Hostport() (string, error) {
	port := "443"
	if h.port != "" {
		port = h.port
	}
	if h.addr == "" {
		return "", errors.New("address empty")
	}
	hostport := h.addr + ":" + port
	return hostport, nil
}

// getChain returns chain of certificates retrieved from TLS session
// established at given addr (host:port) for hostname provided. If addr is
// empty, then hostname:443 is used.
func (h Host) getChain() ([]*x509.Certificate, error) {
	var (
		conn *tls.Conn
		err  error
	)

	type tempErr interface {
		Temporary() bool
	}

	hostport, err := h.Hostport()
	if err != nil {
		printStderr("ERROR: Problem with hostport: %s\n", err)
	}

	conf := &tls.Config{InsecureSkipVerify: true}
	if h.domain != "" {
		conf.ServerName = h.domain
	}

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	// attempt to establish connection 3 times
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i) * time.Second)
		}

		conn, err = tls.DialWithDialer(dialer, "tcp", hostport, conf)
		if e, ok := err.(tempErr); ok && e.Temporary() {
			printStderr("Connection attempt failed: %s\n", hostport)
			continue
		}
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		return conn.ConnectionState().PeerCertificates, nil
	}

	return nil, err
}

func parseHostport(hostport string) (host, port string, err error) {
	if strings.Contains(hostport, "]") || strings.Count(hostport, ":") == 1 {
		host, port, err = net.SplitHostPort(hostport)
		if err != nil {
			return host, port, err
		}
		return host, port, nil
	}
	return hostport, "", nil
}

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
