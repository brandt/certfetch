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
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("No host specified")
		os.Exit(2)
	} else if flag.NArg() > 1 {
		fmt.Println("Too many arguments")
		os.Exit(2)
	}
	hostport := parseURL(flag.Args()[0])

	fetch(conf.Domain, hostport, conf.CAfile, conf.Before)
}

func parseURL(arg string) string {
	var hostport string

	if strings.Contains(arg, "//") {
		u, err := url.Parse(arg)
		if err != nil {
			panic(err)
		}
		hostport = u.Host
	} else {
		hostport = arg
	}

	if !strings.Contains(hostport, ":") {
		hostport = hostport + ":443"
	}

	r, _ := regexp.Compile(`[-_a-zA-Z0-9.]+:[0-9]+`)
	if !r.MatchString(hostport) {
		fmt.Println("Invalid hostport")
		os.Exit(2)
	}

	return hostport
}

// fetch prints pretty report
func fetch(domain, addr, cafile string, dur time.Duration) {
	var expirationWarnings []string

	if domain == "" {
		h := strings.Split(addr, ":")
		domain = h[0]
	}

	chain, err := getChain(domain, addr)
	if err != nil {
		printStderr("ERROR: %s/%s: %v\n", domain, addr, err)
		os.Exit(1)
	}

	now := time.Now()

	for _, c := range chain {
		printCertInfo(c)
		printPEM(c)
		printStderr("\n")

		if now.Before(c.NotBefore) {
			bw := fmt.Sprintf("WARNING: %s is not valid until %v", domain, c.NotBefore)
			expirationWarnings = append(expirationWarnings, bw)
		}

		if now.Add(dur).After(c.NotAfter) {
			aw := fmt.Sprintf("WARNING: %s will expire on %v", domain, c.NotAfter)
			expirationWarnings = append(expirationWarnings, aw)
		}
	}

	for _, w := range expirationWarnings {
		printStderr("%s\n", w)
	}
	if len(expirationWarnings) != 0 {
		printStderr("\n")
	}

	res := Verify(domain, chain, cafile)
	if res != nil {
		printStderr("Verify FAILED! Here's why: %s\n", res)
		os.Exit(4)
	}

	printStderr("Verify PASSED\n")
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

// getChain returns chain of certificates retrieved from TLS session
// established at given addr (host:port) for hostname provided. If addr is
// empty, then hostname:443 is used.
func getChain(hostname, addr string) ([]*x509.Certificate, error) {
	if hostname == "" {
		return nil, errors.New("empty hostname")
	}

	var (
		conn *tls.Conn
		err  error
	)

	type tempErr interface {
		Temporary() bool
	}

	conf := &tls.Config{ServerName: hostname, InsecureSkipVerify: true}
	if addr == "" {
		addr = hostname + ":443"
	}

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	// attempt to establish connection 3 times
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i) * time.Second)
		}

		conn, err = tls.DialWithDialer(dialer, "tcp", addr, conf)
		if e, ok := err.(tempErr); ok && e.Temporary() {
			printStderr("Connection attempt failed: %s\n", addr)
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
