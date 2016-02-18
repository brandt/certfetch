// Fetches the entire certificate chain and prints some common info about them

package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/csv"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var conf struct {
	Domain string
	Addr   string
	File   string
	Before time.Duration
}

func init() {
	flag.StringVar(&conf.Domain, "domain", "", "use this domain name during TLS handshake")
	flag.StringVar(&conf.Addr, "addr", "", "host:port to connect to (defaults to domain:443")
	flag.StringVar(&conf.File, "file", "", "read domain+addr pairs from this CSV file")
	flag.DurationVar(&conf.Before, "exp", 30*24*time.Hour, "warn if certificate will expire in this period of time")
	log.SetFlags(0)
}

func main() {
	flag.Parse()

	if conf.File == "" {
		check(conf.Domain, conf.Addr, conf.Before)
		return
	}

	f, err := os.Open(conf.File)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	rd := csv.NewReader(f)
	rd.FieldsPerRecord = -1
	rd.Comment = '#'
	rd.TrimLeadingSpace = true

	g := newGate(5)

	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Print(err)
			break
		}
		switch len(rec) {
		case 1:
			g.Lock()
			go func(d string) { check(d, "", conf.Before); g.Unlock() }(rec[0])
		case 2:
			g.Lock()
			go func(d, a string) { check(d, a, conf.Before); g.Unlock() }(rec[0], rec[1])
		default:
			log.Print("csv line skipped: invalid number of fields", len(rec))
		}
	}

	// by acquiring gate lock as many times as its capacity we make sure
	// that none other goroutines hold it
	for i := 0; i < cap(g); i++ {
		g.Lock()
	}
}

type gate chan struct{}

func newGate(n int) gate { return make(gate, n) }
func (g gate) Lock()     { g <- struct{}{} }
func (g gate) Unlock()   { <-g }

// check prints pretty report
func check(domain, addr string, dur time.Duration) {
	if addr == "" {
		addr = domain + ":443"
	}
	chain, err := getChain(domain, addr)
	if err != nil {
		fmt.Printf("%s/%s: %v\n", domain, addr, err)
		return
	}
	now := time.Now()
	for i, c := range chain {
		printCertInfo(c)
		pem := string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}))
		fmt.Printf("%s", pem)
		fmt.Fprintf(os.Stderr, "\n")

		if now.Before(c.NotBefore) {
			fmt.Fprintf(os.Stderr, "%s/%s [%d]: NotBefore is %v\n", domain, addr, i, c.NotBefore)
		}
		if now.Add(dur).After(c.NotAfter) {
			fmt.Fprintf(os.Stderr, "%s/%s [%d]: will expire soon (%v)\n", domain, addr, i, c.NotAfter)
		}
	}
}

func printCertInfo(c *x509.Certificate) {
	if c.IsCA {
		fmt.Fprintf(os.Stderr, "=== CERTIFICATE AUTHORITY ===\n")
	}
	printName("Issuer", c.Issuer)
	printName("Subject", c.Subject)
	fmt.Fprintf(os.Stderr, "Serial:     %d\n", c.SerialNumber)
	fmt.Fprintf(os.Stderr, "NotBefore:  %v\n", c.NotBefore)
	fmt.Fprintf(os.Stderr, "NotAfter:   %v\n", c.NotAfter)
	printSAN(c)
}

func printSAN(c *x509.Certificate) {
	if len(c.DNSNames)+len(c.EmailAddresses)+len(c.IPAddresses) > 0 {
		fmt.Fprintf(os.Stderr, "SubjectAlternativeName:\n")
	}
	for _, d := range c.DNSNames {
		fmt.Fprintf(os.Stderr, "- DNS: %s\n", d)
	}
	for _, e := range c.EmailAddresses {
		fmt.Fprintf(os.Stderr, "- Email: %s\n", e)
	}
	for _, i := range c.IPAddresses {
		fmt.Fprintf(os.Stderr, "- IP: %s\n", i.String())
	}
}

func printName(title string, n pkix.Name) {
	fmt.Fprintf(os.Stderr, "%s:\n", title)

	if len(n.Country) != 0 {
		fmt.Fprintf(os.Stderr, "  Country:\t\t%s\n", strings.Join(n.Country, " / "))
	}
	if len(n.Organization) != 0 {
		fmt.Fprintf(os.Stderr, "  Organization:\t\t%s\n", strings.Join(n.Organization, " / "))
	}
	if len(n.OrganizationalUnit) != 0 {
		fmt.Fprintf(os.Stderr, "  OrganizationalUnit:\t%s\n", strings.Join(n.OrganizationalUnit, " / "))
	}
	if len(n.Locality) != 0 {
		fmt.Fprintf(os.Stderr, "  Locality:\t\t%s\n", strings.Join(n.Locality, " / "))
	}
	if len(n.Province) != 0 {
		fmt.Fprintf(os.Stderr, "  Province:\t\t%s\n", strings.Join(n.Province, " / "))
	}
	if len(n.StreetAddress) != 0 {
		fmt.Fprintf(os.Stderr, "  StreetAddress:\t%s\n", strings.Join(n.StreetAddress, " / "))
	}
	if len(n.PostalCode) != 0 {
		fmt.Fprintf(os.Stderr, "  PostalCode:\t\t%s\n", strings.Join(n.PostalCode, " / "))
	}
	if len(n.SerialNumber) != 0 {
		fmt.Fprintf(os.Stderr, "  SerialNumber:\t\t%s\n", n.SerialNumber)
	}
	if len(n.CommonName) != 0 {
		fmt.Fprintf(os.Stderr, "  CommonName:\t\t%s\n", n.CommonName)
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
	conf := &tls.Config{ServerName: hostname}
	if addr == "" {
		addr = hostname + ":443"
	}
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i) * time.Second)
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, conf)
		if e, ok := err.(tempErr); ok && e.Temporary() {
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
