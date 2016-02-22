// Fetches the entire certificate chain and prints some common info about them

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
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
	flag.StringVar(&conf.CAfile, "cafile", "", "path to a CA file (PEM) to use instead of the default system root certs")
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

	target, err := parseURL(flag.Args()[0])
	if err != nil {
		printStderr("ERROR: Problem parsing URL: %s: %v\n", flag.Args()[0], err)
		os.Exit(2)
	}

	// Domain provided via CLI argument overrides default
	if conf.Domain != "" {
		target.domain = conf.Domain
	}

	chain, err := target.getChain()
	if err != nil {
		printStderr("ERROR: %s: %v\n", target.domain, err)
		os.Exit(1)
	}

	printCerts(chain)
	checkDates(chain)

	res := Verify(target.domain, chain, conf.CAfile)
	if res != nil {
		printStderr("%s", colorize(FgRed, "Verify: FAIL\n  `-> Reason: "))
		printStderr("%s\n", res)
		os.Exit(4)
	}
	printStderr("Verify: PASS\n")
}

func checkDates(chain []*x509.Certificate) {
	now := time.Now()

	for i, c := range chain {
		if now.Before(c.NotBefore) {
			printStderr("WARNING: Certificate %d is not valid until %v\n", i, c.NotBefore)
		}

		if now.After(c.NotAfter) {
			printStderr("WARNING: Certificate %d expired on %v\n", i, c.NotAfter)
		} else if now.Add(conf.Before).After(c.NotAfter) {
			printStderr("WARNING: Certificate %d will expire on %v\n", i, c.NotAfter)
		}
	}
}

// getChain returns the chain of certificates retrieved from TLS session
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

	conf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
	}
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
