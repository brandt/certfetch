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

	target, err := parseURL(flag.Args()[0])
	if err != nil {
		printStderr("ERROR: Problem parsing URL: %v\n", err)
		os.Exit(2)
	}
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
