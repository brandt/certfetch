package main

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// Parse a URI into a Host struct
// We attempt to do so in similar fashion to curl.
//
// So all of these are valid:
// - github.com
// - 192.30.252.131
// - github.com:443
// - 192.30.252.131:443
// - 2607:f8b0:400f:803::200e
// - [2607:f8b0:400f:803::200e]:443
// - https://github.com:443
// - https://github.com
// - http://github.com      # This will be interpreted as port 443.
// - http://github.com:443  # This will still use TLS.
// - etc.
//
// We default to port 443/HTTPS instead of 80/HTTP.
func parseURL(arg string) (h Host, err error) {
	var hostport string

	// If arg contains a "//", try to parse it as a URL and extract the hostport.
	if strings.Contains(arg, "//") {
		u, err := url.Parse(arg)
		if err != nil {
			return h, err
		}
		hostport = u.Host
	} else {
		hostport = arg
	}

	host, port, err := parseHostport(hostport)
	if err != nil {
		return h, err
	}

	// Set the domain to host.
	//
	// This could be an IP address (I know, that's weird).  That means at least
	// one of these has to happen in order for the cert to pass verification:
	//
	//   A. The user overrides domain using the -domain flag.
	//   B. The leaf SAN has a matching IP address.
	h.domain = host

	// We set addr to host, though this might be a little confusing as host
	// can be a DNS name.  If it is, the system will resolve it on its own.
	h.addr = host
	h.port = port

	return h, nil
}

// Build a hostport from info in a Host struct
func (h Host) Hostport() (string, error) {
	var hostport string
	// Defaults to port 443 if no port specified
	port := "443"

	if h.port != "" {
		port = h.port
	}

	if h.addr == "" {
		return "", errors.New("address empty")
	}

	// If addr has a colon, assume this is an IPv6 address
	// Simplistic, but hopefully will work given how addr is set.
	if strings.Contains(h.addr, ":") {
		hostport = "[" + h.addr + "]:" + port
	} else {
		hostport = h.addr + ":" + port
	}
	return hostport, nil
}

// Split the host and port segments of a host port
// If there's no port, returns an empty string for the port.
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
