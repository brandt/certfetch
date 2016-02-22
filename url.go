package main

import (
	"errors"
	"net"
	"net/url"
	"regexp"
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
// - https://github.com
// - http://github.com   # Caveat: This will be interpreted as port 443.
//
// An important difference is that we default to port 443 instead of 80.
func parseURL(arg string) (h Host, err error) {
	var hostport string
	domainRegex := "^([a-zA-Z0-9]|[a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9])([.]([a-zA-Z0-9]|[a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]))*[.]?$"

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

	// Detect whether the host is a domain (rather than an IP)
	// If so, set the domain member.
	res, _ := regexp.MatchString(domainRegex, host)
	if res {
		h.domain = host
	} else {
		h.domain = ""
	}

	// We set addr to host, though this might be a little confusing as host
	// can be a DNS name.  If it is, the system will resolve it on its own.
	h.addr = host
	h.port = port

	return h, nil
}

// Build a hostport from info in a Host struct
func (h Host) Hostport() (string, error) {
	// Defaults to port 443 if no port specified
	port := "443"
	if h.port != "" {
		port = h.port
	}
	if h.addr == "" {
		return "", errors.New("address empty")
	}
	// FIXME: This might not work for IPv6 (not sure if net.SplitHostPort retains the square brackets)
	hostport := h.addr + ":" + port
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
