package main

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
)

func parseURL(arg string) (h Host, err error) {
	var hostport string
	domainRegex := "^([a-zA-Z0-9]|[a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9])([.]([a-zA-Z0-9]|[a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]))*[.]?$"

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

	res, _ := regexp.MatchString(domainRegex, host)
	if res {
		h.domain = host
	} else {
		h.domain = ""
	}

	h.addr = host
	h.port = port

	return h, nil
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
