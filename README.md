Command certcheck verifies remote certificate chains for some common problems
like expiration dates or domain name mismatch.

	Usage of certcheck:
	  -addr string
		host:port to connect to (defaults to domain:443)
	  -domain string
		use this domain name during TLS handshake
	  -exp duration
		warn if certificate will expire in this period of time (default 720h0m0s)
	  -file string
		read domain+addr pairs from this CSV file
