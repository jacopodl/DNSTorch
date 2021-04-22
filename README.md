![](https://img.shields.io/badge/Language-Go-orange.svg)
![](https://img.shields.io/badge/version-1.0.0-green.svg)
[![GPLv3 License](https://img.shields.io/badge/License-GPLv3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0.html)

# DNSTorch
DNSTorch is an experimental tool that in standard use is similar to the dig command, but unlike it, it includes several ways to perform more in-depth analysis.

# Setting up DNSTorch :hammer:

:warning: **Make sure you have at least Go 1.8 in your system to build DNSTorch** :warning:

First, getting the code from repository and compile it with following command:

    $ cd dnstorch
    $ export GO111MODULE=off
    $ export GOPATH=$(shell pwd)
    $ go build -o bin/dnstorch src/main.go

or run (certainly faster to type 🚀):
    
    $ make

# Usage examples

	$ dnstorch www.google.com
	
	?? Query
	?$ Flags: AA: false RD: true AD: false CD: false
	? www.google.com	A	1

	!! Answer
	!$ ID: 0
	!$ Flags: AA: false TC: false RD: true RA: true Z: false AD: false CD: false
	!$ Rcode: 0 (request completed successfully)

	!$ Answers (1)
	! www.google.com	A	1	140	142.250.184.100
	
	$ dnstorch -mode walk iana.org
	
	[!] Testing iana.org for zone walking...
	! iana.org	NSEC	1	3599	api.iana.org A NS SOA MX TXT AAAA RRSIG NSEC DNSKEY
	.
	.
	! whois.iana.org	NSEC	1	3599	www.iana.org CNAME RRSIG NSEC
	! www.iana.org		NSEC	1	3599	iana.org CNAME RRSIG NSEC
	[+] Found 60 domains
	
# Supported modes 🔧

* dnsbl:
	- Search into multiple DNS-based blackhole list
* walk
	- Perform DNS NSEC walking
* snoop
	- Perform a DNS cache snooping
* enum
	- Perform brute force subdomain enumeration
* zt
	- Perform DNS zone transfer


# Contribute
All contributions are always welcome 😄
