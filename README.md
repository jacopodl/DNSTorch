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
