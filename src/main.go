package main

import (
	"dns"
	"flag"
	"fmt"
	"net"
	"os"
	"resolver"
	"strconv"
	"strings"
	"time"
)

const (
	VERSION = "1.0.0"
	LOGO    = `
▓█████▄  ███▄    █   ██████ ▄▄▄█████▓ ▒█████   ██▀███   ▄████▄   ██░ ██ 
▒██▀ ██▌ ██ ▀█   █ ▒██    ▒ ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒▒██▀ ▀█  ▓██░ ██▒
░██   █▌▓██  ▀█ ██▒░ ▓██▄   ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒▒▓█    ▄ ▒██▀▀██░
░▓█▄   ▌▓██▒  ▐▌██▒  ▒   ██▒░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄  ▒▓▓▄ ▄██▒░▓█ ░██ 
░▒████▓ ▒██░   ▓██░▒██████▒▒  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒▒ ▓███▀ ░░▓█▒░██▓
 ▒▒▓  ▒ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░ ░▒ ▒  ░ ▒ ░░▒░▒
 ░ ▒  ▒ ░ ░░   ░ ▒░░ ░▒  ░ ░    ░      ░ ▒ ▒░   ░▒ ░ ▒░  ░  ▒    ▒ ░▒░ ░
 ░ ░  ░    ░   ░ ░ ░  ░  ░    ░      ░ ░ ░ ▒    ░░   ░ ░         ░  ░░ ░
   ░             ░       ░               ░ ░     ░     ░ ░       ░  ░  ░
 ░                                                     ░                `
)

type Options struct {
	aa        bool
	ad        bool
	cd        bool
	class     uint16
	dict      string
	ignore    bool
	nord      bool
	ns        string
	snoop     bool
	tcp       bool
	timeout   int
	trace     bool
	qtype     uint16
	ztransfer bool
}

func onError(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err.Error())
	os.Exit(-1)
}

func usage() {
	fmt.Fprintf(os.Stderr, LOGO)
	fmt.Fprintf(os.Stderr, " V: %s\n\n", VERSION)
	fmt.Fprintf(os.Stderr, "usage: dnstorch [options] [domain]\n\n")
	fmt.Fprintf(os.Stderr, "optional arguments:\n")
	flag.PrintDefaults()
}

func parseAddress(address string) (net.IP, int, error) {
	var port uint64 = dns.PORT
	var err error = nil

	split := strings.Split(address, ":")

	if len(split) > 1 {
		if port, err = strconv.ParseUint(split[1], 10, 16); err != nil {
			return nil, 0, fmt.Errorf("malformed port: %s", split[2])
		}
	}

	if ip := net.ParseIP(split[0]); ip != nil {
		return ip, int(port), nil
	}

	// resolve address
	if ips, err := net.LookupIP(split[0]); err != nil {
		return nil, 0, err
	} else {
		return ips[0], int(port), nil
	}
}

func resolve(domain string, rsv *resolver.Resolver, options *Options) {
	var query *dns.Query = nil
	var lookup *resolver.DtLookup = nil
	var err error = nil

	if query, err = dns.NewQuery(domain, options.qtype, options.class); err != nil {
		onError(err)
	}

	if !options.trace {
		lookup, err = rsv.Resolve(query, !options.nord)
	} else {
		lookup, err = rsv.Trace(query)
	}

	if err != nil && lookup == nil {
		onError(err)
	}

	resolver.PrintLookup(lookup)
}

func main() {
	var options = Options{}
	var dnaddr net.IP = nil
	var dnport = 0
	var stype = ""
	var sclass = ""
	var err error = nil

	flag.StringVar(&stype, "t", "A", "Specify query type")
	flag.BoolVar(&options.aa, "aa", false, "Set AA flag in query")
	flag.BoolVar(&options.ad, "ad", false, "Set AD flag in query")
	flag.BoolVar(&options.cd, "cd", false, "Set checking disabled flag in query")
	flag.StringVar(&sclass, "class", "IN", "Specify query class [IN, CH, HS, NONE, ANY]")
	flag.StringVar(&options.dict, "dict", "", "Dictionary file of subdomain to use for brute force")
	flag.BoolVar(&options.ignore, "ignore", false, "Don't revert to TCP for TC responses")
	flag.BoolVar(&options.nord, "nord", false, "Unset recursion desired flag in query")
	flag.StringVar(&options.ns, "ns", "", "Domain server to use.")
	flag.BoolVar(&options.snoop, "snoop", false, "Perform a cache snooping")
	flag.IntVar(&options.timeout, "timeout", 800, "Time(ms) to wait for a server to response to a query")
	flag.BoolVar(&options.trace, "trace", false, "Trace delegation down from root")
	flag.BoolVar(&options.tcp, "tcp", false, "Use TCP protocol to make queries")
	flag.BoolVar(&options.ztransfer, "zt", false, "Perform a zone transfer (axfr)")
	flag.Usage = usage
	flag.Parse()

	// assign address
	if options.ns != "" {
		if dnaddr, dnport, err = parseAddress(options.ns); err != nil {
			onError(err)
		}
	}

	// Convert DNS string type to DNS type
	if tp, ok := dns.TName2Type(stype); ok {
		options.qtype = tp
	} else {
		onError(fmt.Errorf("unknown type: %s", stype))
	}

	// Convert DNS string class to DNS class
	if cl, ok := dns.CName2Class(sclass); ok {
		options.class = cl
	} else {
		onError(fmt.Errorf("unknown class: %s", sclass))
	}

	rsv := resolver.NewResolver(dnaddr, dnport, options.tcp)
	rsv.Timeout = time.Duration(options.timeout)
	rsv.Ignore = options.ignore
	rsv.Flags.AAFlag = options.aa
	rsv.Flags.ADFlag = options.ad
	rsv.Flags.CDFlag = options.cd

	resolve(flag.Arg(0), rsv, &options)
}
