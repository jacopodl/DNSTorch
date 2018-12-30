package main

import (
	"action"
	"dns"
	"dthelper"
	"flag"
	"fmt"
	"net"
	"os"
	"resolver"
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

	fmt.Fprintf(os.Stderr, "\nModes:\n\n")
	for key, mod := range action.Actions {
		fmt.Fprintf(os.Stderr, "%s\n\t%s\n", key, mod.Description())
	}
}

func resolve(query *dns.Query, resolv *resolver.Resolver, trace, nord bool) *resolver.DtLookup {
	var lookup *resolver.DtLookup = nil
	var err error = nil

	if !trace {
		lookup, err = resolv.Resolve(query, !nord)
	} else {
		lookup, err = resolv.Trace(query)
	}

	if err != nil && lookup == nil {
		onError(err)
	}

	return lookup
}

func main() {
	var resolv *resolver.Resolver = nil
	var dnaddr net.IP = nil
	var dnport = dns.PORT
	var qtype uint16 = 0
	var qclass uint16 = 0
	var err error = nil

	stype := flag.String("type", "A", "Specify query type")
	aa := flag.Bool("aa", false, "Set AA flag in query")
	ad := flag.Bool("ad", false, "Set AD flag in query")
	cd := flag.Bool("cd", false, "Set checking disabled flag in query")
	sclass := flag.String("class", "IN", "Specify query class [IN, CH, HS, NONE, ANY]")
	delay := flag.Int("delay", 0, "Delay(ms) between two request")
	dict := flag.String("dict", "", "Dictionary file of subdomain to use for brute force")
	ignore := flag.Bool("ignore", false, "Don't revert to TCP for TC responses")
	nord := flag.Bool("nord", false, "Unset recursion desired flag in query")
	ns := flag.String("ns", "", "Domain server to use.")
	timeout := flag.Int("timeout", 800, "Time(ms) to wait for a server to response to a query")
	trace := flag.Bool("trace", false, "Trace delegation down from root")
	tcp := flag.Bool("tcp", false, "Use TCP protocol to make queries")
	mode := flag.String("mode", "", "Set operation mode")

	// Register operation modes
	action.Register(action.NewSnoop())
	action.Register(action.NewEnum())

	flag.Usage = usage
	flag.Parse()

	// Default DNS server
	if *ns != "" {
		if dnaddr, dnport, err = dthelper.ParseDSAddr(*ns); err != nil {
			onError(err)
		}
	} else {
		if dnaddr, err = dthelper.DefaultDNS(); err != nil {
			onError(err)
		}
	}

	// Convert DNS string type to DNS type
	if tp, ok := dns.TName2Type(*stype); ok {
		qtype = tp
	} else {
		onError(fmt.Errorf("unknown type: %s", *stype))
	}

	// Convert DNS string class to DNS class
	if cl, ok := dns.CName2Class(*sclass); ok {
		qclass = cl
	} else {
		onError(fmt.Errorf("unknown class: %s", sclass))
	}

	// Resolver setup
	resolv = resolver.NewResolver(dnaddr, dnport, *tcp)
	resolv.Ignore = *ignore
	resolv.Timeout = time.Duration(*timeout)
	resolv.Flags.AAFlag = *aa
	resolv.Flags.ADFlag = *ad
	resolv.Flags.CDFlag = *cd

	if *mode == "" {
		if query, err := dns.NewQuery(flag.Arg(0), qtype, qclass); err == nil {
			resolver.PrintLookup(resolve(query, resolv, *trace, *nord))
		} else {
			onError(err)
		}
		return
	}

	opts := &action.Options{
		Delay:  time.Duration(*delay) * time.Millisecond,
		Dict:   *dict,
		Class:  qclass,
		Type:   qtype,
		Resolv: resolv}

	if act, err := action.Init(*mode, opts); err != nil {
		onError(err)
	} else {
		if err = act.Exec(flag.Arg(0)); err != nil {
			onError(err)
		}
	}
}
