package main

import (
	"action"
	"dns"
	"dns/resolver"
	"dthelper"
	"flag"
	"fmt"
	"os"
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
	dthelper.PrintErr("%s\n", err.Error())
	os.Exit(-1)
}

func loadServersOrDie(laddr string, nsl string, rsv *resolver.Resolver) {
	var atLeastOne = false

	// User DNS server
	if laddr != "" {
		if addr, port, err := dthelper.ParseAddr(laddr); err == nil {
			rsv.AddNS(addr, port)
			atLeastOne = true
		} else {
			onError(err)
		}
	}

	// Load DNS servers list
	if nsl != "" {
		if err := dthelper.ParseNSList(nsl, rsv); err != nil {
			onError(err)
		}
		atLeastOne = true
	}

	// Default DNS server
	if !atLeastOne {
		if addr, err := dthelper.DefaultDNS(); err != nil {
			onError(err)
		} else {
			rsv.AddNS(addr, dns.PORT)
		}
	}
}

func resolve(query *dns.Query, rsv *resolver.Resolver, trace, rd bool) {
	var lookup *resolver.Response = nil
	var err error = nil

	if !trace {
		lookup, err = rsv.Resolve(query, rd)
	} else {
		lookup, err = rsv.Trace(query)
	}

	if err != nil && lookup == nil {
		onError(err)
	}

	resolver.PrintLookup(lookup)
}

func toDnsClassOrDie(sclass string) (cl uint16) {
	var ok = false
	if cl, ok = dns.CName2Class(sclass); !ok {
		onError(fmt.Errorf("unknown class: %s", sclass))
	}
	return
}

func toDnsTypeOrDie(stype string) (tp uint16) {
	var ok = false
	if tp, ok = dns.TName2Type(stype); !ok {
		onError(fmt.Errorf("unknown type: %s", stype))
	}
	return
}

func usage() {
	_, _ = fmt.Fprintf(os.Stderr, LOGO)
	_, _ = fmt.Fprintf(os.Stderr, " V: %s\n\n", VERSION)
	_, _ = fmt.Fprintf(os.Stderr, "usage: dnstorch [options] <domain>\n\n")
	_, _ = fmt.Fprintf(os.Stderr, "optional arguments:\n")

	flag.PrintDefaults()

	_, _ = fmt.Fprintf(os.Stderr, "\nModes:\n\n")
	for key, mod := range action.Actions {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n\t%s\n", key, mod.Description())
	}
}

func main() {
	var rsv = resolver.NewResolver()
	var nord = false
	var trace = false
	var useSOA = false
	var delay = 0
	var timeout = 0
	var workers = 0
	var dictPath = ""
	var mode = ""
	var ns = ""
	var nsl = ""
	var lClass = ""
	var lType = ""
	var err error = nil

	flag.BoolVar(&rsv.Flags.AA, "aa", false, "Set AA flag in query")
	flag.BoolVar(&rsv.Flags.AD, "ad", false, "Set AD flag in query")
	flag.BoolVar(&rsv.Flags.CD, "cd", false, "Set checking disabled flag in query")
	flag.BoolVar(&nord, "nord", false, "Unset recursion desired flag in query")
	flag.BoolVar(&rsv.Ignore, "ignore", false, "Don't revert to TCP for TC responses")
	flag.BoolVar(&rsv.Tcp, "tcp", false, "Use TCP protocol to make queries")
	flag.BoolVar(&trace, "trace", false, "Trace delegation down from root")
	flag.BoolVar(&useSOA, "soa", false, "Use nameserver in target SOA record (mode: walk)")
	flag.IntVar(&delay, "delay", 0, "Delay(ms) between two request")
	flag.IntVar(&rsv.MaxDelegations, "deleg", 24, "Set max level of delegations in trace mode")
	flag.IntVar(&timeout, "timeout", 800, "Time(ms) to wait for a server to response to a query")
	flag.IntVar(&workers, "workers", 1, "Set number of active workers")
	flag.StringVar(&dictPath, "dict", "", "Dictionary file of subdomain to use for brute force")
	flag.StringVar(&mode, "mode", "", "Set operation mode")
	flag.StringVar(&ns, "ns", "", "Domain server to use.")
	flag.StringVar(&nsl, "list", "", "List of domain servers to use")
	flag.StringVar(&lClass, "class", "IN", "Specify query class [IN, CH, HS, NONE, ANY]")
	flag.StringVar(&lType, "type", "A", "Specify query type")

	// Register operation modes
	_ = action.Register(action.NewSnoop())
	_ = action.Register(action.NewEnum())
	_ = action.Register(action.NewZT())
	_ = action.Register(action.NewDnsBL())
	_ = action.Register(action.NewWalk())

	flag.Usage = usage
	flag.Parse()

	loadServersOrDie(ns, nsl, rsv)

	if mode == "" {
		target, isaddr := dthelper.ParseTarget(flag.Arg(0))
		class := toDnsClassOrDie(lClass)
		qtype := toDnsTypeOrDie(lType)

		if isaddr && qtype == dns.TYPE_A {
			qtype = dns.TYPE_PTR
		}

		if query, err := dns.NewQuery(target, qtype, class); err != nil {
			onError(err)
		} else {
			resolve(query, rsv, trace, !nord)
		}
		return
	}

	aopts := &action.ActOpts{
		Delay:   time.Duration(delay) * time.Millisecond,
		Class:   toDnsClassOrDie(lClass),
		Soa:     useSOA,
		Type:    toDnsTypeOrDie(lType),
		Workers: workers,
		Resolv:  rsv}

	// Load dict file
	if dictPath != "" {
		if aopts.Dict, err = dthelper.NewFDict(dictPath, dthelper.DefaultQLen); err != nil {
			onError(err)
		}
	}

	if act, err := action.Get(mode); err != nil {
		onError(err)
	} else {
		start := time.Now()
		if err = act.Exec(flag.Arg(0), aopts); err != nil {
			onError(err)
		}
		dthelper.PrintInfo("Time elapsed: %s", time.Since(start).String())
	}
	return
}
