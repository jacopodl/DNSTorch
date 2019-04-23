package main

import (
	"action"
	"dns"
	"dns/resolver"
	"dthelper"
	"flag"
	"fmt"
	"net"
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

type Options struct {
	resolv  *resolver.Resolver
	gflags  resolver.Flags
	ignore  bool
	soa     bool
	tcp     bool
	trace   bool
	delay   int
	timeout int
	workers int
	mdeleg  int
	class   uint16
	qtype   uint16
	ns      string
	mode    string
}

func onError(err error) {
	dthelper.PrintErr("%s\n", err.Error())
	os.Exit(-1)
}

func resolve(target string, options *Options) {
	var query *dns.Query = nil
	var lookup *resolver.Response = nil
	var err error = nil

	if query, err = dns.NewQuery(target, options.qtype, options.class); err != nil {
		onError(err)
	}

	if !options.trace {
		lookup, err = options.resolv.Resolve(query, !options.gflags.RD)
	} else {
		lookup, err = options.resolv.Trace(query)
	}

	if err != nil && lookup == nil {
		onError(err)
	}

	resolver.PrintLookup(lookup)
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
	var opts = Options{}
	var dnaddr net.IP = nil
	var dnport = dns.PORT
	var dpath = ""
	var mode = ""
	var ns = ""
	var nsl = ""
	var sclass = ""
	var stype = ""
	var err error = nil

	flag.BoolVar(&opts.gflags.AA, "aa", false, "Set AA flag in query")
	flag.BoolVar(&opts.gflags.AD, "ad", false, "Set AD flag in query")
	flag.BoolVar(&opts.gflags.CD, "cd", false, "Set checking disabled flag in query")
	flag.BoolVar(&opts.gflags.RD, "nord", false, "Unset recursion desired flag in query")
	flag.BoolVar(&opts.ignore, "ignore", false, "Don't revert to TCP for TC responses")
	flag.BoolVar(&opts.soa, "soa", false, "Use nameserver in target SOA record (mode: walk)")
	flag.BoolVar(&opts.tcp, "tcp", false, "Use TCP protocol to make queries")
	flag.BoolVar(&opts.trace, "trace", false, "Trace delegation down from root")
	flag.IntVar(&opts.delay, "delay", 0, "Delay(ms) between two request")
	flag.IntVar(&opts.mdeleg, "deleg", 24, "Set max level of delegations in trace mode")
	flag.IntVar(&opts.timeout, "timeout", 800, "Time(ms) to wait for a server to response to a query")
	flag.IntVar(&opts.workers, "workers", 1, "Set number of active workers")
	flag.StringVar(&dpath, "dict", "", "Dictionary file of subdomain to use for brute force")
	flag.StringVar(&mode, "mode", "", "Set operation mode")
	flag.StringVar(&ns, "ns", "", "Domain server to use.")
	flag.StringVar(&nsl, "list", "", "List of domain servers to use")
	flag.StringVar(&sclass, "class", "IN", "Specify query class [IN, CH, HS, NONE, ANY]")
	flag.StringVar(&stype, "type", "A", "Specify query type")

	// Register operation modes
	_ = action.Register(action.NewSnoop())
	_ = action.Register(action.NewEnum())
	_ = action.Register(action.NewZT())
	_ = action.Register(action.NewDnsBL())
	_ = action.Register(action.NewWalk())

	flag.Usage = usage
	flag.Parse()

	// Default DNS server
	if ns != "" {
		if dnaddr, dnport, err = dthelper.ParseAddr(ns); err != nil {
			onError(err)
		}
	} else {
		if dnaddr, err = dthelper.DefaultDNS(); err != nil {
			onError(err)
		}
	}

	// Convert DNS string class to DNS class
	if cl, ok := dns.CName2Class(sclass); ok {
		opts.class = cl
	} else {
		onError(fmt.Errorf("unknown class: %s", sclass))
	}

	// Convert DNS string type to DNS type
	if tp, ok := dns.TName2Type(stype); ok {
		opts.qtype = tp
	} else {
		onError(fmt.Errorf("unknown type: %s", stype))
	}

	// Setup Resolver
	opts.resolv = resolver.NewResolver(dnaddr, dnport, opts.tcp)
	opts.resolv.Ignore = opts.ignore
	opts.resolv.Timeout = time.Duration(opts.timeout)
	opts.resolv.MaxDelegations = opts.mdeleg
	opts.resolv.Flags.AA = opts.gflags.AA
	opts.resolv.Flags.AD = opts.gflags.AD
	opts.resolv.Flags.CD = opts.gflags.CD

	// Load NS list (If passed)
	if nsl != "" {
		if err = dthelper.ParseNSList(nsl, opts.resolv); err != nil {
			onError(err)
		}
	}

	if mode == "" {
		target, isaddr := dthelper.ParseTarget(flag.Arg(0))
		if isaddr && opts.qtype == dns.TYPE_A {
			opts.qtype = dns.TYPE_PTR
		}
		resolve(target, &opts)
		return
	}

	aopts := &action.ActOpts{
		Delay:   time.Duration(opts.delay) * time.Millisecond,
		Class:   opts.class,
		Soa:     opts.soa,
		Type:    opts.qtype,
		Workers: opts.workers,
		Resolv:  opts.resolv}

	// Load dict file
	if dpath != "" {
		if aopts.Dict, err = dthelper.NewFDict(dpath, dthelper.DEFAULTQLEN); err != nil {
			onError(err)
		}
	}

	if act, err := action.Get(mode); err != nil {
		onError(err)
	} else {
		if err = act.Exec(flag.Arg(0), aopts); err != nil {
			onError(err)
		}
	}

	return
}
