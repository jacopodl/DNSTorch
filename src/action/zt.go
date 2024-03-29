package action

import (
	"dnstorch/src/dns"
	"dnstorch/src/dthelper"
	"fmt"
	"net"
	"dnstorch/src/resolver"
)

type ztransfer struct{}

func NewZT() Action {
	return &ztransfer{}
}

func (z *ztransfer) Name() string {
	return "zt"
}

func (z *ztransfer) Description() string {
	return "Perform DNS zone transfer"
}

func (z *ztransfer) Exec(domain string, options *ActOpts) error {
	var query *dns.Query = nil
	var lookup *resolver.DtLookup = nil
	var server net.IP = nil
	var err error = nil

	dthelper.PrintInfo("Testing NS servers for zone transfer...\n")

	if query, err = dns.NewQuery(domain, dns.TYPE_NS, options.Class); err != nil {
		return err
	}

	dthelper.PrintInfo("Enumerating all NS servers...\n")
	if lookup, err = options.Resolv.Resolve(query, true); err != nil {
		return err
	}

	if len(lookup.Msg.Answers) == 0 {
		return fmt.Errorf("no NS servers found for %s", domain)
	}

	for i := range lookup.Msg.Answers {
		ns := lookup.Msg.Answers[i].Rdata.(*dns.NS).NSdname
		dthelper.PrintInfo("Resolving A and AAAA record for %s server...\n", ns)
		if server, err = z.getIpAddr(ns, options.Resolv); err != nil {
			continue
		}
		dthelper.PrintInfo("Trying zone transfer on %s(%s)...\n", ns, server)
		if lk, ok := z.transfer(domain, options.Class, options.Resolv, server); ok {
			dthelper.PrintOk("Zone transfer was successful on server %s(%s)\n\n", ns, server)
			resolver.PrintLookup(lk)
			return nil
		}
	}

	return fmt.Errorf("zone transfer failed")
}

func (z *ztransfer) getIpAddr(domain string, resolv *resolver.Resolver) (net.IP, error) {
	var query *dns.Query = nil
	var lookup *resolver.DtLookup = nil
	var err error = nil

	types := []uint16{dns.TYPE_A, dns.TYPE_AAAA}

	for i := range types {
		query, _ = dns.NewQuery(domain, types[i], dns.CLASS_IN)
		if lookup, err = resolv.Resolve(query, true); err == nil {
			if len(lookup.Msg.Answers) > 0 {
				switch lookup.Msg.Answers[0].Qtype {
				case dns.TYPE_A:
					return lookup.Msg.Answers[0].Rdata.(*dns.A).Address, nil
				case dns.TYPE_AAAA:
					return lookup.Msg.Answers[0].Rdata.(*dns.AAAA).Address, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("A and AAAA record not found for %s", domain)
}

func (z *ztransfer) transfer(domain string, class uint16, resolv *resolver.Resolver, server net.IP) (*resolver.DtLookup, bool) {
	query, _ := dns.NewQuery(domain, dns.TYPE_AXFR, class)
	lookup, err := resolv.ResolveWith(query, false, true, server, dns.PORT)
	if err == nil {
		if lookup.Msg.Rcode == dns.RCODE_NOERR && len(lookup.Msg.Answers) > 0 {
			return lookup, true
		}
	}
	return nil, false
}
