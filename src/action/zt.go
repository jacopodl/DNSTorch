package action

import (
	"dns"
	"dns/resolver"
	"dthelper"
	"fmt"
	"net"
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
	var lookup *resolver.Response = nil
	var server net.IP = nil
	var err error = nil

	dthelper.PrintInfo("Testing NS servers for zone transfer...\n")

	dthelper.PrintInfo("Enumerating all NS servers...\n")
	if lookup, err = options.Resolv.ResolveDomain(domain, dns.TYPE_NS, options.Class); err != nil {
		return err
	}

	if len(lookup.Msg.Answers) == 0 {
		return fmt.Errorf("no NS servers found for %s", domain)
	}

	for i := range lookup.Msg.Answers {
		ns := lookup.Msg.Answers[i].Rdata.(*dns.NS).NSdname
		dthelper.PrintInfo("Resolving A and AAAA record for %s server...\n", ns)
		if server = z.getIpAddr(ns, options.Resolv); server == nil {
			dthelper.PrintErr("A and AAAA record not found for %s\n")
			continue
		}
		dthelper.PrintInfo("Trying zone transfer on %s(%)...\n", ns, server)
		lk, err := options.Resolv.Transfer(domain, dns.CLASS_ANY, server, dns.PORT)
		if err == nil && lookup.Msg.Rcode == dns.RCODE_NOERR && len(lookup.Msg.Answers) > 0 {
			dthelper.PrintOk("Zone transfer was successful on server %s(%s)\n\n", ns, server)
			resolver.PrintLookup(lk)
			return nil
		}
	}

	return fmt.Errorf("zone transfer failed")
}

func (z *ztransfer) getIpAddr(domain string, resolv *resolver.Resolver) net.IP {
	var lookup *resolver.Response = nil
	var err error = nil

	for _, tp := range []uint16{dns.TYPE_A, dns.TYPE_AAAA} {
		if lookup, err = resolv.ResolveDomain(domain, tp, dns.CLASS_IN); err == nil {
			if len(lookup.Msg.Answers) > 0 {
				if addr := resolver.Rr2Addr(lookup.Msg.Answers[0]); addr != nil {
					return addr
				}
			}
		}
	}
	return nil
}
