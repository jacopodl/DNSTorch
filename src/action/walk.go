package action

import (
	"dns"
	"dthelper"
	"fmt"
	"net"
	"resolver"
	"time"
)

type walk struct{}

func NewWalk() *walk {
	return &walk{}
}

func (*walk) Name() string {
	return "walk"
}

func (*walk) Description() string {
	return "Perform DNS NSEC walking"
}

func (w *walk) Exec(domain string, options *ActOpts) error {
	var server net.IP = nil
	var exists = map[string]bool{}
	var lookup *resolver.DtLookup = nil
	var err error = nil
	var found = 0

	dthelper.PrintInfo("Testing %s for zone walking...\n", domain)

	if options.Soa {
		dthelper.PrintInfo("Getting SOA record...\n")
		if server, err = w.getSOA(domain, options.Class, options.Resolv); err != nil {
			dthelper.PrintErr("error while resolving SOA record: %s - reverting to default NS...\n", err)
		}

	}

	for {
		if lookup, err = options.Resolv.ResolveDomainWith(domain, dns.TYPE_NSEC, options.Class, server, dns.PORT); err != nil {
			return err
		}

		if lookup.Msg.Rcode != dns.RCODE_NOERR {
			return fmt.Errorf(dns.Rcode2Msg(lookup.Msg.Rcode))
		}

		if len(lookup.Msg.Answers) == 0 {
			break
		}

		domain = lookup.Msg.Answers[0].Rdata.(*dns.NSEC).NextDN

		if _, ok := exists[domain]; ok {
			break
		}

		exists[domain] = true
		found++

		resolver.PrintRRs(lookup.Msg.Answers, resolver.ANSWER_ID)
		if options.Delay != 0 {
			time.Sleep(options.Delay)
		}
	}

	dthelper.PrintOk("Found %d domains\n", found)
	return nil
}

func (w *walk) getSOA(domain string, class uint16, resolv *resolver.Resolver) (net.IP, error) {
	var addrs []net.IP = nil
	lookup, err := resolv.ResolveDomain(domain, dns.TYPE_SOA, class)
	if err == nil {
		if lookup.Msg.Rcode != dns.RCODE_NOERR {
			err = fmt.Errorf(dns.Rcode2Msg(lookup.Msg.Rcode))
		} else {
			soa := lookup.Msg.Answers[0].Rdata.(*dns.SOA).Mname
			if addrs, err = resolv.GetDomainAddrs(soa, class, false); err == nil {
				return addrs[0], nil
			}
		}
	}

	return nil, err
}
