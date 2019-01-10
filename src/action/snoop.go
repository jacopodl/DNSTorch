package action

import (
	"dns"
	"dthelper"
	"fmt"
	"resolver"
	"time"
)

type snoop struct{}

func NewSnoop() *snoop {
	return &snoop{}
}

func (s *snoop) Name() string {
	return "snoop"
}

func (s *snoop) Description() string {
	return "Perform a DNS cache snooping"
}

func (s *snoop) Exec(domain string, options *ActOpts) error {
	total := 0
	count := 0

	dthelper.PrintInfo("Performing cache snooping...\n")

	if options.Dict == nil {
		if domain == "" {
			return fmt.Errorf("empty domain name")
		}
		total = 1
		if s.snoopAndPrint(domain, options) {
			count++
		}
	} else {
		for dname := range options.Dict.Data {
			total++
			if s.snoopAndPrint(dname, options) {
				count++
			}
			if options.Delay > 0 {
				time.Sleep(options.Delay)
			}
		}
		if total == 0 {
			return fmt.Errorf("empty domains list")
		}
	}
	fmt.Println()
	dthelper.PrintOk("%d/%d found!\n", count, total)
	return nil
}

func (s *snoop) inCacheRD(domain string, options *ActOpts) (bool, *resolver.DtLookup, error) {
	query, err := dns.NewQuery(domain, options.Type, options.Class)
	if err != nil {
		return false, nil, err
	}
	lookup, err := options.Resolv.Resolve(query, false)
	if err != nil {
		return false, nil, err
	}
	return lookup.Msg.Rcode == dns.RCODE_NOERR && len(lookup.Msg.Answers) > 0, lookup, nil
}

func (s *snoop) snoopAndPrint(name string, options *ActOpts) bool {
	cached, lookup, err := s.inCacheRD(name, options)
	if err != nil {
		dthelper.PrintErr("%s: %s\n", name, err)
		return false
	}
	s.printResult(cached, lookup)
	return cached
}

func (s *snoop) printResult(cached bool, lookup *resolver.DtLookup) {
	if cached {
		fmt.Printf("\n-- %s\n", lookup.Query.Query.Name)
		resolver.PrintRRs(lookup.Msg.Answers, "")
	}
	if lookup.Msg.Rcode != dns.RCODE_NOERR {
		fmt.Printf("\n-- %s: %s\n", lookup.Query.Query.Name, dns.Rcode2Msg(lookup.Msg.Rcode))
	}
}
