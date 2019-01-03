package action

import (
	"dns"
	"dthelper"
	"fmt"
	"resolver"
	"time"
)

type snoop struct {
	*Options
	dict *dthelper.FDict
}

func NewSnoop() Action {
	return &snoop{}
}

func (s *snoop) Name() string {
	return "snoop"
}

func (s *snoop) Description() string {
	return "Perform a DNS cache snooping"
}

func (s *snoop) Init(soptions string, options *Options) (Action, error) {
	snp := &snoop{Options: options}
	var err error = nil

	if options.Dict != "" {
		if snp.dict, err = dthelper.NewFDict(options.Dict, dthelper.DEFAULTQLEN); err != nil {
			return nil, err
		}
	}

	return snp, nil
}

func (s *snoop) Exec(domain string) error {
	total := 0
	count := 0

	dthelper.PrintInfo("Performing cache snooping...\n")

	if s.dict == nil {
		if domain == "" {
			return fmt.Errorf("empty domain name")
		}
		total = 1
		if s.snoopAndPrint(domain) {
			count++
		}
	} else {
		for dname := range s.dict.Data {
			total++
			if s.snoopAndPrint(dname) {
				count++
			}
			if s.Delay > 0 {
				time.Sleep(s.Delay)
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

func (s *snoop) inCacheRD(domain string, resolv *resolver.Resolver) (bool, *resolver.DtLookup, error) {
	query, err := dns.NewQuery(domain, s.Type, s.Class)
	if err != nil {
		return false, nil, err
	}
	lookup, err := resolv.Resolve(query, false)
	if err != nil {
		return false, nil, err
	}
	return lookup.Msg.Rcode == dns.RCODE_NOERR && len(lookup.Msg.Answers) > 0, lookup, nil
}

func (s *snoop) snoopAndPrint(name string) bool {
	cached, lookup, err := s.inCacheRD(name, s.Resolv)
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
