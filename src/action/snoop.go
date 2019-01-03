package action

import (
	"dns"
	"dthelper"
	"fmt"
	"resolver"
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
		}
		if total == 0 {
			return fmt.Errorf("empty domains list")
		}
	}
	fmt.Println()
	dthelper.PrintOk("%d/%d found!", count, total)
	return nil
}

func (s *snoop) snoopAndPrint(name string) bool {
	lookup, err := s.inCacheRD(name, s.Resolv)
	if err != nil {
		dthelper.PrintErr("%s: %s\n", name, err)
		return false
	}
	s.printResult(lookup)
	return true
}

func (s *snoop) inCacheRD(domain string, resolv *resolver.Resolver) (*resolver.DtLookup, error) {
	query, err := dns.NewQuery(domain, s.Type, s.Class)
	if err != nil {
		return nil, err
	}
	return resolv.Resolve(query, false)
}

func (s *snoop) printResult(lookup *resolver.DtLookup) {
	if lookup.Msg.Rcode == dns.RCODE_NOERR {
		if len(lookup.Msg.Answers) > 0 {
			fmt.Printf("\n-- %s\n", lookup.Query.Query.Name)
			resolver.PrintRRs(lookup.Msg.Answers, "")
		}
		return
	}
	fmt.Printf("%s: %s\n", lookup.Query.Query.Name, dns.Rcode2Msg(lookup.Msg.Rcode))
}
