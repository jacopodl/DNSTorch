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
	dnchan := make(chan string, 5)
	done := make(chan bool)
	count := 0

	dthelper.PrintInfo("Performing cache snooping...\n")

	go func() {
		for name := range dnchan {
			if lookup, err := s.inCacheRD(name, s.Resolv); err != nil {
				dthelper.PrintErr("%s: %s\n", name, err)
			} else {
				s.printResult(lookup)
			}
			if s.Delay > 0 {
				time.Sleep(s.Delay)
			}
		}
		close(done)
	}()

	if s.dict == nil {
		if domain == "" {
			return fmt.Errorf("empty domain name")
		}
		dnchan <- domain
	} else {
		for dname := range s.dict.Data {
			dnchan <- dname
			count++
		}
		if count == 0 {
			return fmt.Errorf("empty domains list")
		}
	}

	close(dnchan)
	<-done

	return nil
}

func (s *snoop) inCacheRD(domain string, resolv *resolver.Resolver) (*resolver.DtLookup, error) {
	query, err := dns.NewQuery(domain, s.Type, s.Class)
	if err != nil {
		return nil, err
	}
	return resolv.Resolve(query, false)
}

func (s *snoop) printResult(lookup *resolver.DtLookup) {
	fmt.Printf("\n-- %s\n", lookup.Query.Query.Name)
	if lookup.Msg.Rcode == dns.RCODE_NOERR {
		if len(lookup.Msg.Answers) > 0 {
			resolver.PrintRRs(lookup.Msg.Answers, "")
		}
	} else {
		fmt.Printf("%s\n", dns.Rcode2Msg(lookup.Msg.Rcode))
	}
}
