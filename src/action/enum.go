package action

import (
	"dns"
	"dthelper"
	"fmt"
	"resolver"
	"sync"
	"time"
)

type enum struct {
	*Options
	dict *dthelper.FDict
	wg   sync.WaitGroup
}

func NewEnum() Action {
	return &enum{}
}

func (e *enum) Name() string {
	return "enum"
}

func (e *enum) Description() string {
	return "Perform brute force subdomain enumeration"
}

func (e *enum) Init(soptions string, options *Options) (Action, error) {
	enm := &enum{Options: options}
	var err error = nil

	if options.Dict == "" {
		return nil, fmt.Errorf("enum requires a dictionary file, use -dict %%filename%%")
	}

	if enm.dict, err = dthelper.NewFDict(options.Dict, dthelper.DEFAULTQLEN); err != nil {
		return nil, err
	}

	return enm, nil
}

func (e *enum) Exec(domain string) error {
	if domain == "" {
		return fmt.Errorf("empty domain name")
	}

	lkchan := make(chan *resolver.DtLookup, 5)
	erchan := make(chan error, 5)
	done := make(chan bool)

	e.wg.Add(1)
	go e.enumWorker(domain, lkchan, erchan)

	go func() {
		lkend := false
		erend := false
		for !lkend || !erend {
			select {
			case lookup, ok := <-lkchan:
				if !ok {
					lkend = true
					break
				}
				e.printResult(lookup)
			case err, ok := <-erchan:
				if !ok {
					erend = true
					break
				}
				dthelper.PrintErr("%s\n", err)
			}
		}
		close(done)
	}()

	e.wg.Wait()
	close(lkchan)
	close(erchan)
	<-done

	return nil
}

func (e *enum) enumWorker(domain string, lkchan chan *resolver.DtLookup, erchan chan error) {
	var query *dns.Query = nil
	var lookup *resolver.DtLookup = nil
	var err error = nil

	defer e.wg.Done()

	for {
		if e.Delay > 0 {
			time.Sleep(e.Delay)
		}
		select {
		case prefix, ok := <-e.dict.Data:
			if !ok {
				return
			}
			if query, err = dns.NewQuery(dns.ConcatLabel(prefix, domain), e.Type, e.Class); err == nil {
				if lookup, err = e.Resolv.Resolve(query, true); err == nil {
					lkchan <- lookup
					continue
				}
			}
			erchan <- err
		}
	}
}

func (e *enum) printResult(lookup *resolver.DtLookup) {
	if lookup.Msg.Rcode == dns.RCODE_NOERR && len(lookup.Msg.Answers) > 0 {
		resolver.PrintRRs(lookup.Msg.Answers, "!")
	}
}
