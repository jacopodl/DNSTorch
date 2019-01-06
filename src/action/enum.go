package action

import (
	"dns"
	"dthelper"
	"fmt"
	"resolver"
)

type enum struct {
	*Options
	dict *dthelper.FDict
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

	w := dthelper.NewWorkers(e.Delay, e.enumWorker, e.printResult)
	w.Spawn(e.Workers, domain)
	w.Wait()

	return nil
}

func (e *enum) enumWorker(params ...interface{}) (interface{}, bool) {
	var query *dns.Query = nil
	var lookup *resolver.DtLookup = nil
	var err error = nil

	prefix, ok := <-e.dict.Data
	if !ok {
		return nil, true
	}
	if query, err = dns.NewQuery(dns.ConcatLabel(prefix, params[0].(string)), e.Type, e.Class); err == nil {
		if lookup, err = e.Resolv.Resolve(query, true); err == nil {
			return dthelper.BgResult{Data: lookup}, false
		}
	}
	return dthelper.BgResult{Data: err, IsError: true}, false
}

func (e *enum) printResult(data interface{}) {
	result := data.(dthelper.BgResult)
	if !result.IsError {
		lookup := result.Data.(*resolver.DtLookup)
		if lookup.Msg.Rcode == dns.RCODE_NOERR && len(lookup.Msg.Answers) > 0 {
			resolver.PrintRRs(lookup.Msg.Answers, "!")
		}
		return
	}
	dthelper.PrintErr("%s\n", result.Data.(error).Error())
}
