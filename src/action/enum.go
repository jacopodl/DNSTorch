package action

import (
	"dns"
	"dthelper"
	"fmt"
	"resolver"
)

type enum struct {
	found int
	total int
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

func (e *enum) Exec(domain string, options *ActOpts) error {
	if domain == "" {
		return fmt.Errorf("empty domain name")
	}

	if options.Dict == nil {
		return fmt.Errorf("enum requires a dictionary file")
	}

	dthelper.PrintInfo("Performing enumeration on target %s...\n\n", domain)

	w := dthelper.NewWorkers(options.Delay, e.enumWorker, e.printResult)
	w.Spawn(options.Workers, domain, options)
	w.Wait()

	fmt.Println()
	dthelper.PrintOk("%d/%d found!\n", e.found, e.total)

	return nil
}

func (e *enum) enumWorker(params ...interface{}) (interface{}, bool) {
	var query *dns.Query = nil
	var lookup *resolver.DtLookup = nil
	var err error = nil

	domain := params[0].(string)
	opts := params[1].(*ActOpts)

	prefix, ok := <-opts.Dict.Data
	if !ok {
		return nil, true
	}
	if query, err = dns.NewQuery(dns.ConcatLabel(prefix, domain), opts.Type, opts.Class); err == nil {
		if lookup, err = opts.Resolv.Resolve(query, true); err == nil {
			return dthelper.BgResult{Data: lookup}, false
		}
	}
	return dthelper.BgResult{Data: err, IsError: true}, false
}

func (e *enum) printResult(data interface{}) {
	result := data.(dthelper.BgResult)
	e.total++
	if !result.IsError {
		lookup := result.Data.(*resolver.DtLookup)
		if lookup.Msg.Rcode == dns.RCODE_NOERR && len(lookup.Msg.Answers) > 0 {
			resolver.PrintRRs(lookup.Msg.Answers, "!")
			e.found++
		}
		return
	}
	dthelper.PrintErr("%s\n", result.Data.(error).Error())
}
