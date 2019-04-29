package action

import (
	"dns"
	"dns/resolver"
	"dthelper"
	"fmt"
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
	return "Perform subdomain enumeration"
}

func (e *enum) Exec(domain string, options *ActOpts) error {
	if domain == "" {
		return fmt.Errorf(errMissingDN)
	}

	if options.Dict == nil {
		return fmt.Errorf(errReqDict)
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
	var response *resolver.Response = nil
	var err error = nil

	domain := params[0].(string)
	opts := params[1].(*ActOpts)

	if prefix, ok := <-opts.Dict.Data; ok {
		if response, err = opts.Resolv.ResolveDomain(dns.ConcatLabel(prefix, domain), opts.Type, opts.Class); err == nil {
			return dthelper.BgResult{Data: response}, false
		}
		return dthelper.BgResult{Data: err, IsError: true}, false
	}
	return nil, true
}

func (e *enum) printResult(data interface{}) {
	result := data.(dthelper.BgResult)
	e.total++
	if !result.IsError {
		lookup := result.Data.(*resolver.Response)
		if lookup.Msg.Rcode == dns.RCODE_NOERR && len(lookup.Msg.Answers) > 0 {
			resolver.PrintRRs(lookup.Msg.Answers, resolver.AnswerId)
			e.found++
		}
		return
	}
	dthelper.PrintErr("%s\n", result.Data.(error).Error())
}
