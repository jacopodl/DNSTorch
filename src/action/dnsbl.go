package action

import (
	"dns"
	"dthelper"
	"fmt"
	"net"
	"resolver"
)

type dnsbl struct {
	total int
	found int
}

type blResult struct {
	target string
	blkns  string
	found  bool
	info   string
	err    error
}

func NewDnsBL() *dnsbl {
	return &dnsbl{}
}

func (*dnsbl) Name() string {
	return "dnsbl"
}

func (*dnsbl) Description() string {
	return "Search into multiple DNS-based blackhole list"
}

func (d *dnsbl) Exec(domain string, options *ActOpts) error {
	target := net.ParseIP(domain)
	if target == nil {
		return fmt.Errorf("dnsbl required a valid, public, IP address")
	}

	if options.Dict == nil {
		return fmt.Errorf("dnsbl requires a dictionary file")
	}

	w := dthelper.NewWorkers(options.Delay, d.worker, d.printResult)
	w.Spawn(options.Workers, target, options)
	w.Wait()

	fmt.Println()
	dthelper.PrintOk("%d/%d found!\n", d.found, d.total)
	return nil
}

func (d *dnsbl) worker(params ...interface{}) (interface{}, bool) {
	var query *dns.Query = nil
	var lookup *resolver.DtLookup = nil
	var qtype = uint16(dns.TYPE_A)
	var target = ""
	var err error = nil

	tip := params[0].(net.IP)
	opts := params[1].(*ActOpts)

	bl, ok := <-opts.Dict.Data
	if !ok {
		return nil, true
	}

	if tip.To4() != nil {
		target = dns.IP2Label(tip, "")
	} else {
		target = dns.IP62Label(tip, "")
		qtype = dns.TYPE_AAAA
	}

	ret := &blResult{target: tip.String(), blkns: bl}
	if query, err = dns.NewQuery(dns.ConcatLabel(target, bl), qtype, opts.Class); err == nil {
		if lookup, err = opts.Resolv.Resolve(query, true); err == nil {
			if lookup.Msg.Rcode == dns.RCODE_NOERR {
				ret.found = true
				query, _ = dns.NewQuery(dns.ConcatLabel(target, bl), dns.TYPE_TXT, opts.Class)
				txtlck, err := opts.Resolv.Resolve(query, true)
				if err == nil && txtlck.Msg.Rcode == dns.RCODE_NOERR && len(txtlck.Msg.Answers) > 0 {
					ret.info = txtlck.Msg.Answers[0].Rdata.(*dns.TXT).Txt
				}
			}
		}
	}
	ret.err = err
	return ret, false
}

func (d *dnsbl) printResult(data interface{}) {
	result := data.(*blResult)
	d.total++
	if result.err == nil {
		if result.found {
			dthelper.PrintOk("Found %s into: %s with info:\n\t%s\n", result.target, result.blkns, result.info)
			d.found++
		}
		return
	}
	dthelper.PrintErr("%s error: %s\n", result.blkns, result.err.Error())
}
