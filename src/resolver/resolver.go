package resolver

import (
	"dns"
	"fmt"
	"net"
	"time"
)

type Resolver struct {
	server   net.IP
	port     int
	tcp      bool
	Ignore   bool
	Flags    DtQFlags
	Timeout  time.Duration
	MaxDeleg int
}

func NewResolver(server net.IP, port int, tcp bool) *Resolver {
	return &Resolver{server: server, port: port, tcp: tcp, Timeout: 3000, MaxDeleg: 24}
}

func (r *Resolver) Resolve(query *dns.Query, rd bool) (*DtLookup, error) {
	return r.ResolveWith(query, rd, r.tcp, r.server, r.port)
}

func (r *Resolver) ResolveDomain(domain string, qtype, class uint16) (*DtLookup, error) {
	var query *dns.Query = nil
	var err error = nil

	if query, err = dns.NewQuery(domain, qtype, class); err != nil {
		return nil, err
	}

	return r.Resolve(query, true)
}

func (r *Resolver) ResolveDomainWith(domain string, qtype, class uint16, server net.IP, port int) (*DtLookup, error) {
	var query *dns.Query = nil
	var err error = nil

	if query, err = dns.NewQuery(domain, qtype, class); err != nil {
		return nil, err
	}

	return r.ResolveWith(query, true, r.tcp, server, port)
}

func (r *Resolver) ResolveWith(query *dns.Query, rd, tcp bool, server net.IP, port int) (*DtLookup, error) {
	var dtQ = &DtQuery{Query: *query}

	dtQ.AAFlag = r.Flags.AAFlag
	dtQ.RDFlag = rd
	dtQ.ADFlag = r.Flags.ADFlag
	dtQ.CDFlag = r.Flags.CDFlag

	if server == nil {
		server = r.server
		port = r.port
	}

	return r.askTo(dtQ, server, port, tcp)
}

func (r *Resolver) Trace(query *dns.Query) (*DtLookup, error) {
	var dtquery = &DtQuery{Query: *query}

	// ask for ROOT
	addrs, err := r.GetRootAddrs()
	if err != nil {
		return nil, err
	}
	return r.iterate(dtquery, addrs)
}

func (r *Resolver) iterate(query *DtQuery, addresses []*dns.ResourceRecord) (*DtLookup, error) {
	var lookup *DtLookup = nil
	var nschain []*dns.ResourceRecord = nil
	var err error = nil
	var deleg = 0
	var ridx = 0

	for deleg < r.MaxDeleg {
		srvAddr, _ := getAddr(addresses[ridx])
		if lookup, err = r.askTo(query, srvAddr, dns.PORT, r.tcp); err != nil {
			ridx++
			if ridx >= len(addresses) {
				return nil, fmt.Errorf("no response from the DNS servers")
			}
			continue
		}

		// Add NS
		nschain = append(nschain, addresses[ridx])

		// process response
		if lookup.Msg.Rcode != dns.RCODE_NOERR {
			return nil, fmt.Errorf(dns.Rcode2Msg(lookup.Msg.Rcode))
		}

		lookup.NsChain = nschain

		if len(lookup.Msg.Answers) != 0 && lookup.Msg.Authoritative {
			return lookup, nil
		}

		// process referrals
		if addresses = r.processReferral(lookup.Msg.Authority, lookup.Msg); len(addresses) == 0 {
			return lookup, fmt.Errorf("no more referral")
		}

		deleg++
		ridx = 0
	}

	return nil, fmt.Errorf("max level of delegation(%d) reached", r.MaxDeleg)
}

func (r *Resolver) processReferral(targets []*dns.ResourceRecord, msg *dns.Dns) []*dns.ResourceRecord {
	var resv []*dns.ResourceRecord = nil
	var toQuery []*dns.ResourceRecord = nil
	qChan := make(chan *dns.Query, 5)
	aChan := make(chan *dns.ResourceRecord, 5)
	doneChan := make(chan bool)
	var maxRoutines = 3

	for i := range targets {
		if rrs, ok := r.getAdditional(targets[i], msg.Additional); ok {
			if rrs != nil {
				resv = append(resv, rrs...)
				continue
			}
			toQuery = append(toQuery, targets[i])
		}
	}

	if toQuery != nil {
		// spawn worker
		for i := 0; i < maxRoutines; i++ {
			go func() {
				for {
					select {
					case query, ok := <-qChan:
						if !ok {
							doneChan <- false
							return
						}
						if lookup, err := r.Resolve(query, true); err == nil {
							if lookup.Msg.Rcode == dns.RCODE_NOERR && len(lookup.Msg.Answers) > 0 {
								aChan <- lookup.Msg.Answers[0]
							}
						} else {
							aChan <- nil
						}
					}
				}
			}()
		}

		// Producer
		go func() {
			for i := range toQuery {
				// IP and IP6
				if toQuery[i].Qtype == dns.TYPE_NS {
					qChan <- &dns.Query{Name: toQuery[i].Rdata.(*dns.NS).NSdname, Type: dns.TYPE_A, Class: dns.CLASS_IN}
					qChan <- &dns.Query{Name: toQuery[i].Rdata.(*dns.NS).NSdname, Type: dns.TYPE_AAAA, Class: dns.CLASS_IN}
				}
			}
			close(qChan)
		}()

		for maxRoutines > 0 {
			select {
			case rr := <-aChan:
				if rr != nil {
					resv = append(resv, rr)
				}
			case <-doneChan:
				maxRoutines--
			}
		}
		close(aChan)
		close(doneChan)
	}

	return resv
}

func (r *Resolver) askTo(query *DtQuery, server net.IP, port int, tcp bool) (*DtLookup, error) {
	sock, err := newDSock(server, port, tcp, r.Timeout)
	if err != nil {
		return nil, err
	}
	defer sock.close()
	return r.askToSock(query, sock)
}

func (r *Resolver) askToSock(query *DtQuery, socket *dSocket) (*DtLookup, error) {
	var lookup *DtLookup = nil
	var err error = nil

	if lookup, err = socket.ask(query); err != nil {
		return nil, err
	}

	if lookup.Msg.Truncated && !r.Ignore {
		if socket, err = socket.switchProto(); err != nil {
			return nil, err
		}
		defer socket.close()
		if lookup, err = socket.ask(query); err != nil {
			return nil, err
		}
	}
	return lookup, nil
}

// Extracts additional ResourceRecord if necessary.
//
// Returns additional RR, true if the input rr required additional section processing, otherwise returns nil, false.
func (r *Resolver) getAdditional(rr *dns.ResourceRecord, additional []*dns.ResourceRecord) ([]*dns.ResourceRecord, bool) {
	var rrs []*dns.ResourceRecord = nil
	var name = ""

	// Parse Rr
	switch rr.Qtype {
	case dns.TYPE_NS:
		name = rr.Rdata.(*dns.NS).NSdname
	case dns.TYPE_MD:
		name = rr.Rdata.(*dns.MD).MDname
	case dns.TYPE_MF:
		name = rr.Rdata.(*dns.MF).MFname
	case dns.TYPE_MB:
		name = rr.Rdata.(*dns.MB).MBname
	case dns.TYPE_MX:
		name = rr.Rdata.(*dns.MX).Exchange
	default:
		return nil, false
	}

	for i := range additional {
		if additional[i].Name == name {
			rrs = append(rrs, additional[i])
		}
	}

	return rrs, true
}

func (r *Resolver) GetDomainAddrs(domain string, class uint16, ip4only bool) ([]net.IP, error) {
	var lookup *DtLookup = nil
	var err error = nil
	var addrs []net.IP = nil

	// get A
	if lookup, err = r.ResolveDomain(domain, dns.TYPE_A, class); err == nil {
		if lookup.Msg.Rcode == dns.RCODE_NOERR {
			for i := range lookup.Msg.Answers {
				if addr, _ := getAddr(lookup.Msg.Answers[i]); addr != nil {
					addrs = append(addrs, addr)
				}
			}
		} else {
			err = fmt.Errorf("type_A: %s", dns.Rcode2Msg(lookup.Msg.Rcode))
		}
	}

	// get AAAA
	if !ip4only {
		if lookup, err = r.ResolveDomain(domain, dns.TYPE_AAAA, class); err == nil {
			if lookup.Msg.Rcode == dns.RCODE_NOERR {
				for i := range lookup.Msg.Answers {
					if addr, _ := getAddr(lookup.Msg.Answers[i]); addr != nil {
						addrs = append(addrs, addr)
					}
				}
			} else {
				err = fmt.Errorf("type_AAAA: %s", dns.Rcode2Msg(lookup.Msg.Rcode))
			}
		}
	}

	if addrs == nil {
		err = fmt.Errorf("no addresses found")
	} else {
		err = nil
	}

	return addrs, err
}

func (r *Resolver) GetRootNS() (*DtLookup, error) {
	return r.Resolve(&dns.Query{Name: ".", Type: dns.TYPE_NS, Class: dns.CLASS_IN}, true)
}

func (r *Resolver) GetRootAddrs() ([]*dns.ResourceRecord, error) {
	rootlk, err := r.GetRootNS()
	if err != nil {
		return nil, fmt.Errorf("unable to obtain ROOT name servers(%s)", err.Error())
	}
	// process answers and extracts root addresses
	addrs := r.processReferral(rootlk.Msg.Answers, rootlk.Msg)
	if addrs == nil {
		return nil, fmt.Errorf("unable to resolve root addresses")
	}
	return addrs, nil
}

func getAddr(record *dns.ResourceRecord) (net.IP, error) {
	switch {
	case record.Qtype == dns.TYPE_A:
		return record.Rdata.(*dns.A).Address, nil
	case record.Qtype == dns.TYPE_AAAA:
		return record.Rdata.(*dns.AAAA).Address, nil
	}
	return nil, fmt.Errorf("invalid ResourceRecord of type: %d", record.Qtype)
}
