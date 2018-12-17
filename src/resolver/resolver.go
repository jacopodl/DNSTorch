package resolver

import (
	"dns"
	"fmt"
	"net"
	"time"
)

type resolver struct {
	server   net.IP
	port     int
	tcp      bool
	ignore   bool
	flags    DtQFlags
	timeout  time.Duration
	maxDeleg int
}

func NewResolver(server net.IP, port int, tcp bool) *resolver {
	return &resolver{server: server, port: port, tcp: tcp, timeout: 3000, maxDeleg: 24}
}

func (r *resolver) Resolve(query *dns.Query) (*DtLookup, error) {
	var dtquery = &DtQuery{Query: *query}

	dtquery.AAFlag = r.flags.AAFlag
	dtquery.RDFlag = r.flags.RDFlag
	dtquery.ADFlag = r.flags.ADFlag
	dtquery.CDFlag = r.flags.CDFlag

	return r.ask(dtquery)
}

func (r *resolver) Trace(query *dns.Query) (*DtLookup, error) {
	var dtquery = &DtQuery{Query: *query}
	var addrs []*dns.ResourceRecord = nil

	// ask for ROOT
	if rootlk, err := r.GetRootNS(); err != nil {
		return nil, fmt.Errorf("unable to obtain ROOT name servers(%s)", err.Error())
	} else {
		// process answers and extracts root addresses
		addrs = r.processReferral(rootlk.Msg.Answers, rootlk.Msg)
		if addrs == nil {
			return nil, fmt.Errorf("unable to resolve root addresses")
		}
	}

	return r.iterate(dtquery, addrs)
}

func (r *resolver) iterate(query *DtQuery, addresses []*dns.ResourceRecord) (*DtLookup, error) {
	var lookup *DtLookup = nil
	var nschain []*dns.ResourceRecord = nil
	var err error = nil
	var deleg = 0
	var ridx = 0

	for deleg < r.maxDeleg {
		srvAddr, _ := getAddr(addresses[ridx])
		if lookup, err = r.askTo(query, srvAddr, dns.PORT); err != nil {
			if ridx >= len(addresses) {
				return nil, fmt.Errorf("unable ...") // TODO error msg
			}
			ridx++
			continue
		}

		// Add NS
		nschain = append(nschain, addresses[ridx])

		// process response
		if lookup.Msg.Rcode != dns.RCODE_NOERR {
			return nil, fmt.Errorf(dns.Rcode2Msg(lookup.Msg.Rcode))
		}

		if len(lookup.Msg.Answers) != 0 && lookup.Msg.Authoritative {
			lookup.NsChain = nschain
			return lookup, nil
		}

		// process referrals
		if addresses = r.processReferral(lookup.Msg.Authority, lookup.Msg); len(addresses) == 0 {
			return nil, fmt.Errorf("no referral, error")
		}

		deleg++
		ridx = 0
	}

	return nil, fmt.Errorf("max level of delegation(%d) reached", r.maxDeleg)
}

func (r *resolver) processReferral(targets []*dns.ResourceRecord, msg *dns.Dns) []*dns.ResourceRecord {
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
						if lookup, err := r.Resolve(query); err == nil {
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
				qChan <- &dns.Query{Name: toQuery[i].Rdata.(*dns.NS).NSdname, Type: dns.TYPE_A, Class: dns.CLASS_IN}
				qChan <- &dns.Query{Name: toQuery[i].Rdata.(*dns.NS).NSdname, Type: dns.TYPE_AAAA, Class: dns.CLASS_IN}
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

func (r *resolver) ask(query *DtQuery) (*DtLookup, error) {
	return r.askTo(query, r.server, r.port)
}

func (r *resolver) askTo(query *DtQuery, server net.IP, port int) (*DtLookup, error) {
	sock, err := newDSock(server, port, r.tcp, r.timeout)
	if err != nil {
		return nil, err
	}
	defer sock.close()
	return r.askToSock(query, sock)
}

func (r *resolver) askToSock(query *DtQuery, socket *dSocket) (*DtLookup, error) {
	var lookup *DtLookup = nil
	var err error = nil

	if lookup, err = socket.ask(query); err != nil {
		return nil, err
	}

	if lookup.Msg.Truncated && !r.ignore {
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
func (r *resolver) getAdditional(rr *dns.ResourceRecord, additional []*dns.ResourceRecord) ([]*dns.ResourceRecord, bool) {
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

func (r *resolver) GetRootNS() (*DtLookup, error) {
	return r.Resolve(&dns.Query{Name: ".", Type: dns.TYPE_NS, Class: dns.CLASS_IN})
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
