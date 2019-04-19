package resolver

import (
	"dns"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

const (
	maxFailure   = 5
	maxQueueSize = 3
)

type nsEntry struct {
	server  net.IP
	port    int
	failure int
}

type traceContext struct {
	in  []*dns.Query
	out []*dns.ResourceRecord

	iCond *sync.Cond
	oCond *sync.Cond

	wg   sync.WaitGroup
	stop bool
}

type Resolver struct {
	servers []*nsEntry
	srvLck  sync.Mutex

	tcp            bool
	Ignore         bool
	Flags          Flags
	Timeout        time.Duration
	MaxDelegations int
}

func NewResolver(server net.IP, port int, tcp bool) *Resolver {
	res := &Resolver{tcp: tcp, Timeout: 3000, MaxDelegations: 24}
	res.AddNS(server, port)
	return res
}

func (r *Resolver) AddNS(server net.IP, port int) {
	r.srvLck.Lock()
	defer r.srvLck.Unlock()

	r.servers = append(r.servers, &nsEntry{server, port, 0})
}

func (r *Resolver) askTo(query *Query, server net.IP, port int, tcp bool) (*Response, error) {
	sock, err := newDSock(server, port, tcp, r.Timeout)
	if err != nil {
		return nil, err
	}
	defer sock.close()
	return r.askToSock(query, sock)
}

func (r *Resolver) askToSock(query *Query, socket *dSocket) (*Response, error) {
	var lookup *Response = nil
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

func (r *Resolver) GetDomainAddrs(domain string, class uint16, ip4only bool) ([]net.IP, error) {
	var lookup *Response = nil
	var err error = nil
	var addrs []net.IP = nil

	// get A
	if lookup, err = r.ResolveDomain(domain, dns.TYPE_A, class); err == nil {
		if lookup.Msg.Rcode == dns.RCODE_NOERR {
			for i := range lookup.Msg.Answers {
				if addr := rr2addr(lookup.Msg.Answers[i]); addr != nil {
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
					if addr := rr2addr(lookup.Msg.Answers[i]); addr != nil {
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

func (r *Resolver) getNextSrv(tc *traceContext) *dns.ResourceRecord {
	tc.oCond.L.Lock()
	defer tc.oCond.L.Unlock()

	if len(tc.out) == 0 {
		if len(tc.in) == 0 {
			return nil
		}
		tc.iCond.Broadcast()
		tc.oCond.Wait()
	}

	srv := tc.out[0]
	tc.out = tc.out[1:] // remove srv from queue
	return srv
}

func (r *Resolver) GetRootNS() (*Response, error) {
	return r.Resolve(&dns.Query{Name: ".", Type: dns.TYPE_NS, Class: dns.CLASS_IN}, true)
}

func (r *Resolver) GetSoaAddr(domain string, class uint16) (net.IP, error) {
	var addrs []net.IP

	lookup, err := r.ResolveDomain(domain, dns.TYPE_SOA, class)
	if err == nil {
		if lookup.Msg.Rcode != dns.RCODE_NOERR {
			err = fmt.Errorf(dns.Rcode2Msg(lookup.Msg.Rcode))
		} else {
			soa := lookup.Msg.Answers[0].Rdata.(*dns.SOA).Mname
			if addrs, err = r.GetDomainAddrs(soa, class, false); err == nil {
				return addrs[0], nil
			}
		}
	}

	return nil, err
}

func (r *Resolver) traceWk(tc *traceContext) {
	defer tc.wg.Done()

	for !tc.stop {
		tc.iCond.L.Lock()
		for len(tc.in) == 0 {
			if tc.stop {
				tc.iCond.L.Unlock()
				return
			}
			tc.iCond.Wait()
		}
		tc.oCond.L.Lock()
		if len(tc.out) > maxQueueSize || tc.stop {
			tc.oCond.L.Unlock()
			tc.iCond.L.Unlock()
			continue
		}

		if lookup, err := r.Resolve(tc.in[0], true); err == nil {
			if lookup.Msg.Rcode == dns.RCODE_NOERR && len(lookup.Msg.Answers) > 0 {
				tc.out = append(tc.out, lookup.Msg.Answers[0])
			}
		}

		tc.in = tc.in[1:]

		tc.iCond.L.Unlock()
		tc.oCond.L.Unlock()
		tc.oCond.Signal()
	}
}

func (r *Resolver) pickNS() *nsEntry {
	var ns *nsEntry = nil
	var idx = 0

	rand.Seed(time.Now().Unix())
	r.srvLck.Lock()
	defer r.srvLck.Unlock()

	for ns == nil && len(r.servers) > 0 {
		idx = rand.Intn(len(r.servers))
		ns = r.servers[idx]
		if ns.failure >= maxFailure {
			r.servers = append(r.servers[:idx], r.servers[idx+1:]...)
			ns = nil
		}
	}

	return ns
}

func (r *Resolver) processReferral(tc *traceContext, msg *dns.Dns, useAuth bool) {
	var referrals = msg.Answers

	tc.iCond.L.Lock()
	defer tc.iCond.L.Unlock()

	tc.oCond.L.Lock()
	defer tc.oCond.L.Unlock()

	// cleanup
	tc.in = tc.in[:0]
	tc.out = tc.out[:0]

	if useAuth {
		referrals = msg.Authority
	}

	for idx := range referrals {
		if rrs, ok := parseAdditional(referrals[idx], msg.Additional); ok {
			if rrs != nil {
				tc.out = append(tc.out, rrs...)
				continue
			}
			if referrals[idx].Qtype == dns.TYPE_NS {
				tc.in = append(tc.in, &dns.Query{Name: referrals[idx].Rdata.(*dns.NS).NSdname, Type: dns.TYPE_A, Class: dns.CLASS_IN})
				tc.in = append(tc.in, &dns.Query{Name: referrals[idx].Rdata.(*dns.NS).NSdname, Type: dns.TYPE_AAAA, Class: dns.CLASS_IN})
			}
		}
	}
}

func (r *Resolver) Resolve(query *dns.Query, rd bool) (*Response, error) {
	return r.ResolveWith(query, rd, r.tcp, nil, 0)
}

func (r *Resolver) ResolveDomain(domain string, qtype, class uint16) (*Response, error) {
	var query *dns.Query = nil
	var err error = nil

	if query, err = dns.NewQuery(domain, qtype, class); err != nil {
		return nil, err
	}

	return r.Resolve(query, true)
}

func (r *Resolver) ResolveDomainWith(domain string, qtype, class uint16, server net.IP, port int) (*Response, error) {
	var query *dns.Query = nil
	var err error = nil

	if query, err = dns.NewQuery(domain, qtype, class); err != nil {
		return nil, err
	}

	return r.ResolveWith(query, true, r.tcp, server, port)
}

func (r *Resolver) ResolveWith(query *dns.Query, rd, tcp bool, server net.IP, port int) (*Response, error) {
	var dtQ = &Query{Query: *query}

	dtQ.AA = r.Flags.AA
	dtQ.RD = rd
	dtQ.AD = r.Flags.AD
	dtQ.CD = r.Flags.CD

	if server == nil {
		for {
			if ns := r.pickNS(); ns == nil {
				return nil, fmt.Errorf("no DNS servers available")
			} else {
				rsp, err := r.askTo(dtQ, ns.server, ns.port, tcp)
				if err != nil {
					ns.failure++
					continue
				}
				return rsp, err
			}
		}
	}

	return r.askTo(dtQ, server, port, tcp)
}

func (r *Resolver) Trace(query *dns.Query) (*Response, error) {
	var dtQ = Query{Query: *query}
	var tc = traceContext{
		iCond: sync.NewCond(&sync.Mutex{}),
		oCond: sync.NewCond(&sync.Mutex{})}

	tc.wg.Add(1)
	go r.traceWk(&tc)

	response, err := r.trace(&tc, &dtQ)

	tc.stop = true
	tc.iCond.Broadcast()
	tc.wg.Wait()

	return response, err
}

func (r *Resolver) TraceDomain(domain string, qtype, class uint16) (*Response, error) {
	var query *dns.Query = nil
	var err error = nil

	if query, err = dns.NewQuery(domain, qtype, class); err != nil {
		return nil, err
	}

	return r.Trace(query)
}

func (r *Resolver) trace(tc *traceContext, query *Query) (*Response, error) {
	var nsChain []*dns.ResourceRecord = nil
	var srv *dns.ResourceRecord = nil
	var lookup *Response = nil
	var err error = nil
	var delegations = 0

	if lookup, err = r.GetRootNS(); err != nil {
		return nil, err
	}

	r.processReferral(tc, lookup.Msg, false)

	for delegations < r.MaxDelegations {
		if srv = r.getNextSrv(tc); err != nil {
			return nil, fmt.Errorf("no response from the DNS servers")
		}
		if lookup, err = r.askTo(query, rr2addr(srv), dns.PORT, r.tcp); err != nil {
			continue
		}

		// Add NS
		nsChain = append(nsChain, srv)

		// process response
		if lookup.Msg.Rcode != dns.RCODE_NOERR {
			return nil, fmt.Errorf(dns.Rcode2Msg(lookup.Msg.Rcode))
		}

		if len(lookup.Msg.Answers) != 0 && lookup.Msg.Authoritative {
			lookup.NsChain = nsChain
			return lookup, nil
		}

		// process referrals
		r.processReferral(tc, lookup.Msg, true)
		delegations++
	}
	return nil, fmt.Errorf("max level of delegation(%d) reached", r.MaxDelegations)
}

func parseAdditional(rr *dns.ResourceRecord, addSection []*dns.ResourceRecord) ([]*dns.ResourceRecord, bool) {
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

	for i := range addSection {
		if addSection[i].Name == name {
			rrs = append(rrs, addSection[i])
		}
	}

	return rrs, true
}

func rr2addr(record *dns.ResourceRecord) net.IP {
	switch {
	case record.Qtype == dns.TYPE_A:
		return record.Rdata.(*dns.A).Address
	case record.Qtype == dns.TYPE_AAAA:
		return record.Rdata.(*dns.AAAA).Address
	}
	return nil
}
