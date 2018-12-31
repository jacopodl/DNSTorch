package resolver

import (
	"dns"
	"encoding/binary"
	"net"
	"time"
)

// TODO: how do I get UDP/TCP packet timestamp in Go?
// There is a way? :(

type dSocket struct {
	server  net.IP
	port    int
	tcp     bool
	conn    net.Conn
	timeout time.Duration
}

func newDSock(server net.IP, port int, tcp bool, timeout time.Duration) (*dSocket, error) {
	conn, err := openConn(server, port, tcp)
	if err != nil {
		return nil, err
	}
	return &dSocket{server, port, tcp, conn, timeout * time.Millisecond}, nil
}

func (d *dSocket) ask(query *DtQuery) (*DtLookup, error) {
	var lookup = &DtLookup{Query: query}
	var dPkt = &dns.Dns{}
	var buf []byte = nil
	var err error = nil

	dPkt.Authoritative = query.AAFlag
	dPkt.RecursionDesired = query.RDFlag
	dPkt.AuthenticatedData = query.ADFlag
	dPkt.CheckingDisabled = query.CDFlag
	dPkt.AddQuestion(&query.Query)

	buf = prepareBuf(dPkt, d.tcp)

	if _, err := d.conn.Write(buf); err != nil {
		return nil, err
	}

	if !d.tcp {
		err = d.recvUDP(lookup)
	} else {
		err = d.recvTCP(lookup)
	}

	if err != nil {
		return nil, err
	}

	return lookup, nil
}

func (d *dSocket) close() {
	d.conn.Close()
}

func (d *dSocket) recvUDP(lookup *DtLookup) error {
	buf := make([]byte, dns.MAXLEN)

	if d.timeout != 0 {
		d.conn.SetReadDeadline(time.Now().Add(d.timeout))
	}

	if length, err := d.conn.Read(buf); err != nil {
		return err
	} else {
		lookup.Msg = dns.FromBytes(buf[:length])
		return nil
	}
}

func (d *dSocket) recvTCP(lookup *DtLookup) error {
	buf := []byte{0x00, 0x00}
	clen := 0
	tlen := -1

	for clen != tlen {
		if length, err := d.conn.Read(buf[clen:]); err != nil {
			return err
		} else {
			if tlen < 0 {
				tlen = int(binary.BigEndian.Uint16(buf))
				buf = make([]byte, tlen)
				continue
			}
			clen += length
		}
	}
	lookup.Msg = dns.FromBytes(buf[:tlen])
	return nil
}

func (d *dSocket) switchProto() (*dSocket, error) {
	return newDSock(d.server, d.port, !d.tcp, d.timeout)
}

func openConn(server net.IP, port int, tcp bool) (net.Conn, error) {
	if tcp {
		return net.DialTCP("tcp", nil, &net.TCPAddr{IP: server, Port: port})
	}
	return net.DialUDP("udp", nil, &net.UDPAddr{IP: server, Port: port})
}

func prepareBuf(dPkt *dns.Dns, tcp bool) []byte {
	buf := dPkt.ToBytes(true)
	if tcp {
		preamble := []byte{0x00, 0x00}
		binary.BigEndian.PutUint16(preamble, uint16(len(buf)))
		buf = append(preamble, buf...)
	}
	return buf
}
