package resolver

import (
	"dns"
	"encoding/binary"
	"net"
	"time"
)

type dSocket struct {
	server   net.IP
	port     int
	tcp      bool
	compress bool
	conn     net.Conn
	timeout  time.Duration
}

func newDSock(server net.IP, port int, tcp bool, timeout time.Duration) (*dSocket, error) {
	conn, err := openConn(server, port, tcp)
	if err != nil {
		return nil, err
	}
	return &dSocket{server, port, tcp, true, conn, timeout * time.Millisecond}, nil
}

func (d *dSocket) ask(query *Query) (*Response, error) {
	var lookup = &Response{Query: query}
	var dPkt = &dns.Dns{}
	var buf []byte = nil

	dPkt.Identification = query.Id

	dPkt.Authoritative = query.AA
	dPkt.RecursionDesired = query.RD
	dPkt.AuthenticatedData = query.AD
	dPkt.CheckingDisabled = query.CD
	dPkt.AddQuestion(&query.Query)

	buf = d.prepareBuf(dPkt, d.tcp)

	if _, err := d.conn.Write(buf); err != nil {
		return nil, err
	}

	if !d.tcp {
		return d.recvUDP(lookup)
	}
	return d.recvTCP(lookup)
}

func (d *dSocket) close() {
	_ = d.conn.Close()
}

func (d *dSocket) prepareBuf(dPkt *dns.Dns, tcp bool) []byte {
	buf := dPkt.ToBytes(d.compress)
	if tcp {
		preamble := []byte{0x00, 0x00}
		binary.BigEndian.PutUint16(preamble, uint16(len(buf)))
		buf = append(preamble, buf...)
	}
	return buf
}

func (d *dSocket) recvUDP(response *Response) (*Response, error) {
	var length = 0
	var buf = make([]byte, dns.MAXLEN)
	var err error = nil

	if d.timeout != 0 {
		if err := d.conn.SetReadDeadline(time.Now().Add(d.timeout)); err != nil {
			return nil, err
		}
	}

	if length, err = d.conn.Read(buf); err != nil {
		return nil, err
	}

	response.Msg = dns.FromBytes(buf[:length])
	return response, nil
}

func (d *dSocket) recvTCP(lookup *Response) (*Response, error) {
	var buf = []byte{0x00, 0x00}
	var length = 0
	var currLen = 0
	var preamble = -1
	var err error = nil

	for currLen != preamble {
		if length, err = d.conn.Read(buf[currLen:]); err != nil {
			return nil, err
		}
		if preamble < 0 {
			preamble = int(binary.BigEndian.Uint16(buf))
			buf = make([]byte, preamble)
			continue
		}
		currLen += length
	}
	lookup.Msg = dns.FromBytes(buf[:preamble])
	return lookup, nil
}

func (d *dSocket) setCompression(enable bool) {
	d.compress = enable
}

func (d *dSocket) switchProto() (*dSocket, error) {
	ds, err := newDSock(d.server, d.port, !d.tcp, d.timeout)
	if err == nil && !d.compress {
		ds.setCompression(false)
	}
	return ds, err
}

func openConn(server net.IP, port int, tcp bool) (net.Conn, error) {
	if tcp {
		return net.DialTCP("tcp", nil, &net.TCPAddr{IP: server, Port: port})
	}
	return net.DialUDP("udp", nil, &net.UDPAddr{IP: server, Port: port})
}
