package dns

import (
	"encoding/binary"
	"net"
)

type A struct {
	Address net.IP
}

func (a *A) packRData(current int, cdct map[string]uint16) []byte {
	return a.toBytes()
}

func (a *A) toBytes() []byte {
	return a.Address.To4()
}

func (a *A) fromBytes(buf []byte, current int, size int) {
	a.Address = net.IP(buf[current : current+4])
}

type NS struct {
	NSdname string
}

func (n *NS) packRData(current int, cdct map[string]uint16) []byte {
	return __packRData(n.NSdname, current, cdct)
}

func (n *NS) toBytes() []byte {
	return __toBytes(n.NSdname)
}

func (n *NS) fromBytes(buf []byte, current int, size int) {
	n.NSdname = Qname2Name(buf, &current)
}

type MD struct {
	MDname string
}

func (m *MD) packRData(current int, cdct map[string]uint16) []byte {
	return __packRData(m.MDname, current, cdct)
}

func (m *MD) toBytes() []byte {
	return __toBytes(m.MDname)
}

func (m *MD) fromBytes(buf []byte, current int, size int) {
	m.MDname = Qname2Name(buf, &current)
}

type MF struct {
	MFname string
}

func (m *MF) packRData(current int, cdct map[string]uint16) []byte {
	return __packRData(m.MFname, current, cdct)
}

func (m *MF) toBytes() []byte {
	return __toBytes(m.MFname)
}

func (m *MF) fromBytes(buf []byte, current int, size int) {
	m.MFname = Qname2Name(buf, &current)
}

type CNAME struct {
	Cname string
}

func (c *CNAME) packRData(current int, cdct map[string]uint16) []byte {
	return __packRData(c.Cname, current, cdct)
}

func (c *CNAME) toBytes() []byte {
	return __toBytes(c.Cname)
}

func (c *CNAME) fromBytes(buf []byte, current int, size int) {
	c.Cname = Qname2Name(buf, &current)
}

type SOA struct {
	Mname   string
	Rname   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
}

func (s *SOA) packRData(current int, cdct map[string]uint16) []byte {
	var buf []byte = nil

	if cnbuf, ok := compressName2Buf([]byte{}, current, s.Mname, cdct); ok {
		buf = append(buf, cnbuf...)
	} else {
		buf = append(buf, Name2Qname(s.Mname)...)
	}

	if cnbuf, ok := compressName2Buf([]byte{}, current+len(buf), s.Rname, cdct); ok {
		buf = append(buf, cnbuf...)
	} else {
		buf = append(buf, Name2Qname(s.Rname)...)
	}

	return append(buf, s.packUint32()...)
}

func (s *SOA) toBytes() []byte {
	buf := Name2Qname(s.Mname)
	buf = append(buf, Name2Qname(s.Rname)...)
	return append(buf, s.packUint32()...)
}

func (s *SOA) packUint32() []byte {
	tmp := make([]byte, 16)
	binary.BigEndian.PutUint32(tmp[:4], s.Serial)
	binary.BigEndian.PutUint32(tmp[4:8], s.Refresh)
	binary.BigEndian.PutUint32(tmp[8:12], s.Retry)
	binary.BigEndian.PutUint32(tmp[12:], s.Expire)
	return tmp
}

func (s *SOA) fromBytes(buf []byte, current int, size int) {
	s.Mname = Qname2Name(buf, &current)
	s.Rname = Qname2Name(buf, &current)
	s.Serial = binary.BigEndian.Uint32(buf[current : current+4])
	s.Refresh = binary.BigEndian.Uint32(buf[current+4 : current+8])
	s.Retry = binary.BigEndian.Uint32(buf[current+8 : current+12])
	s.Expire = binary.BigEndian.Uint32(buf[current+12 : current+16])
}

type MB struct {
	MBname string
}

func (m *MB) packRData(current int, cdct map[string]uint16) []byte {
	return __packRData(m.MBname, current, cdct)
}

func (m *MB) toBytes() []byte {
	return __toBytes(m.MBname)
}

func (m *MB) fromBytes(buf []byte, current int, size int) {
	m.MBname = Qname2Name(buf, &current)
}

type MG struct {
	MGname string
}

func (m *MG) packRData(current int, cdct map[string]uint16) []byte {
	return __packRData(m.MGname, current, cdct)
}

func (m *MG) toBytes() []byte {
	return __toBytes(m.MGname)
}

func (m *MG) fromBytes(buf []byte, current int, size int) {
	m.MGname = Qname2Name(buf, &current)
}

type MR struct {
	Newname string
}

func (m *MR) packRData(current int, cdct map[string]uint16) []byte {
	return __packRData(m.Newname, current, cdct)
}

func (m *MR) toBytes() []byte {
	return __toBytes(m.Newname)
}

func (m *MR) fromBytes(buf []byte, current int, size int) {
	m.Newname = Qname2Name(buf, &current)
}

type NULL struct {
	Rdata []byte
}

func (n *NULL) packRData(current int, cdct map[string]uint16) []byte {
	return n.toBytes()
}

func (n *NULL) toBytes() []byte {
	return n.Rdata
}

func (n *NULL) fromBytes(buf []byte, current int, size int) {
	n.Rdata = append(n.Rdata, buf[current:current+size]...)
}

type PTR struct {
	Ptr string
}

func (p *PTR) packRData(current int, cdct map[string]uint16) []byte {
	return __packRData(p.Ptr, current, cdct)
}

func (p *PTR) toBytes() []byte {
	return __toBytes(p.Ptr)
}

func (p *PTR) fromBytes(buf []byte, current int, size int) {
	p.Ptr = Qname2Name(buf, &current)
}

type MINFO struct {
	Rmailbx string
	Emailbx string
}

func (m *MINFO) packRData(current int, cdct map[string]uint16) []byte {
	var buf []byte = nil

	if cnbuf, ok := compressName2Buf([]byte{}, current, m.Rmailbx, cdct); ok {
		buf = append(buf, cnbuf...)
	} else {
		buf = append(buf, Name2Qname(m.Rmailbx)...)
	}

	if cnbuf, ok := compressName2Buf([]byte{}, current+len(buf), m.Emailbx, cdct); ok {
		buf = append(buf, cnbuf...)
	} else {
		buf = append(buf, Name2Qname(m.Emailbx)...)
	}

	return buf
}

func (m *MINFO) toBytes() []byte {
	return append(Name2Qname(m.Rmailbx), Name2Qname(m.Emailbx)...)
}

func (m *MINFO) fromBytes(buf []byte, current int, size int) {
	m.Rmailbx = Qname2Name(buf, &current)
	m.Emailbx = Qname2Name(buf, &current)
}

type MX struct {
	Preference uint16
	Exchange   string
}

func (m *MX) packRData(current int, cdct map[string]uint16) []byte {
	if cnbuf, ok := compressName2Buf([]byte{}, current+2, m.Exchange, cdct); ok {
		tmp := []byte{0x00, 0x00}
		binary.BigEndian.PutUint16(tmp, m.Preference)
		return append(tmp, cnbuf...)
	}
	return m.toBytes()
}

func (m *MX) toBytes() []byte {
	tmp := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(tmp, m.Preference)
	return append(tmp, Name2Qname(m.Exchange)...)
}

func (m *MX) fromBytes(buf []byte, current int, size int) {
	m.Preference = binary.BigEndian.Uint16(buf[current : current+2])
	current += 2
	m.Exchange = Qname2Name(buf, &current)
}

type AAAA struct {
	Address net.IP
}

func (a *AAAA) packRData(current int, cdct map[string]uint16) []byte {
	return a.toBytes()
}

func (a *AAAA) toBytes() []byte {
	return a.Address.To16()
}

func (a *AAAA) fromBytes(buf []byte, current int, size int) {
	a.Address = net.IP(buf[current : current+16])
}

type SRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

func (s *SRV) packRData(current int, cdct map[string]uint16) []byte {
	buf := s.packUint16()
	if cnbuf, ok := compressName2Buf([]byte{}, current+len(buf), s.Target, cdct); ok {
		buf = append(buf, cnbuf...)
	} else {
		buf = append(buf, Name2Qname(s.Target)...)
	}
	return buf
}

func (s *SRV) toBytes() []byte {
	buf := s.packUint16()
	return append(buf, Name2Qname(s.Target)...)
}

func (s *SRV) packUint16() []byte {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[:2], s.Priority)
	binary.BigEndian.PutUint16(buf[2:4], s.Weight)
	binary.BigEndian.PutUint16(buf[4:], s.Port)
	return buf
}

func (s *SRV) fromBytes(buf []byte, current int, size int) {
	s.Priority = binary.BigEndian.Uint16(buf[current : current+2])
	s.Weight = binary.BigEndian.Uint16(buf[current+2 : current+4])
	s.Port = binary.BigEndian.Uint16(buf[current+4 : current+6])
	current += 6
	s.Target = Qname2Name(buf, &current)
}

func __packRData(name string, current int, cdct map[string]uint16) []byte {
	if cnbuf, ok := compressName2Buf([]byte{}, current, name, cdct); ok {
		return cnbuf
	}
	return __toBytes(name)
}

func __toBytes(name string) []byte {
	return Name2Qname(name)
}
