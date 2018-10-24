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
	return Name2Qname(n.NSdname)
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
	return Name2Qname(m.MDname)
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
	return Name2Qname(m.MFname)
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
	return Name2Qname(c.Cname)
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
	buf = append(buf, __packRData(s.Mname, current, cdct)...)
	buf = append(buf, __packRData(s.Rname, current+len(buf), cdct)...)
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
	return Name2Qname(m.MBname)
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
	return Name2Qname(m.MGname)
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
	return Name2Qname(m.Newname)
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

type WKS struct {
	Address  net.IP
	Protocol byte
	Bitmap   []byte
}

func (w *WKS) packRData(current int, cdct map[string]uint16) []byte {
	return w.toBytes()
}

func (w *WKS) toBytes() []byte {
	buf := make([]byte, 4+1)
	copy(buf[:4], w.Address.To4())
	buf[4] = w.Protocol
	return append(buf, w.Bitmap...)
}

func (w *WKS) fromBytes(buf []byte, current int, size int) {
	w.Address = net.IP(buf[current : current+4])
	w.Protocol = buf[current+4]
	w.Bitmap = buf[current+5 : (current+5)+(size-5)]
}

type PTR struct {
	Ptr string
}

func (p *PTR) packRData(current int, cdct map[string]uint16) []byte {
	return __packRData(p.Ptr, current, cdct)
}

func (p *PTR) toBytes() []byte {
	return Name2Qname(p.Ptr)
}

func (p *PTR) fromBytes(buf []byte, current int, size int) {
	p.Ptr = Qname2Name(buf, &current)
}

type HINFO struct {
	Cpu string
	Os  string
}

func (h *HINFO) packRData(current int, cdct map[string]uint16) []byte {
	return h.toBytes()
}

func (h *HINFO) toBytes() []byte {
	return append(text2bytes(h.Cpu), text2bytes(h.Os)...)
}

func (h *HINFO) fromBytes(buf []byte, current int, size int) {
	h.Cpu = bytes2text(buf, &current)
	h.Os = bytes2text(buf, &current)
}

type MINFO struct {
	Rmailbx string
	Emailbx string
}

func (m *MINFO) packRData(current int, cdct map[string]uint16) []byte {
	buf := __packRData(m.Rmailbx, current, cdct)
	return append(buf, __packRData(m.Emailbx, current+len(buf), cdct)...)
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
	if cnbuf, ok := dnCompressor([]byte{}, current+2, m.Exchange, cdct); ok {
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

type TXT struct {
	Txt string
}

func (t *TXT) packRData(current int, cdct map[string]uint16) []byte {
	return t.toBytes()
}

func (t *TXT) toBytes() []byte {
	return text2bytes(t.Txt)
}

func (t *TXT) fromBytes(buf []byte, current int, size int) {
	t.Txt = bytes2text(buf, &current)
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
	return append(buf, __packRData(s.Target, current+len(buf), cdct)...)
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

type NAPTR struct {
	Order       uint16
	Preference  uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement string
}

func (n *NAPTR) packUint16() []byte {
	buf := []byte{0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(buf[:2], n.Order)
	binary.BigEndian.PutUint16(buf[2:], n.Preference)
	return buf
}

func (n *NAPTR) packRData(current int, cdct map[string]uint16) []byte {
	buf := n.packUint16()
	buf = append(buf, text2bytes(n.Flags)...)
	buf = append(buf, text2bytes(n.Service)...)
	buf = append(buf, text2bytes(n.Regexp)...)
	return append(buf, __packRData(n.Replacement, current+len(buf), cdct)...)
}

func (n *NAPTR) toBytes() []byte {
	buf := n.packUint16()
	buf = append(buf, text2bytes(n.Flags)...)
	buf = append(buf, text2bytes(n.Service)...)
	buf = append(buf, text2bytes(n.Regexp)...)
	return append(buf, Name2Qname(n.Replacement)...)
}

func (n *NAPTR) fromBytes(buf []byte, current int, size int) {
	n.Order = binary.BigEndian.Uint16(buf[current : current+2])
	n.Preference = binary.BigEndian.Uint16(buf[current+2 : current+4])
	current += 4
	n.Flags = bytes2text(buf, &current)
	n.Service = bytes2text(buf, &current)
	n.Regexp = bytes2text(buf, &current)
	n.Replacement = Qname2Name(buf, &current)
}

type DNAME struct {
	Dname string
}

func (d *DNAME) packRData(current int, cdct map[string]uint16) []byte {
	return __packRData(d.Dname, current, cdct)
}

func (d *DNAME) toBytes() []byte {
	return Name2Qname(d.Dname)
}

func (d *DNAME) fromBytes(buf []byte, current int, size int) {
	d.Dname = Qname2Name(buf, &current)
}

type DHCID struct {
	Digest string
}

func (d *DHCID) packRData(current int, cdct map[string]uint16) []byte {
	return d.toBytes()
}

func (d *DHCID) toBytes() []byte {
	return text2bytes(d.Digest)
}

func (d *DHCID) fromBytes(buf []byte, current int, size int) {
	d.Digest = bytes2text(buf, &current)
}

func __packRData(name string, current int, cdct map[string]uint16) []byte {
	if cnbuf, ok := dnCompressor([]byte{}, current, name, cdct); ok {
		return cnbuf
	}
	return Name2Qname(name)
}

func text2bytes(str string) []byte {
	buf := make([]byte, len(str)+1)
	buf[0] = byte(len(str))
	copy(buf[1:], []byte(str))
	return buf
}

func bytes2text(buf []byte, current *int) string {
	length := int(buf[*current])
	*current++
	str := string(buf[*current : *current+length])
	*current += length
	return str
}
