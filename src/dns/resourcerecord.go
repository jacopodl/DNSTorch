package dns

import "encoding/binary"

const RRHDRSIZE = 10

type ResourceRecord struct {
	Name     string
	Qtype    uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16
	Rdata    []byte
}

func NewRR(name string, qtype, class uint16, ttl uint32, rdlength uint16, rdata []byte) (*ResourceRecord, error) {
	if err := VerifyDN(name); err != nil {
		return nil, err
	}
	return &ResourceRecord{name, qtype, class, ttl, rdlength, rdata}, nil
}

func (r *ResourceRecord) Qname() []byte {
	return Name2Qname(r.Name)
}

func (r *ResourceRecord) HeaderToBytes() []byte {
	buf := make([]byte, RRHDRSIZE)

	binary.BigEndian.PutUint16(buf[:2], r.Qtype)
	binary.BigEndian.PutUint16(buf[2:4], r.Class)
	binary.BigEndian.PutUint32(buf[4:8], r.Ttl)
	binary.BigEndian.PutUint16(buf[8:], r.Rdlength)
	return buf
}

func (r *ResourceRecord) ToBytes() []byte {
	buf := Name2Qname(r.Name)
	hdr := make([]byte, RRHDRSIZE)

	binary.BigEndian.PutUint16(hdr[:2], r.Qtype)
	binary.BigEndian.PutUint16(hdr[2:4], r.Class)
	binary.BigEndian.PutUint32(hdr[4:8], r.Ttl)
	binary.BigEndian.PutUint16(hdr[8:], r.Rdlength)
	buf = append(buf, hdr...)

	return append(buf, r.Rdata...)
}
