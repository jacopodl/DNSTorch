package dns

import (
	"encoding/binary"
)

const RRHDRSIZE = 10

type RdInterface interface {
	packRData(current int, cdct map[string]uint16) []byte
	toBytes() []byte
}

type ResourceRecord struct {
	Name     string
	Qtype    uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16
	Rdata    RdInterface
}

func NewRR(name string, qtype, class uint16, ttl uint32, rdata RdInterface) (*ResourceRecord, error) {
	if err := VerifyDN(name); err != nil {
		return nil, err
	}
	rr := &ResourceRecord{name, qtype, class, ttl, 0, rdata}
	if rdata == nil {
		rr.Rdata = &NULL{}
	}
	return rr, nil
}

func (r *ResourceRecord) headerToBytes() []byte {
	buf := make([]byte, RRHDRSIZE)

	binary.BigEndian.PutUint16(buf[:2], r.Qtype)
	binary.BigEndian.PutUint16(buf[2:4], r.Class)
	binary.BigEndian.PutUint32(buf[4:8], r.Ttl)
	binary.BigEndian.PutUint16(buf[8:], r.Rdlength)

	return buf
}

func (r *ResourceRecord) ToBytes() []byte {
	buf := Name2Qname(r.Name)
	rdata := r.Rdata.toBytes()
	r.Rdlength = uint16(len(rdata))
	buf = append(buf, r.headerToBytes()...)
	return append(buf, rdata...)
}

func (r *ResourceRecord) pack(buf []byte, compress bool, cdct map[string]uint16) []byte {
	if compress {
		if rbuf, ok := compressName2Buf(buf, len(buf), r.Name, cdct); ok {
			rdata := r.Rdata.packRData(len(buf), cdct)
			r.Rdlength = uint16(len(rdata))
			buf = append(rbuf, r.headerToBytes()...)
			return append(buf, rdata...)
		}
	}
	return append(buf, r.ToBytes()...)
}
