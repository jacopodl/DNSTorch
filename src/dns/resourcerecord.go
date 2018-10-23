package dns

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
)

const RRHDRSIZE = 10

type RdInterface interface {
	packRData(current int, cdct map[string]uint16) []byte
	fromBytes(buf []byte, current int, size int)
	toBytes() []byte
}

type resourceRecord struct {
	Name     string
	Qtype    uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16
	Rdata    RdInterface
}

func NewRR(name string, qtype, class uint16, ttl uint32, rdata RdInterface) (*resourceRecord, error) {
	if err := VerifyDN(name); err != nil {
		return nil, err
	}
	rr := &resourceRecord{name, qtype, class, ttl, 0, rdata}
	if rdata == nil {
		rr.Rdata = &NULL{}
	}
	return rr, nil
}

func (r *resourceRecord) ToBytes() []byte {
	buf := Name2Qname(r.Name)
	rdata := r.Rdata.toBytes()
	r.Rdlength = uint16(len(rdata))
	buf = append(buf, r.headerToBytes()...)
	return append(buf, rdata...)
}

func (r *resourceRecord) String() string {
	str := fmt.Sprintf("Name: %s"+
		"\nType: %d"+
		"\nClass: %d"+
		"\nTTL: %d"+
		"\nLength: %d"+
		"\nRDATA:", r.Name, r.Qtype, r.Class, r.Ttl, r.Rdlength)
	rds := r.RDStringsList()
	for i := range rds {
		str += "\n\t" + rds[i]
	}
	return str
}

func (r *resourceRecord) Json() string {
	js, _ := json.Marshal(r)
	return string(js)
}

func (r *resourceRecord) RDStringsList() []string {
	var strs []string = nil
	ref := reflect.ValueOf(r.Rdata).Elem()
	for i := 0; i < ref.NumField(); i++ {
		strs = append(strs, fmt.Sprintf("%s: %s", ref.Type().Field(i).Name, ref.Field(i).Interface()))
	}
	return strs
}

func (r *resourceRecord) headerToBytes() []byte {
	buf := make([]byte, RRHDRSIZE)

	binary.BigEndian.PutUint16(buf[:2], r.Qtype)
	binary.BigEndian.PutUint16(buf[2:4], r.Class)
	binary.BigEndian.PutUint32(buf[4:8], r.Ttl)
	binary.BigEndian.PutUint16(buf[8:], r.Rdlength)

	return buf
}

func (r *resourceRecord) pack(buf []byte, compress bool, cdct map[string]uint16) []byte {
	if compress {
		if buf, ok := dnCompressor(buf, len(buf), r.Name, cdct); ok {
			rdata := r.Rdata.packRData(len(buf)+RRHDRSIZE, cdct)
			r.Rdlength = uint16(len(rdata))
			buf = append(buf, r.headerToBytes()...)
			return append(buf, rdata...)
		}
	}
	return append(buf, r.ToBytes()...)
}

func (r *resourceRecord) unpack(buf []byte, ptr int) {
	switch r.Qtype {
	case TYPE_A:
		r.Rdata = &A{}
	case TYPE_NS:
		r.Rdata = &NS{}
	case TYPE_MD:
		r.Rdata = &MD{}
	case TYPE_MF:
		r.Rdata = &MF{}
	case TYPE_CNAME:
		r.Rdata = &CNAME{}
	case TYPE_SOA:
		r.Rdata = &SOA{}
	case TYPE_MB:
		r.Rdata = &MB{}
	case TYPE_MG:
		r.Rdata = &MG{}
	case TYPE_MR:
		r.Rdata = &MR{}
	case TYPE_NULL:
		r.Rdata = &NULL{}
	case TYPE_WKS:
		r.Rdata = &WKS{}
	case TYPE_PTR:
		r.Rdata = &PTR{}
	case TYPE_HINFO:
		r.Rdata = &HINFO{}
	case TYPE_MINFO:
		r.Rdata = &MINFO{}
	case TYPE_MX:
		r.Rdata = &MX{}
	case TYPE_TXT:
		r.Rdata = &TXT{}
	case TYPE_AAAA:
		r.Rdata = &AAAA{}
	case TYPE_SRV:
		r.Rdata = &SRV{}
	case TYPE_NAPTR:
		r.Rdata = &NAPTR{}
	case TYPE_DNAME:
		r.Rdata = &DNAME{}
	case TYPE_DHCID:
		r.Rdata = &DHCID{}
	default:
		panic(fmt.Errorf("unknown type: %d", r.Qtype))
	}
	r.Rdata.fromBytes(buf, ptr, int(r.Rdlength))
}

func RRFromBytes(buf []byte, ptr *int) *resourceRecord {
	rr := &resourceRecord{Qname2Name(buf, ptr), 0, 0, 0, 0, nil}

	rr.Qtype = binary.BigEndian.Uint16(buf[*ptr : *ptr+2])
	rr.Class = binary.BigEndian.Uint16(buf[*ptr+2 : *ptr+4])
	rr.Ttl = binary.BigEndian.Uint32(buf[*ptr+4 : *ptr+8])
	rr.Rdlength = binary.BigEndian.Uint16(buf[*ptr+8 : *ptr+10])
	*ptr += RRHDRSIZE

	rr.unpack(buf, *ptr)

	*ptr += int(rr.Rdlength)

	return rr
}
