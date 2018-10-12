package dns

import "encoding/binary"

const QUERYHDRSIZE = 4

type Query struct {
	Name  string
	Type  uint16
	Class uint16
}

func (q *Query) Qname() []byte {
	return Name2Qname(q.Name)
}

func (q *Query) HeaderToBytes() []byte {
	buf := make([]byte, QUERYHDRSIZE)
	binary.BigEndian.PutUint16(buf[:2], q.Type)
	binary.BigEndian.PutUint16(buf[2:], q.Class)
	return buf
}

func (q *Query) ToBytes() []byte {
	buf := Name2Qname(q.Name)
	hdr := make([]byte, QUERYHDRSIZE)

	binary.BigEndian.PutUint16(hdr[:2], q.Type)
	binary.BigEndian.PutUint16(hdr[2:], q.Class)
	return append(buf, hdr...)
}

func QueryFromBytes(name string, buf []byte, ptr int) *Query {
	query := Query{name, 0, 0}

	query.Type = binary.BigEndian.Uint16(buf[ptr : ptr+2])
	query.Class = binary.BigEndian.Uint16(buf[ptr+2:])

	return &query
}
