package dns

import "encoding/binary"

const QUERYHDRSIZE = 4

type Query struct {
	Name  string
	Type  uint16
	Class uint16
}

func NewQuery(name string, qtype, class uint16) (*Query, error) {
	if err := VerifyDN(name); err != nil {
		return nil, err
	}
	return &Query{name, qtype, class}, nil
}

func (q *Query) Qname() []byte {
	return Name2Qname(q.Name)
}

func (q *Query) headerToBytes() []byte {
	buf := make([]byte, QUERYHDRSIZE)
	binary.BigEndian.PutUint16(buf[:2], q.Type)
	binary.BigEndian.PutUint16(buf[2:], q.Class)
	return buf
}

func (q *Query) ToBytes() []byte {
	buf := Name2Qname(q.Name)
	return append(buf, q.headerToBytes()...)
}

func (q *Query) pack(buf []byte, compress bool, cdct map[string]uint16) []byte {
	if compress {
		if rbuf, ok := compressName2Buf(buf, len(buf), q.Name, cdct); ok {
			return append(rbuf, q.headerToBytes()...)
		}
	}
	return append(buf, q.ToBytes()...)
}

func QueryFromBytes(name string, buf []byte, ptr int) *Query {
	query := Query{name, 0, 0}

	query.Type = binary.BigEndian.Uint16(buf[ptr : ptr+2])
	query.Class = binary.BigEndian.Uint16(buf[ptr+2:])

	return &query
}
