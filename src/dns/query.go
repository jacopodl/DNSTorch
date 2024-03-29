package dns

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

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

func (q *Query) ToBytes() []byte {
	buf := Name2Qname(q.Name)
	return append(buf, q.headerToBytes()...)
}

func (q *Query) String() string {
	return fmt.Sprintf("Name: %s Type: %d(%s) Class: %d", q.Name, q.Type, Type2TName(q.Type), q.Class)
}

func (q *Query) Json() string {
	js, _ := json.Marshal(q)
	return string(js)
}

func (q *Query) headerToBytes() []byte {
	buf := make([]byte, QUERYHDRSIZE)
	binary.BigEndian.PutUint16(buf[:2], q.Type)
	binary.BigEndian.PutUint16(buf[2:], q.Class)
	return buf
}

func (q *Query) pack(buf []byte, compress bool, cdct map[string]uint16) []byte {
	if compress {
		if rbuf, ok := dnCompressor(buf, len(buf), q.Name, cdct); ok {
			return append(rbuf, q.headerToBytes()...)
		}
	}
	return append(buf, q.ToBytes()...)
}

func QueryFromBytes(buf []byte, ptr *int) *Query {
	query := Query{Qname2Name(buf, ptr), 0, 0}

	query.Type = binary.BigEndian.Uint16(buf[*ptr : *ptr+2])
	query.Class = binary.BigEndian.Uint16(buf[*ptr+2:])
	*ptr += QUERYHDRSIZE

	return &query
}
