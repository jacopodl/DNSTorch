package dns

import (
	"encoding/binary"
)

const (
	MASK_QR     = 0x0001
	MASK_OPCODE = 0x001E
	MASK_AA     = 0x0020
	MASK_TC     = 0x0040
	MASK_RD     = 0x0080
	MASK_RA     = 0x0100
	MASK_Z      = 0x0200
	MASK_AD     = 0x0400
	MASK_CD     = 0x0800
	MASK_RCODE  = 0xF000
)

type dnsFlags struct {
	Response           bool
	Opcode             int
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Zero               bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	Rcode              int
}

func (df *dnsFlags) packFlags() uint16 {
	flag := uint16(0)

	if df.Response {
		flag |= 1
	}
	flag |= uint16(df.Opcode) << 1
	if df.Authoritative {
		flag |= 1 << 5
	}
	if df.Truncated {
		flag |= 1 << 6
	}
	if df.RecursionDesired {
		flag |= 1 << 7
	}
	if df.RecursionAvailable {
		flag |= 1 << 8
	}
	if df.Zero {
		flag |= 1 << 9
	}
	if df.AuthenticatedData {
		flag |= 1 << 10
	}
	if df.CheckingDisabled {
		flag |= 1 << 11
	}
	flag |= uint16(df.Rcode) << 12

	return flag
}

func (df *dnsFlags) unpackFlags(flag uint16) {
	df.Response = flag&MASK_QR == MASK_QR
	df.Opcode = int(flag&MASK_OPCODE) >> 1
	df.Authoritative = flag&MASK_AA == MASK_AA
	df.Truncated = flag&MASK_TC == MASK_TC
	df.RecursionDesired = flag&MASK_RD == MASK_RD
	df.RecursionAvailable = flag&MASK_RA == MASK_RA
	df.Zero = flag&MASK_Z == MASK_Z
	df.AuthenticatedData = flag&MASK_AD == MASK_AD
	df.CheckingDisabled = flag&MASK_CD == MASK_CD
	df.Rcode = int(flag&MASK_RCODE) >> 12
}

type Dns struct {
	Identification uint16
	dnsFlags
	questions  []*Query
	answers    []*ResourceRecord
	authority  []*ResourceRecord
	additional []*ResourceRecord
}

func (d *Dns) AddQuestion(query *Query) {
	d.questions = append(d.questions, query)
}

func (d *Dns) AddAnswer(rr *ResourceRecord) {
	d.answers = append(d.answers, rr)
}

func (d *Dns) AddAuthority(rr *ResourceRecord) {
	d.authority = append(d.authority, rr)
}

func (d *Dns) AddAdditional(rr *ResourceRecord) {
	d.additional = append(d.additional, rr)
}

func (d *Dns) ToBytes(compress bool) []byte {
	buf := make([]byte, HDRSIZE)
	comprdct := map[string]uint16{}

	// pack header
	binary.BigEndian.PutUint16(buf[:2], d.Identification)
	binary.BigEndian.PutUint16(buf[2:4], d.packFlags())
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(d.questions)))
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(d.answers)))
	binary.BigEndian.PutUint16(buf[8:10], uint16(len(d.authority)))
	binary.BigEndian.PutUint16(buf[10:], uint16(len(d.additional)))

	for i := range d.questions {
		buf = d.questions[i].pack(buf, compress, comprdct)
	}
	for i := range d.answers {
		buf = d.answers[i].pack(buf, compress, comprdct)
	}
	for i := range d.authority {
		buf = d.authority[i].pack(buf, compress, comprdct)
	}
	for i := range d.additional {
		buf = d.additional[i].pack(buf, compress, comprdct)
	}

	return buf
}

func FromBytes(buf []byte) *Dns {
	dns := &Dns{}

	// unpack header
	dns.Identification = binary.BigEndian.Uint16(buf[:2])
	dns.dnsFlags.unpackFlags(binary.BigEndian.Uint16(buf[2:4]))
	qlen := int(binary.BigEndian.Uint16(buf[4:6]))
	anslen := int(binary.BigEndian.Uint16(buf[6:8]))
	authlen := int(binary.BigEndian.Uint16(buf[8:10]))
	addlen := int(binary.BigEndian.Uint16(buf[10:12]))

	ptr := HDRSIZE

	for i := 0; i < qlen; i++ {
		dns.AddQuestion(QueryFromBytes(buf, &ptr))
	}
	for i := 0; i < anslen; i++ {
		dns.AddAnswer(RRFromBytes(buf, &ptr))
	}
	for i := 0; i < authlen; i++ {
		dns.AddAuthority(RRFromBytes(buf, &ptr))
	}
	for i := 0; i < addlen; i++ {
		dns.AddAdditional(RRFromBytes(buf, &ptr))
	}

	return dns
}

func compressor(name string, current int, dct map[string]uint16) (int, uint16) {
	label := 0
	length := len(name)
	for name != "" {
		if ptr, ok := dct[name]; ok {
			return label, ptr
		}
		dct[name] = uint16((current + (length - len(name))) | NAMEPTR) // +HDRSIZE is implicit
		name = TruncLabelLeft(name, 1)
		label++
	}
	return label, 0
}

func compressName2Buf(buf []byte, current int, name string, cdct map[string]uint16) ([]byte, bool) {
	tmp := []byte{0x00, 0x00}
	if count, ptr := compressor(name, current, cdct); ptr > 0 {
		buf = append(buf, Name2QnameN(name, count)...)
		binary.BigEndian.PutUint16(tmp, ptr)
		return append(buf, tmp...), true
	}
	return buf, false
}
