package dns

import (
	"encoding/binary"
)

const (
	MASK_QR     = 1 << 15
	MASK_OPCODE = 0x000F
	MASK_AA     = 1 << 10
	MASK_TC     = 1 << 9
	MASK_RD     = 1 << 8
	MASK_RA     = 1 << 7
	MASK_Z      = 1 << 6
	MASK_AD     = 1 << 5
	MASK_CD     = 1 << 4
	MASK_RCODE  = 0x000F
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
		flag |= MASK_QR
	}
	flag |= uint16(df.Opcode&MASK_OPCODE) << 11
	if df.Authoritative {
		flag |= MASK_AA
	}
	if df.Truncated {
		flag |= MASK_TC
	}
	if df.RecursionDesired {
		flag |= MASK_RD
	}
	if df.RecursionAvailable {
		flag |= MASK_RA
	}
	if df.Zero {
		flag |= MASK_Z
	}
	if df.AuthenticatedData {
		flag |= MASK_AD
	}
	if df.CheckingDisabled {
		flag |= MASK_CD
	}
	flag |= uint16(df.Rcode & MASK_RCODE)

	return flag
}

func (df *dnsFlags) unpackFlags(flag uint16) {
	df.Response = flag&MASK_QR == MASK_QR
	df.Opcode = int(flag>>11) & MASK_OPCODE
	df.Authoritative = flag&MASK_AA == MASK_AA
	df.Truncated = flag&MASK_TC == MASK_TC
	df.RecursionDesired = flag&MASK_RD == MASK_RD
	df.RecursionAvailable = flag&MASK_RA == MASK_RA
	df.Zero = flag&MASK_Z == MASK_Z
	df.AuthenticatedData = flag&MASK_AD == MASK_AD
	df.CheckingDisabled = flag&MASK_CD == MASK_CD
	df.Rcode = int(flag & MASK_RCODE)
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
