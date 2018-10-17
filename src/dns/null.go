package dns

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
