package resolver

import (
	"dns"
)

type Flags struct {
	AA bool
	RD bool
	AD bool
	CD bool
}

type Query struct {
	Query dns.Query
	Id    uint16
	Flags
}

type Response struct {
	Query   *Query
	Msg     *dns.Dns
	NsChain []*dns.ResourceRecord
}
