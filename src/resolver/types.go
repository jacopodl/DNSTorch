package resolver

import (
	"dnstorch/src/dns"
)

type DtQFlags struct {
	AAFlag bool
	RDFlag bool
	ADFlag bool
	CDFlag bool
}

type DtQuery struct {
	Query dns.Query
	DtQFlags
}

type DtLookup struct {
	Query   *DtQuery
	Msg     *dns.Dns
	NsChain []*dns.ResourceRecord
}
