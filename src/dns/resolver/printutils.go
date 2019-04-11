package resolver

import (
	"dns"
	"fmt"
	"strings"
)

const (
	HeaderId            = "$"
	QueryId             = "?"
	AnswerId            = "!"
	AnswerAuthSectionId = "@"
	AnswerAddSectionId  = "+"
	GenericInfoId       = ";"
)

func PrintQuery(query *Query) {
	fmt.Printf("%s%s Query\n", QueryId, QueryId)
	fmt.Printf("%s%s Flags: AA: %t RD: %t AD: %t CD: %t\n",
		QueryId,
		HeaderId,
		query.AA,
		query.RD,
		query.AD,
		query.CD)
	fmt.Printf("%s %s\t%s\t%d\n",
		QueryId,
		query.Query.Name,
		dns.Type2TName(query.Query.Type),
		query.Query.Class)
}

func PrintAnswer(msg *dns.Dns) {
	fmt.Printf("%s%s Answer\n", AnswerId, AnswerId)
	fmt.Printf("%s%s ID: %d\n", AnswerId, HeaderId, msg.Identification)
	fmt.Printf("%s%s Flags: AA: %t TC: %t RD: %t RA: %t Z: %t AD: %t CD: %t\n",
		AnswerId,
		HeaderId,
		msg.Authoritative,
		msg.Truncated,
		msg.RecursionDesired,
		msg.RecursionAvailable,
		msg.Zero,
		msg.AuthenticatedData,
		msg.CheckingDisabled)
	fmt.Printf("%s%s Rcode: %d (%s)\n", AnswerId, HeaderId, msg.Rcode, dns.Rcode2Msg(msg.Rcode))

	if len(msg.Answers) > 0 {
		fmt.Printf("\n%s%s Answers (%d)\n", AnswerId, HeaderId, len(msg.Answers))
		PrintRRs(msg.Answers, AnswerId)
	}
	if len(msg.Authority) > 0 {
		fmt.Printf("\n%s%s Authority (%d)\n", AnswerId, HeaderId, len(msg.Authority))
		PrintRRs(msg.Authority, AnswerId+AnswerAuthSectionId)
	}
	if len(msg.Additional) > 0 {
		fmt.Printf("\n%s%s Additional (%d)\n", AnswerId, HeaderId, len(msg.Additional))
		PrintRRs(msg.Additional, AnswerId+AnswerAddSectionId)
	}
}

func PrintRRs(records []*dns.ResourceRecord, prefix string) {
	dmlen := 0
	tmlen := 0

	for i := range records {
		dnlen := len(records[i].Name)
		qtlen := len(dns.Type2TName(records[i].Qtype))
		if dnlen > dmlen {
			dmlen = dnlen
		}
		if qtlen > tmlen {
			tmlen = qtlen
		}
	}

	for i := range records {
		dn := records[i].Name
		qtype := dns.Type2TName(records[i].Qtype)
		fmt.Printf("%s %s\t%s\t%d\t%d\t%s\n",
			prefix,
			dn+strings.Repeat(" ", dmlen-len(records[i].Name)),
			qtype+strings.Repeat(" ", tmlen-len(qtype)),
			records[i].Class,
			records[i].Ttl,
			strings.Join(records[i].RDStringsList(false), " "))
	}
}

func PrintLookup(response *Response) {
	PrintQuery(response.Query)
	fmt.Println()

	PrintAnswer(response.Msg)
	fmt.Println()

	if len(response.NsChain) > 0 {
		fmt.Printf("%s%s NSChain\n", GenericInfoId, GenericInfoId)
		PrintRRs(response.NsChain, GenericInfoId)
	}
}
