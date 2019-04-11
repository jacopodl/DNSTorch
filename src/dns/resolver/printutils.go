package resolver

import (
	"dns"
	"fmt"
	"strings"
)

const (
	HEADER_ID             = "$"
	QUERY_ID              = "?"
	ANSWER_ID             = "!"
	ANSWER_AUTHSECTION_ID = "@"
	ANSWER_ADDSECTION_ID  = "+"
	GENERIC_INFO_ID       = ";"
)

func PrintQuery(query *Query) {
	fmt.Printf("%s%s Query\n", QUERY_ID, QUERY_ID)
	fmt.Printf("%s%s Flags: AA: %t RD: %t AD: %t CD: %t\n",
		QUERY_ID,
		HEADER_ID,
		query.AA,
		query.RD,
		query.AD,
		query.CD)
	fmt.Printf("%s %s\t%s\t%d\n",
		QUERY_ID,
		query.Query.Name,
		dns.Type2TName(query.Query.Type),
		query.Query.Class)
}

func PrintAnswer(msg *dns.Dns) {
	fmt.Printf("%s%s Answer\n", ANSWER_ID, ANSWER_ID)
	fmt.Printf("%s%s ID: %d\n", ANSWER_ID, HEADER_ID, msg.Identification)
	fmt.Printf("%s%s Flags: AA: %t TC: %t RD: %t RA: %t Z: %t AD: %t CD: %t\n",
		ANSWER_ID,
		HEADER_ID,
		msg.Authoritative,
		msg.Truncated,
		msg.RecursionDesired,
		msg.RecursionAvailable,
		msg.Zero,
		msg.AuthenticatedData,
		msg.CheckingDisabled)
	fmt.Printf("%s%s Rcode: %d (%s)\n", ANSWER_ID, HEADER_ID, msg.Rcode, dns.Rcode2Msg(msg.Rcode))

	if len(msg.Answers) > 0 {
		fmt.Printf("\n%s%s Answers (%d)\n", ANSWER_ID, HEADER_ID, len(msg.Answers))
		PrintRRs(msg.Answers, ANSWER_ID)
	}
	if len(msg.Authority) > 0 {
		fmt.Printf("\n%s%s Authority (%d)\n", ANSWER_ID, HEADER_ID, len(msg.Authority))
		PrintRRs(msg.Authority, ANSWER_ID+ANSWER_AUTHSECTION_ID)
	}
	if len(msg.Additional) > 0 {
		fmt.Printf("\n%s%s Additional (%d)\n", ANSWER_ID, HEADER_ID, len(msg.Additional))
		PrintRRs(msg.Additional, ANSWER_ID+ANSWER_ADDSECTION_ID)
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

func PrintLookup(lookup *Response) {
	PrintQuery(lookup.Query)
	fmt.Println()

	PrintAnswer(lookup.Msg)
	fmt.Println()

	if len(lookup.NsChain) > 0 {
		fmt.Printf("%s%s NSChain\n", GENERIC_INFO_ID, GENERIC_INFO_ID)
		PrintRRs(lookup.NsChain, GENERIC_INFO_ID)
	}
}
