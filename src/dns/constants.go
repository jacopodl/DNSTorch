package dns

import (
	"strings"
)

const (
	MAXLEN     = 512
	HDRSIZE    = 12
	PORT       = 53
	MAXDATALEN = MAXLEN - HDRSIZE
	NAMEPTR    = 0xC0

	// QR - 1bit
	QR_QUERY    = 0
	QR_RESPONSE = 1

	// Opcodes - 4bits
	OP_QUERY  = 0
	OP_IQUERY = 1
	OP_STATUS = 2
	// 3 --
	OP_NOTIFY = 4
	OP_UPDATE = 5
	// 6 - 15 Reserved

	// Return code
	RCODE_NOERR          = 0
	RCODE_FMTERR         = 1
	RCODE_SERVER_FAILURE = 2
	RCODE_NAMEERR        = 3
	RCODE_NOTIMPL        = 4
	RCODE_REFUSED        = 5
	RCODE_YXDOMAIN       = 6
	RCODE_YXRRSET        = 7
	RCODE_NXRRSET        = 8
	RCODE_NOTATUH        = 9
	RCODE_NOTZONE        = 10
	// 11 - 15
	RCODE_BADVERS  = 16
	RCODE_BADKEY   = 17
	RCODE_BADTIME  = 18
	RCODE_BADMODE  = 19
	RCODE_BADNAME  = 20
	RCODE_BADALG   = 21
	RCODE_BADTRUNC = 22

	// Types
	TYPE_A     = 1
	TYPE_NS    = 2
	TYPE_MD    = 3
	TYPE_MF    = 4
	TYPE_CNAME = 5
	TYPE_SOA   = 6
	TYPE_MB    = 7
	TYPE_MG    = 8
	TYPE_MR    = 9
	TYPE_NULL  = 10
	TYPE_WKS   = 11
	TYPE_PTR   = 12
	TYPE_HINFO = 13
	TYPE_MINFO = 14
	TYPE_MX    = 15
	TYPE_TXT   = 16

	TYPE_RP         = 17
	TYPE_AFSDB      = 18
	TYPE_X25        = 19
	TYPE_ISDN       = 20
	TYPE_RT         = 21
	TYPE_NSAP       = 22
	TYPE_NSAP_PTR   = 23
	TYPE_SIG        = 24
	TYPE_KEY        = 25
	TYPE_PX         = 26
	TYPE_GPOS       = 27
	TYPE_AAAA       = 28
	TYPE_LOC        = 29
	TYPE_NXT        = 30
	TYPE_EID        = 31
	TYPE_NIMLOC     = 32
	TYPE_SRV        = 33
	TYPE_ATMA       = 34
	TYPE_NAPTR      = 35
	TYPE_KX         = 36
	TYPE_CERT       = 37
	TYPE_A6         = 38
	TYPE_DNAME      = 39
	TYPE_SINK       = 40
	TYPE_OPT        = 41
	TYPE_APL        = 42
	TYPE_DS         = 43
	TYPE_SSHFP      = 44
	TYPE_IPSECKEY   = 45
	TYPE_RRSIG      = 46
	TYPE_NSEC       = 47
	TYPE_DNSKEY     = 48
	TYPE_DHCID      = 49
	TYPE_NSEC3      = 50
	TYPE_NSEC3PARAM = 51
	TYPE_TLSA       = 52
	// 53 - 54
	TYPE_HIP    = 55
	TYPE_NINFO  = 56
	TYPE_RKEY   = 57
	TYPE_TALINK = 58
	TYPE_CDS    = 59
	// 60 - 98
	TYPE_SPF    = 99
	TYPE_UINFO  = 100
	TYPE_UID    = 101
	TYPE_GID    = 102
	TYPE_UNSPEC = 103
	// 104 - 248
	TYPE_TKEY  = 249
	TYPE_TISG  = 250
	TYPE_IXFR  = 251
	TYPE_AXFR  = 252
	TYPE_MAILB = 253
	TYPE_MAILA = 254
	TYPE_ANY   = 255
	TYPE_URI   = 256
	TYPE_CAA   = 257
	// 258 - 32767
	TYPE_TA  = 32768
	TYPE_DLV = 32769

	// Class
	CLASS_RESERVED = 0
	CLASS_IN       = 1
	// 2
	CLASS_CH = 3
	CLASS_HS = 4
	// 5 - 253
	CLASS_NONE = 254
	CLASS_ANY  = 255
	// 256 - 65279
	// 65280 - 65534 Private Use.
	// 65535
)

var (
	rcMsg = map[int]string{
		RCODE_NOERR:          "request completed successfully",
		RCODE_FMTERR:         "name server was unable to interpret the query",
		RCODE_SERVER_FAILURE: "name server was unable to process this query due to a problem with the name server",
		RCODE_NAMEERR:        "domain name referenced in the query does not exist",
		RCODE_NOTIMPL:        "name server does not support the requested kind of query",
		RCODE_REFUSED:        "name server refuses to perform the specified operation for policy reasons",
		RCODE_YXDOMAIN:       "name exists when it should not.",
		RCODE_YXRRSET:        "RR set exists when it should not",
		RCODE_NXRRSET:        "RR set that should exist does not",
		RCODE_NOTATUH:        "server not authoritative for zone",
		RCODE_NOTZONE:        "name not contained in zone",
		RCODE_BADVERS:        "bad OPT version / TSIG signature failure",
		RCODE_BADKEY:         "key not recognized",
		RCODE_BADTIME:        "signature out of time window",
		RCODE_BADMODE:        "bad TKEY mode",
		RCODE_BADNAME:        "duplicate key name",
		RCODE_BADALG:         "algorithm not supported",
		RCODE_BADTRUNC:       "bad truncation"}
	nameType = map[string]int{
		"A":          TYPE_A,
		"NS":         TYPE_NS,
		"MD":         TYPE_MD,
		"MF":         TYPE_MF,
		"CNAME":      TYPE_CNAME,
		"SOA":        TYPE_SOA,
		"MB":         TYPE_MB,
		"MG":         TYPE_MG,
		"MR":         TYPE_MR,
		"NULL":       TYPE_NULL,
		"WKS":        TYPE_WKS,
		"PTR":        TYPE_PTR,
		"HINFO":      TYPE_HINFO,
		"MINFO":      TYPE_MINFO,
		"MX":         TYPE_MX,
		"TXT":        TYPE_TXT,
		"RP":         TYPE_RP,
		"AFSDB":      TYPE_AFSDB,
		"X25":        TYPE_X25,
		"ISDN":       TYPE_ISDN,
		"RT":         TYPE_RT,
		"NSAP":       TYPE_NSAP,
		"NSAP_PTR":   TYPE_NSAP_PTR,
		"SIG":        TYPE_SIG,
		"KEY":        TYPE_KEY,
		"PX":         TYPE_PX,
		"GPOS":       TYPE_GPOS,
		"AAAA":       TYPE_AAAA,
		"LOC":        TYPE_LOC,
		"NXT":        TYPE_NXT,
		"EID":        TYPE_EID,
		"NIMLOC":     TYPE_NIMLOC,
		"SRV":        TYPE_SRV,
		"ATMA":       TYPE_ATMA,
		"NAPTR":      TYPE_NAPTR,
		"KX":         TYPE_KX,
		"CERT":       TYPE_CERT,
		"A6":         TYPE_A6,
		"DNAME":      TYPE_DNAME,
		"SINK":       TYPE_SINK,
		"OPT":        TYPE_OPT,
		"APL":        TYPE_APL,
		"DS":         TYPE_DS,
		"SSHFP":      TYPE_SSHFP,
		"IPSECKEY":   TYPE_IPSECKEY,
		"RRSIG":      TYPE_RRSIG,
		"NSEC":       TYPE_NSEC,
		"DNSKEY":     TYPE_DNSKEY,
		"DHCID":      TYPE_DHCID,
		"NSEC3":      TYPE_NSEC3,
		"NSEC3PARAM": TYPE_NSEC3PARAM,
		"TLSA":       TYPE_TLSA,
		"HIP":        TYPE_HIP,
		"NINFO":      TYPE_NINFO,
		"RKEY":       TYPE_RKEY,
		"TALINK":     TYPE_TALINK,
		"CDS":        TYPE_CDS,
		"SPF":        TYPE_SPF,
		"UINFO":      TYPE_UINFO,
		"UID":        TYPE_UID,
		"GID":        TYPE_GID,
		"UNSPEC":     TYPE_UNSPEC,
		"TKEY":       TYPE_TKEY,
		"TISG":       TYPE_TISG,
		"IXFR":       TYPE_IXFR,
		"AXFR":       TYPE_AXFR,
		"MAILB":      TYPE_MAILB,
		"MAILA":      TYPE_MAILA,
		"ANY":        TYPE_ANY,
		"URI":        TYPE_URI,
		"CAA":        TYPE_CAA,
		"TA":         TYPE_TA,
		"DLV":        TYPE_DLV}
	typeName map[uint16]string = nil
)

func Rcode2Msg(rcode int) string {
	if msg, ok := rcMsg[rcode]; ok {
		return msg
	}
	return "unknown RCODE value"
}

func TName2Type(name string) (uint16, bool) {
	if val, ok := nameType[strings.ToUpper(name)]; ok {
		return uint16(val), true
	}
	return 0, false
}

func Type2TName(tp uint16) string {
	if typeName == nil {
		typeName = make(map[uint16]string, len(nameType))
		for i := range nameType {
			typeName[uint16(nameType[i])] = i
		}
	}
	if val, ok := typeName[tp]; ok {
		return val
	}
	return ""
}

func CName2Class(name string) (uint16, bool) {
	var class uint16 = 0

	switch strings.ToUpper(name) {
	case "IN":
		class = CLASS_IN
	case "CH":
		class = CLASS_CH
	case "HS":
		class = CLASS_HS
	case "NONE":
		class = CLASS_NONE
	case "ANY":
		class = CLASS_ANY
	default:
		return 0, false
	}

	return class, true
}
