package dns

const (
	FLAG_SEP    = 1
	FLAG_REVOKE = 1 << 7
	FLAG_ZONE   = 1 << 8

	// Protocol
	PROTOCOL_VALUE = 3

	// Algorithms
	ALGO_RSAMD5           uint8 = 1
	ALGO_DH               uint8 = 2
	ALGO_DSA              uint8 = 3
	ALGO_RSASHA1          uint8 = 5
	ALGO_DSANSEC3SHA1     uint8 = 6
	ALGO_RSASHA1NSEC3SHA1 uint8 = 7
	ALGO_RSASHA256        uint8 = 8
	ALGO_RSASHA512        uint8 = 9
	ALGO_ECCGOST          uint8 = 10
	ALGO_ECDSAP256SHA256  uint8 = 11
	ALGO_ECDSAP384SHA384  uint8 = 12
	ALGO_ED25519          uint8 = 13
	ALGO_ED448            uint8 = 14
	ALGO_INDIRECT         uint8 = 252
	ALGO_PRIVATEDNS       uint8 = 253
	ALGO_PRIVATEOID       uint8 = 254
)

var (
	algoStr = map[uint8]string{
		ALGO_RSAMD5:           "RSAMD5",
		ALGO_DH:               "DH",
		ALGO_DSA:              "DSA",
		ALGO_RSASHA1:          "RSASHA1",
		ALGO_DSANSEC3SHA1:     "DSANSEC3SHA1",
		ALGO_RSASHA1NSEC3SHA1: "RSASHA1NSEC3SHA1",
		ALGO_RSASHA256:        "RSASHA256",
		ALGO_RSASHA512:        "RSASHA512",
		ALGO_ECCGOST:          "ECCGOST",
		ALGO_ECDSAP256SHA256:  "ECDSAP256SHA256",
		ALGO_ECDSAP384SHA384:  "ECDSAP384SHA384",
		ALGO_ED25519:          "ED25519",
		ALGO_ED448:            "ED448",
		ALGO_INDIRECT:         "INDIRECT",
		ALGO_PRIVATEDNS:       "PRIVATEDNS",
		ALGO_PRIVATEOID:       "PRIVATEOID"}
)

func Algo2Str(algoirthm uint8) string {
	if msg, ok := algoStr[algoirthm]; ok {
		return msg
	}
	return "unknown algorithm value"
}
