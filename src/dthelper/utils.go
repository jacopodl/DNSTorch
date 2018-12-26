package dthelper

import (
	"dns"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func ParseDSAddr(address string) (net.IP, int, error) {
	var port uint64 = dns.PORT
	var err error = nil

	split := strings.Split(address, ":")

	if len(split) > 1 {
		if port, err = strconv.ParseUint(split[1], 10, 16); err != nil {
			return nil, 0, fmt.Errorf("malformed port: %s", split[2])
		}
	}

	if ip := net.ParseIP(split[0]); ip != nil {
		return ip, int(port), nil
	}

	// resolve address
	if ips, err := net.LookupIP(split[0]); err != nil {
		return nil, 0, err
	} else {
		return ips[0], int(port), nil
	}
}
