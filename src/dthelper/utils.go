package dthelper

import (
	"dnstorch/src/dns"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func ParseDNSAddr(address string) (net.IP, int, error) {
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

func ParseTarget(name string) (string, bool) {
	var addr = net.ParseIP(name)
	if addr != nil {
		if addr.To4() != nil {
			return dns.IP2Label(addr, dns.IPDOMAIN), true
		}
		return dns.IP62Label(addr, dns.IP6DOMAIN), true
	}
	return name, false
}
