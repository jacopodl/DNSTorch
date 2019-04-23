package dthelper

import (
	"bufio"
	"dns"
	"dns/resolver"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

func ParseAddr(address string) (net.IP, int, error) {
	var port uint64 = dns.PORT
	var sport = ""
	var err error = nil

	last := strings.LastIndex(address, ":")

	if address[0] == '[' {
		// Expect ']' just before the last ':'.
		if address[last-1] != ']' {
			return nil, 0, fmt.Errorf("missing ']' in address")
		}
		sport = address[last+1:]
		address = address[1 : last-1]
	} else {
		if strings.Contains(address, ".") && last > 0 {
			sport = address[last+1:]
			address = address[:last]
		}
	}

	if ip := net.ParseIP(address); ip != nil {
		if sport != "" {
			if port, err = strconv.ParseUint(sport, 10, 16); err != nil {
				return nil, 0, fmt.Errorf("malformed port: %s", address[last+1:])
			}
		}
		return ip, int(port), nil
	}

	// resolve address
	if ips, err := net.LookupIP(address); err != nil {
		return nil, 0, err
	} else {
		return ips[0], int(port), nil
	}
}

func ParseNSList(path string, resolver *resolver.Resolver) error {
	var reader *bufio.Reader = nil
	var file *os.File = nil
	var buf []byte = nil
	var err error = nil

	if file, err = os.Open(path); err != nil {
		return err
	}

	reader = bufio.NewReader(file)

	for {
		if buf, _, err = reader.ReadLine(); err != nil {
			if err != io.EOF {
				_ = file.Close()
				return err
			}
			break
		} else {
			str := strings.TrimSpace(string(buf))
			if len(str) == 0 || strings.HasPrefix(str, "#") {
				continue
			}
			if addr, port, err := ParseAddr(str); err == nil {
				resolver.AddNS(addr, port)
			}
		}
	}

	_ = file.Close()
	return nil
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
