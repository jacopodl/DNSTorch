package dthelper

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
	"net"
	"strings"
)

func DefaultDNS() (net.IP, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	if v, _, err := key.GetStringValue("DhcpNameServer"); err == nil {
		return net.ParseIP(strings.Fields(v)[0]), nil
	}

	if v, _, err := key.GetStringValue("Domain"); err == nil {
		if ips, err := net.LookupIP(v); err == nil {
			return ips[0], nil
		}
	}

	return nil, fmt.Errorf("nameserver not found")
}
