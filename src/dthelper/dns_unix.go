// +build linux darwin

package dthelper

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

func DefaultDNS() (net.IP, error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		split := strings.Fields(scanner.Text())
		if len(split) < 2 {
			continue // malformed
		}
		if strings.ToLower(split[0]) == "nameserver" {
			return net.ParseIP(split[1]), nil
		}
	}
	return nil, fmt.Errorf("nameserver not found")
}
