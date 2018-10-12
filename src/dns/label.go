package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	MAXLBLSIZE = 63
	MAXDN      = 253
	LABELSEP   = '.'
	SLABELSEP  = string(LABELSEP)
)

func CountLabel(name string) int {
	count := 0
	addlbl := true

	for i, _ := range name {
		if addlbl {
			count++
			addlbl = false
		}
		if name[i] == LABELSEP {
			addlbl = true
			continue
		}
	}
	return count
}

func jmpQname(buf []byte, ptr int) int {
	for length := buf[ptr]; length != 0; length = buf[ptr] {
		if length == 0xC0 {
			ptr++
			break
		}
		ptr += int(length + 1)
	}
	return ptr + 1
}

func Name2Qname(name string) []byte {
	var qname []byte = make([]byte, len(name)+2)
	var i = 0
	var ins = 0
	var count byte = 0

	if name == "" {
		return []byte{0x00}
	}

	for i = range name {
		if name[i] == LABELSEP {
			qname[ins] = count
			ins = i + 1
			count = 0
			continue
		}
		qname[i+1] = name[i]
		count++
	}
	qname[ins] = count
	qname[i+2] = 0x00
	return qname
}

func Name2QnameN(name string, n int) []byte {
	return Name2Qname(TruncLabel(name, n))
}

func Qname2Name(buf []byte, ptr int) string {
	name := ""

	for sz := int(buf[ptr]); sz != 0x00; sz = int(buf[ptr]) {
		if sz == 0xC0 {
			ptr = int(binary.BigEndian.Uint16(buf[ptr:ptr+2])) - NAMEPTR - HDRSIZE
			continue
		}
		name += string(buf[ptr+1 : ptr+sz+1])
		if ptr += sz + 1; buf[ptr] != 0x00 {
			name += SLABELSEP
		}
	}
	return name
}

func SplitLabel(name string) []string {
	var labels []string = nil
	splt := strings.Split(name, SLABELSEP)

	for i, _ := range splt {
		if splt[i] != "" {
			labels = append(labels, strings.TrimSpace(splt[i]))
		}
	}

	return labels
}

func TruncLabel(name string, n int) string {
	count := 0
	i := 0

	if n <= 0 {
		return ""
	}
	for i, _ = range name {
		if name[i] == LABELSEP {
			count++
			if count >= n {
				i--
				break
			}
		}
	}
	i++
	return name[:i]
}

func VerifyDN(name string) error {
	chrcount := 0

	switch {
	case len(name) == 0:
		return fmt.Errorf("empty domain name")
	case len(name)+2 > 253:
		return fmt.Errorf("domain name exceeds the maximum size of %d bytes", MAXDN)
	}

	for i, _ := range name {
		if name[i] != LABELSEP {
			chrcount++
			if chrcount > MAXLBLSIZE {
				return fmt.Errorf("label exceeds the maximum size of %d bytes", MAXLBLSIZE)
			}
			continue
		}
		chrcount = 0
	}
	return nil
}
