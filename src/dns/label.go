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
	lc := CountLabel(name)
	buf := Name2Qname(TruncLabelRight(name, n))
	if n < lc {
		return buf[:len(buf)-1]
	}
	return buf
}

func Qname2Name(buf []byte, ptr *int) string {
	name := ""
	current := *ptr

	for sz := int(buf[current]); sz != 0x00; sz = int(buf[current]) {
		if sz == 0xC0 {
			if current == *ptr {
				*ptr++
			}
			current = int(binary.BigEndian.Uint16(buf[current:current+2])) - NAMEPTR
			continue
		}
		name += string(buf[current+1 : current+sz+1])
		if current += sz + 1; buf[current] != 0x00 {
			name += SLABELSEP
		}
		if current > *ptr {
			*ptr += sz + 1
		}
	}
	*ptr++
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

func truncLabel(name string, n int, left bool) string {
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
	if left {
		if len(name) != i {
			i++
		}
		return name[i:]
	}
	return name[:i]
}

func TruncLabelLeft(name string, n int) string {
	return truncLabel(name, n, true)
}

func TruncLabelRight(name string, n int) string {
	return truncLabel(name, n, false)
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
