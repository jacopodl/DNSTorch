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
	SLABELSEP  = "."
)

func ConcatLabel(lbl1, lbl2 string) string {
	if lbl1 != "" && strings.HasSuffix(lbl1, SLABELSEP) {
		lbl1 = lbl1[:len(lbl1)-1]
	}
	if lbl2 != "" && strings.HasPrefix(lbl2, SLABELSEP) {
		lbl2 = lbl2[1:]
	}

	switch {
	case lbl1 == "":
		return lbl2
	case lbl2 == "":
		return lbl1
	}
	return lbl1 + SLABELSEP + lbl2
}

func CountLabel(name string) int {
	count := 0
	addlbl := true

	for i := range name {
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

func dnCompressor(buf []byte, current int, name string, cdct map[string]uint16) ([]byte, bool) {
	tmp := []byte{0x00, 0x00}
	if count, ptr := searchDN(name, current, cdct); ptr > 0 {
		buf = append(buf, Name2QnameN(name, count)...)
		binary.BigEndian.PutUint16(tmp, ptr)
		return append(buf, tmp...), true
	}
	return buf, false
}

func jmpQname(buf []byte, ptr int) int {
	for length := buf[ptr]; length != 0; length = buf[ptr] {
		if length&NAMEPTR == NAMEPTR {
			ptr++
			break
		}
		ptr += int(length + 1)
	}
	return ptr + 1
}

func GetNLabel(name string, n int) string {
	count := 0
	i := 0

	if n <= 0 {
		return ""
	}
	for i = range name {
		if name[i] == LABELSEP {
			count++
			if count >= n {
				return name[:i]
			}
		}
	}
	return name
}

func Name2Qname(name string) []byte {
	var qname = make([]byte, len(name)+2)
	var i = 0
	var ins = 0
	var count byte = 0

	if name == "" || name == "." {
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
	buf := Name2Qname(GetNLabel(name, n))
	if n < lc {
		return buf[:len(buf)-1]
	}
	return buf
}

func Qname2Name(buf []byte, ptr *int) string {
	name := ""
	current := *ptr

	for sz := int(buf[current]); sz != 0x00; sz = int(buf[current]) {
		if sz&NAMEPTR == NAMEPTR {
			if current == *ptr {
				*ptr++
			}
			current = int(binary.BigEndian.Uint16(buf[current:current+2])) - 0xC000
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

func searchDN(name string, current int, dct map[string]uint16) (int, uint16) {
	label := 0
	length := len(name)
	for name != "" {
		if ptr, ok := dct[name]; ok {
			return label, ptr
		}
		dct[name] = uint16((current + (length - len(name))) | NAMEPTR) // +HDRSIZE is implicit
		name = TruncLabelLeft(name, 1)
		label++
	}
	return label, 0
}

func SplitLabel(name string) []string {
	var labels []string = nil
	splt := strings.Split(name, SLABELSEP)

	for i := range splt {
		if splt[i] != "" {
			labels = append(labels, strings.TrimSpace(splt[i]))
		}
	}

	return labels
}

func TruncLabelLeft(name string, n int) string {
	count := 0
	i := 0

	if n <= 0 {
		return name
	}

	for i = range name {
		if name[i] == LABELSEP {
			count++
			if count >= n {
				break
			}
		}
	}

	return name[i+1:]
}

func TruncLabelRight(name string, n int) string {
	count := 0

	if n <= 0 {
		return name
	}

	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == LABELSEP {
			count++
			if count >= n {
				return name[:i]
			}
		}
	}
	return ""
}

func VerifyDN(name string) error {
	chrcount := 0

	switch {
	case len(name) == 0:
		return fmt.Errorf("empty domain name")
	case len(name)+2 > 253:
		return fmt.Errorf("domain name exceeds the maximum size of %d bytes", MAXDN)
	}

	for i := range name {
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
