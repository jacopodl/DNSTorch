package dthelper

import (
	"bufio"
	"io"
	"os"
)

const DEFAULTQLEN = 10

type FDict struct {
	file   *os.File
	closed bool
	Data   chan string
	stopch chan bool
}

func NewFDict(path string, qlen int) (*FDict, error) {
	fdict := &FDict{Data: make(chan string, qlen), stopch: make(chan bool)}

	if file, err := os.Open(path); err != nil {
		return nil, err
	} else {
		fdict.file = file
	}

	go fdict.readFile()

	return fdict, nil
}

func (f *FDict) readFile() {
	reader := bufio.NewReader(f.file)
	str := ""

	for !f.closed {
		if buf, _, err := reader.ReadLine(); err != nil {
			if err != io.EOF {
				panic(err)
			}
			break
		} else {
			if len(buf) == 0 {
				continue
			}
			str = string(buf)
		}
		select {
		case <-f.stopch:
			f.closed = true
		case f.Data <- str:
		}
	}
	close(f.Data)
}

func (f *FDict) Close() {
	f.closed = true
	close(f.stopch)
}

func (f *FDict) IsClosed() bool {
	return f.closed
}
