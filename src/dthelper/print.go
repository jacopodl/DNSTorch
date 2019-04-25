package dthelper

import (
	"fmt"
	"os"
)

const (
	errMsg  = "[X]"
	infoMsg = "[!]"
	okMsg   = "[+]"
)

func PrintStatusMsg(file *os.File, mtype, format string, params ...interface{}) {
	_, _ = fmt.Fprintf(file, "%s %s", mtype, fmt.Sprintf(format, params...))
}

func PrintErr(format string, params ...interface{}) {
	PrintStatusMsg(os.Stderr, errMsg, format, params...)
}

func PrintInfo(format string, params ...interface{}) {
	PrintStatusMsg(os.Stdout, infoMsg, format, params...)
}

func PrintOk(format string, params ...interface{}) {
	PrintStatusMsg(os.Stdout, okMsg, format, params...)
}
