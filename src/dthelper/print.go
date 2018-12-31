package dthelper

import (
	"fmt"
	"os"
)

const (
	ERRMSG  = "[X]"
	INFOMSG = "[!]"
	OKMSG   = "[+]"
)

func PrintStatusMsg(file *os.File, mtype, format string, params ...interface{}) {
	fmt.Fprintf(file, "%s %s", mtype, fmt.Sprintf(format, params...))
}

func PrintErr(format string, params ...interface{}) {
	PrintStatusMsg(os.Stderr, ERRMSG, format, params...)
}

func PrintInfo(format string, params ...interface{}) {
	PrintStatusMsg(os.Stdout, INFOMSG, format, params...)
}

func PrintOk(format string, params ...interface{}) {
	PrintStatusMsg(os.Stdout, OKMSG, format, params...)
}
