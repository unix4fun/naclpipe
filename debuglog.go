package main

import (
	"io"
	"log"
)

//var DebugLog *log.Logger
//var DebugLevel int

type DebugLog struct {
	log *log.Logger
	lev int
}

func NewDebugLog(out io.Writer, prefix string) (d *DebugLog) {
	d = new(DebugLog)
	d.log = log.New(out, prefix, log.Lmicroseconds|log.LstdFlags)
	return
}

func (d *DebugLog) Inc() {
	d.lev++
}

func (d *DebugLog) Set(val int) {
	d.lev = val
}

func (d *DebugLog) Printf(msglevel int, format string, a ...interface{}) {
	//fmt.Printf("d.lev: %d msglevel: %d\n", d.lev, msglevel)
	if d.lev >= msglevel {
		d.log.Printf(format, a...)
	}
}
