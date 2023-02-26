//go:build !windows

package main

import (
	"os"
	"syscall"
)

var InterruptSignals = []os.Signal{
	os.Interrupt,
	syscall.SIGTERM,
	syscall.SIGHUP,
}
