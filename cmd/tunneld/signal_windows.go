//go:build windows

package main

import (
	"os"
)

var InterruptSignals = []os.Signal{os.Interrupt}
