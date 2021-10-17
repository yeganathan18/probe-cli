// Package runtimex contains runtime extensions. This package is inspired to
// https://pkg.go.dev/github.com/m-lab/go/rtx, except that it's simpler.
package runtimex

import (
	"fmt"
	"os"
)

// PanicOnError calls panic() if err is not nil.
func PanicOnError(err error, message string) {
	if err != nil {
		panic(fmt.Errorf("%s: %w", message, err))
	}
}

// PanicIfFalse calls panic if assertion is false.
func PanicIfFalse(assertion bool, message string) {
	if !assertion {
		panic(message)
	}
}

// PanicIfTrue calls panic if assertion is true.
func PanicIfTrue(assertion bool, message string) {
	PanicIfFalse(!assertion, message)
}

// TrapPanics transforms a panic into a clean exit from the program.
func TrapPanics() {
	if v := recover(); v != nil {
		fmt.Fprint(os.Stderr, v, "\n")
		os.Exit(1)
	}
}
