package core

import (
	"fmt"
	"os"
)

// AsmError is a helper for printing an error message, with code location.
// It wraps Printf, allowing arbitrary arguments.
func AsmError(loc, msg string, args ...interface{}) {
	fmt.Printf("Assembly error at "+loc+" "+msg+"\n", args...)
	os.Exit(1)
}
