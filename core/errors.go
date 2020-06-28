package core

import (
	"fmt"
	"os"

	"github.com/shepheb/psec"
)

// AsmError is a helper for printing an error message, with code location.
// It wraps Printf, allowing arbitrary arguments.
func AsmError(loc *psec.Loc, msg string, args ...interface{}) {
	fmt.Printf("Assembly error at "+loc.String()+": "+msg+"\n", args...)
	os.Exit(1)
}
