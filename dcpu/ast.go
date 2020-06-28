package dcpu

import "github.com/shepheb/drasm/core"

type arg struct {
	reg      int // 0 = A, 7 = J
	indirect bool
	offset   core.Expression
	special  int
}
