package dcpu

import "github.com/shepheb/drasm/core"

type arg struct {
	reg      int // 0 = A, 7 = J
	indirect bool
	offset   core.Expression
	special  int
}

type binaryOp struct {
	opcode uint16
	a      *arg
	b      *arg
}

type unaryOp struct {
	opcode uint16
	a      *arg
}
