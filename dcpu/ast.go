package dcpu

import "github.com/shepheb/drasm/core"

type arg struct {
	reg      int // 0 = A, 7 = J
	indirect bool
	offset   core.Expression
	special  int
}

func (a *arg) encode(s *core.AssemblyState, inA bool) (inOp uint16, extraWord uint16, extraNeeded bool) {
	if a.special == 0 {
		// Register family
		inOp = uint16(a.reg) // Start with the register number.
		if a.offset != nil {
			inOp |= 16
			extraWord = core.Evaluate16(a.offset, s)
			extraNeeded = true
		} else if a.indirect {
			inOp |= 8
		}
		return
	}

	inOp = uint16(a.special)

	// Simple specials, no extra word.
	if 0x18 <= a.special && a.special <= 0x1d && a.special != 0x1a {
		return
	}

	// PICK or [lit], which can only be expressed thus.
	if a.special == 0x1a || a.special == 0x1e {
		extraWord = core.Evaluate16(a.offset, s)
		extraNeeded = true
		return
	}

	// Finally: inline literals.
	value := core.Evaluate16(a.offset, s)
	if inA && (value == 0xffff || value < 0x1f) {
		inOp = 0x21 + value
		return
	}

	// Long form literal.
	inOp = 0x1f
	extraWord = value
	extraNeeded = true
	return
}

type binaryOp struct {
	opcode uint16
	a      *arg
	b      *arg
}

func (op *binaryOp) Assemble(s *core.AssemblyState) {
	// Prepare the two arguments.
	aField, aExtra, aWide := op.a.encode(s, true)
	bField, bExtra, bWide := op.b.encode(s, false)

	opcode := (aField << 10) | (bField << 5) | op.opcode
	s.Push(opcode)

	if aWide {
		s.Push(aExtra)
	}
	if bWide {
		s.Push(bExtra)
	}
}

type unaryOp struct {
	opcode uint16
	a      *arg
}

func (op *unaryOp) Assemble(s *core.AssemblyState) {
	// Prepare the two arguments.
	aField, aExtra, aWide := op.a.encode(s, true)

	opcode := (aField << 10) | (op.opcode << 5)
	s.Push(opcode)

	if aWide {
		s.Push(aExtra)
	}
}
