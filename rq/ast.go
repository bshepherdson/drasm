package rq

import (
	"github.com/shepheb/drasm/core"
)

type instruction struct {
	opcode string // Should be upcased.
	args   []*arg
	loc    string
}

// Assemble for top-level Risque-16s instruction.
func (op *instruction) Assemble(s *core.AssemblyState) {
	// We check for this opcode in each of the format types, and if it
	// matches the right arguments then we assemble it thus.
	if n, ok := rrrInstructions[op.opcode]; ok && len(op.args) == 3 &&
		op.args[0].kind == atReg && op.args[1].kind == atReg && op.args[2].kind == atReg {
		opRRR(op.loc, op.opcode, n, op.args, s)
	} else if n, ok := rrInstructions[op.opcode]; ok && len(op.args) == 2 &&
		op.args[0].kind == atReg && op.args[1].kind == atReg {
		opRR(op.loc, op.opcode, n, op.args, s)
	} else if n, ok := rInstructions[op.opcode]; ok && len(op.args) == 1 && op.args[0].kind == atReg {
		opR(op.loc, op.opcode, n, op.args, s)
	} else if n, ok := voidInstructions[op.opcode]; ok && len(op.args) == 0 {
		opVoid(op.loc, op.opcode, n, s)
	} else if n, ok := riInstructions[op.opcode]; ok && len(op.args) == 2 &&
		op.args[0].kind == atReg && op.args[1].kind == atLiteral {
		opRI(op.loc, op.opcode, n, op.args, s)
	} else if n, ok := branchInstructions[op.opcode]; ok && len(op.args) == 1 && op.args[0].kind == atLabel {
		opBranch(op.loc, op.opcode, n, op.args, s)
	} else if f, ok := specialInstructions[op.opcode]; ok {
		f(op.loc, op.opcode, op.args, s)
	} else {
		core.AsmError(op.loc, "Unrecognized opcode: %s", op.opcode)
	}
}

type loadStore struct {
	storing bool
	dest    uint16 // Destination register. Required
	base    uint16 // Base register. Required, but -1 for SP/PC.
	preLit  core.Expression
	preReg  uint16
	postLit core.Expression
}

// Assemble for the load and store family.
func (op *loadStore) Assemble(s *core.AssemblyState) {
	// Deal with the SP special case first.
	opcode := uint16(0)
	if op.base == 0xffff {
		// Always an 8-bit unsigned offset.
		off := uint16(0)
		if op.preLit != nil {
			off = checkLiteral(s, op.preLit, false, 4)
		}

		opcode = 6
		if op.storing {
			opcode++
		}
		s.Push(0xc000 | (opcode << 10) | uint16(op.dest<<7) | off)
		return
	}

	if op.preReg != 0xffff {
		opcode = 4
		if op.storing {
			opcode++
		}
		s.Push(0xc000 | (opcode << 10) | (op.dest << 7) | (op.base << 4) | op.preReg)
	} else if op.preLit != nil {
		opcode = 2
		if op.storing {
			opcode++
		}
		value := checkLiteral(s, op.preLit, false, 4)
		s.Push(0xc000 | (opcode << 10) | (op.dest << 7) | (op.base << 4) | value)
	} else { // Postlit, maybe 0.
		opcode = 0
		if op.storing {
			opcode++
		}
		var value uint16
		if op.postLit != nil {
			value = checkLiteral(s, op.postLit, false, 4)
		}
		s.Push(0xc000 | (opcode << 10) | (op.dest << 7) | (op.base << 4) | value)
	}
}

// Exits with an error message if the literal won't fit.
func checkLiteral(s *core.AssemblyState, expr core.Expression, signed bool, width uint) uint16 {
	value := expr.Evaluate(s)
	loc := expr.Location()
	if !signed {
		if value < (1 << width) {
			return value
		}
		core.AsmError(loc, "Unsigned literal %d (0x%x) is too big for %d-bit literal", value, value, width)
	} else {
		mask := uint16((1 << width) - 1)
		// No non-default bits outside the range.
		if (value|mask) == mask || (value|mask) == 0xffff {
			return value
		}
		core.AsmError(loc, "Signed literal %d (0x%x) doesn't fit in %d-bit literal", value, value, width)
	}
	return 0 // Never actually happens.
}

type stackOp struct {
	regs    uint16
	storing bool
	lrpc    bool
	base    uint16
}

// Assemble for push and pop stack ops.
func (op *stackOp) Assemble(s *core.AssemblyState) {
	// If base is 0xffff then this is a PUSH/POP.
	if op.base == 0xffff {
		opcode := uint16(0)
		if op.storing {
			opcode++
		}

		lrpcBit := uint16(0x0100)
		if !op.lrpc {
			lrpcBit = 0
		}

		s.Push(0xe000 | (opcode << 11) | lrpcBit | op.regs)
	} else { // LDMIA/STMIA
		opcode := uint16(2)
		if op.storing {
			opcode++
		}

		s.Push(0xe000 | (opcode << 11) | op.regs | (op.base << 8))
	}
}

const (
	atReg int = iota
	atPC
	atSP
	atRlist // Uses reg and lrpc
	atLabel
	atLiteral
)

type arg struct {
	kind  int // One of the at* constants above.
	reg   uint16
	lrpc  bool // For reg lists.
	lit   core.Expression
	label core.Expression
}

// Instructions come in several flavours, with corresponding arguments.
// Each of these tables holds opcodes and op numbers for the simple cases.
// Complex cases where the arguments don't fit the standard patterns go in
// specialInstructions (like `ADD Rd, PC, #Imm` vs. `ADD Rd, #Imm`).

var riInstructions = map[string]uint16{
	"MOV": 0x1,
	"NEG": 0x2,
	"CMP": 0x3,
	"ADD": 0x4,
	"SUB": 0x5,
	"MUL": 0x6,
	"LSL": 0x7,
	"LSR": 0x8,
	"ASR": 0x9,
	"AND": 0xa,
	"ORR": 0xb,
	"XOR": 0xc,
	"MVH": 0xf,
}

var rrrInstructions = map[string]uint16{
	"ADD": 0x1,
	"ADC": 0x2,
	"SUB": 0x3,
	"SBC": 0x4,
	"MUL": 0x5,
	"LSL": 0x6,
	"LSR": 0x7,
	"ASR": 0x8,
	"AND": 0x9,
	"ORR": 0xa,
	"XOR": 0xb,
}

var rrInstructions = map[string]uint16{
	"MOV": 0x1,
	"CMP": 0x2,
	"CMN": 0x3,
	"ROR": 0x4,
	"NEG": 0x5,
	"TST": 0x6,
	"MVN": 0x7,
}

var rInstructions = map[string]uint16{
	"BX":  0x1,
	"BLX": 0x2,
	"SWI": 0x3,
	"HWN": 0x4,
	"HWQ": 0x5,
	"HWI": 0x6,
	"XSR": 0x7,
}

var voidInstructions = map[string]uint16{
	"RFI":   0,
	"IFS":   1,
	"IFC":   2,
	"RET":   3,
	"POPSP": 4,
	"BRK":   5,
}

var branchInstructions = map[string]uint16{
	"B":   0x0,
	"BL":  0x1,
	"BEQ": 0x2,
	"BNE": 0x3,
	"BCS": 0x4,
	"BCC": 0x5,
	"BMI": 0x6,
	"BPL": 0x7,
	"BVS": 0x8,
	"BVC": 0x9,
	"BHI": 0xa,
	"BLS": 0xb,
	"BGE": 0xc,
	"BLT": 0xd,
	"BGT": 0xe,
	"BLE": 0xf,
}

var specialInstructions = map[string]func(string, string, []*arg, *core.AssemblyState){
	"ADD": opAddSub,
	"SUB": opAddSub,
	"SWI": opSWI,
}
