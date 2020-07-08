package mocha

import "github.com/shepheb/drasm/core"

// Captures the actual values that need assembling for an operand.
type operandBits struct {
	mode       uint16
	regField   uint16
	extraWords []uint16
}

type operand interface {
	Encode(s *core.AssemblyState) *operandBits
	HasEffectiveAddress() bool
}

/** Handling the simpler cases of registers. */
type regSimple struct {
	reg  uint16
	mode regMode
}

type regMode int

const (
	rmDirect regMode = iota
	rmIndirect
	rmPostincrement
	rmPredecrement
)

func (r *regSimple) Encode(s *core.AssemblyState) *operandBits {
	return &operandBits{mode: uint16(r.mode), regField: r.reg}
}

func (r *regSimple) HasEffectiveAddress() bool {
	return r.mode != rmDirect
}

func regDirect(r uint16) *regSimple {
	return &regSimple{reg: r, mode: rmDirect}
}

/** Register literal offset */
type regOffset struct {
	reg    uint16
	offset core.Expression
}

func (r *regOffset) Encode(s *core.AssemblyState) *operandBits {
	value := r.offset.Evaluate(s)
	return &operandBits{
		mode:       4,
		regField:   r.reg,
		extraWords: []uint16{core.LowWord(value)},
	}
}

func (r *regOffset) HasEffectiveAddress() bool {
	return true
}

/** Register indexed by register. */
type regIndexed struct {
	reg   uint16
	index uint16 // Another register number
}

func (r *regIndexed) Encode(s *core.AssemblyState) *operandBits {
	return &operandBits{mode: 5, regField: r.reg, extraWords: []uint16{r.index}}
}

func (r *regIndexed) HasEffectiveAddress() bool {
	return true
}

/** Special register and literal values. */
type specialReg struct {
	pc, sp, ex, ia, lit0, lit1 bool
}

func (r *specialReg) Encode(s *core.AssemblyState) *operandBits {
	bits := &operandBits{mode: 6}
	if r.pc {
		bits.regField = 0
	} else if r.sp {
		bits.regField = 1
	} else if r.ex {
		bits.regField = 2
	} else if r.ia {
		bits.regField = 3
	} else if r.lit0 {
		bits.regField = 6
	} else if r.lit1 {
		bits.regField = 7
	} else {
		panic("Malformed specialReg with no flags set")
	}
	return bits
}

func (r *specialReg) HasEffectiveAddress() bool {
	return false
}

// Literal values, indirect or immediate.
type immediate struct {
	value    core.Expression
	indirect bool
}

func (r *immediate) Encode(s *core.AssemblyState) *operandBits {
	bits := &operandBits{mode: 7, regField: 0}
	value := r.value.Evaluate(s)
	if value == 0 {
		return &operandBits{mode: 6, regField: 6}
	} else if value == 1 {
		return &operandBits{mode: 6, regField: 7}
	} else if core.Fits16(value) {
		bits.extraWords = []uint16{core.LowWord(value)}
	} else {
		bits.extraWords = []uint16{core.HighWord(value), core.LowWord(value)}
		bits.regField++ // The longword versions are one higher.
	}

	if !r.indirect {
		bits.regField += 2 // Immediate literals are 2 and 3, indirect 0 and 1.
	}

	return bits
}

func (r *immediate) HasEffectiveAddress() bool {
	return r.indirect
}

// PC-relative indirection
type pcRel struct {
	reg    uint16
	offset core.Expression // nil for the register
}

func (r *pcRel) Encode(s *core.AssemblyState) *operandBits {
	bits := &operandBits{mode: 7, regField: 4}
	if r.offset != nil {
		value := r.offset.Evaluate(s)
		if !core.Fits16Signed(value) {
			core.AsmError(r.offset.Location(),
				"PC-relative offset doesn't fit in signed 16-bit value: %d", int32(value))
		} else {
			bits.extraWords = []uint16{core.LowWord(value)}
		}
	}
	return bits
}

func (r *pcRel) HasEffectiveAddress() bool {
	return true
}

// SP-relative operations: push/pop, indirect
type spRel struct {
	offset   core.Expression
	adjustSP bool
}

func (r *spRel) Encode(s *core.AssemblyState) *operandBits {
	if r.offset == nil {
		bits := &operandBits{mode: 6, regField: 4} // PEEK
		if r.adjustSP {
			bits.regField++ // PUSH/POP
		}
		return bits
	}

	value := r.offset.Evaluate(s)
	if !core.Fits16Signed(value) {
		core.AsmError(r.offset.Location(), "SP-relative offset does not fit in 16-bit value: %d", value)
	}
	return &operandBits{mode: 7, regField: 6, extraWords: []uint16{core.LowWord(value)}}
}

func (r *spRel) HasEffectiveAddress() bool {
	return true
}

// Now the instruction types. There's a lot of subtle variations in encoding
// here, so unfortunately this takes a bunch of code to handle all the cases.
//
// Broadly, we have these types of operations:
// - Binary (reg + EA)
// - SET (2 EAs)
// - IFx/BRx (2 EAs, optional branch target)
// - Unary (EA)
// - Immediates and bit twiddlers (EA + immediate word)
// - Register only (some with immediate too)
// - Nullary (immediates again)
