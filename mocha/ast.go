package mocha

import (
	"fmt"

	"github.com/shepheb/drasm/core"
)

// Captures the actual values that need assembling for an operand.
type operandBits struct {
	mode       uint16
	regField   uint16
	extraWords []uint16
}

func (bits *operandBits) eaField() uint16 {
	return (bits.mode << 3) | bits.regField
}

func (bits *operandBits) assembleExtras(s *core.AssemblyState) {
	for _, w := range bits.extraWords {
		s.Push(w)
	}
}

type operand interface {
	Encode(s *core.AssemblyState) *operandBits
	HasEffectiveAddress() bool
	ErrLabel() string
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

var regLabels = map[regMode]string{
	rmDirect:        "register",
	rmIndirect:      "[register]",
	rmPostincrement: "[register]+",
	rmPredecrement:  "-[register]",
}

func (r *regSimple) ErrLabel() string {
	return regLabels[r.mode]
}

func regDirect(r uint16) *regSimple {
	return &regSimple{reg: r, mode: rmDirect}
}

func isDirectReg(op operand) bool {
	if rs, ok := op.(*regSimple); ok {
		return rs.mode == rmDirect
	}
	return false
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

func (r *regOffset) ErrLabel() string {
	return "[register + offset]"
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

func (r *regIndexed) ErrLabel() string {
	return "[register, index]"
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

func (r *specialReg) ErrLabel() string {
	if r.pc {
		return "PC"
	}
	if r.sp {
		return "SP"
	}
	if r.ex {
		return "EX"
	}
	if r.ia {
		return "IA"
	}
	if r.lit0 {
		return "lit 0"
	}
	if r.lit1 {
		return "lit 1"
	}
	panic("missing special reg type")
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
	} else if core.Fits16Signed(value) && !r.indirect {
		return &operandBits{
			mode:       7,
			regField:   7,
			extraWords: []uint16{core.LowWord(value)},
		}
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

func (r *immediate) ErrLabel() string {
	if r.indirect {
		return "[literal]"
	}
	return "literal"
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
	} else {
		// Relative index, but the register number in the next word.
		bits.extraWords = []uint16{r.reg}
		bits.regField = 5
	}
	return bits
}

func (r *pcRel) HasEffectiveAddress() bool {
	return true
}

func (r *pcRel) ErrLabel() string {
	if r.offset != nil {
		return "[PC + offset]"
	}
	return "[PC, index]"
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

func (r *spRel) ErrLabel() string {
	if r.offset != nil {
		return "[SP + offset]"
	}

	if r.adjustSP {
		return "PUSH/POP"
	}

	return "PEEK"
}

// Now the instruction types. There's a lot of subtle variations in encoding
// here, so unfortunately this takes a bunch of code to handle all the cases.
//
// Broadly, we have these types of operations:
// - Binary short
// - Binary long
// - Binary branches
// - Unary
// - Unary branches
// - Nullary

type binaryShort struct {
	opcode    uint16
	dst, src  operand
	longwords bool
}

type binaryLong struct {
	opcode    uint16
	dst, src  operand
	longwords bool
	branch    core.Expression
}

func binaryOp(opcode string, dst, src operand, longwords bool) core.Assembled {
	if short, ok := binaryOpcodesShort[opcode]; ok {
		return &binaryShort{
			opcode:    short,
			dst:       dst,
			src:       src,
			longwords: longwords,
		}
	}
	long := binaryOpcodesLong[opcode]
	return &binaryLong{
		opcode:    long,
		dst:       dst,
		src:       src,
		longwords: longwords,
	}
}

var binaryOpcodesShort = map[string]uint16{
	"set": 1,
	"add": 2,
	"sub": 3,
	"and": 4,
	"bor": 5,
	"xor": 6,
}

var binaryOpcodesLong = map[string]uint16{
	"adx": 0,
	"sbx": 1,
	"shr": 2,
	"asr": 3,
	"shl": 4,
	"mul": 5,
	"mli": 6,
	"div": 7,
	"dvi": 8,
	"lea": 9,
	"btx": 10,
	"bts": 11,
	"btc": 12,
	"bvm": 13,
	"ifb": 16,
	"ifc": 17,
	"ife": 18,
	"ifn": 19,
	"ifg": 20,
	"ifa": 21,
	"ifl": 22,
	"ifu": 23,
}

const (
	lFlag uint16 = 0x8000 // Its commonest position, bit 6.
)

func (b *binaryShort) Assemble(s *core.AssemblyState) {
	srcBits := b.src.Encode(s)
	dstBits := b.dst.Encode(s)
	word := (b.opcode << 12) | (dstBits.eaField() << 6) | srcBits.eaField()
	if b.longwords {
		word |= lFlag
	}
	s.Push(word)
	srcBits.assembleExtras(s)
	dstBits.assembleExtras(s)
}

func (b *binaryLong) Assemble(s *core.AssemblyState) {
	srcBits := b.src.Encode(s)
	dstBits := b.dst.Encode(s)
	word := 0x7000 | (dstBits.eaField() << 6) | srcBits.eaField()
	if b.longwords {
		word |= lFlag
	}
	s.Push(word)

	nextWord := b.opcode
	if b.branch != nil {
		target := b.branch.Evaluate(s)
		base := s.Index() + 1 // Just after this word, ie. where PC will point.
		delta := int32(target) - int32(base)
		fmt.Printf("binary branch %08x to %08x target: %d\n", base, target, delta)

		// The space is 11 bits signed, so make sure it'll fit.
		// That's -1024 to 1023
		// NB: Forward references are on the first pass get evaluated to 0, so we
		// sometimes fail to assemble them here. We hack around that by
		// special-casing a target of 0 and flagging the state as dirty.
		if delta < -1024 || delta > 1023 {
			if target == 0 {
				delta = 0
				s.MarkDirty()
			} else {
				core.AsmError(b.branch.Location(), "Branch target is too far away (-1024 to 1023), need %d", delta)
			}
		}
		nextWord |= uint16(delta << 5)
	} else if 0x10 <= b.opcode && b.opcode <= 0x17 { // Branches, but no branch target
		nextWord |= 0xffe0 // Set all the upper bits, signaling it's a skipping IFx.
	}
	s.Push(nextWord)
	srcBits.assembleExtras(s)
	dstBits.assembleExtras(s)
}

type unaryOp struct {
	opcode    uint16
	dst       operand
	longwords bool
	branch    core.Expression
}

func (b *unaryOp) Assemble(s *core.AssemblyState) {
	bits := b.dst.Encode(s)
	word := (b.opcode << 6) | bits.eaField()
	if b.longwords {
		word |= lFlag
	}
	s.Push(word)

	if b.branch != nil {
		// 16-bit signed value.
		target := b.branch.Evaluate(s)
		base := s.Index() + 1 // Address after this word is written.
		delta := int32(target) - int32(base)
		if delta < -65536 || delta > 65535 {
			core.AsmError(b.branch.Location(), "Branch target is too far away (+/- 64K), need %d", delta)
		}
		s.Push(uint16(delta))
	}

	bits.assembleExtras(s)
}

var unaryOpcodes = map[string]uint16{
	"swp": 1,
	"pea": 2,
	"not": 3,
	"neg": 4,
	"jsr": 5,
	"log": 6,
	"lnk": 7,
	"hwn": 9,
	"hwq": 10,
	"hwi": 11,
	"int": 12,
	"iaq": 13,
	"ext": 14,
	"clr": 15,
	"psh": 16,
	"pop": 17,
	// Branches
	"bzr":  0x20,
	"bnz":  0x21,
	"bps":  0x22,
	"bng":  0x23,
	"bzrd": 0x24,
	"bnzd": 0x25,
	"bpsd": 0x26,
	"bngd": 0x27,
}

type nullaryOp struct {
	opcode    uint16
	longwords bool
}

func (b *nullaryOp) Assemble(s *core.AssemblyState) {
	word := b.opcode
	if b.longwords {
		word |= lFlag
	}
	s.Push(word)
}

var nullaryOpcodes = map[string]uint16{
	"nop": 0,
	"rfi": 1,
	"brk": 2,
	"hlt": 3,
	"ulk": 4,
}

var binaryBranchOpcodes = map[string]uint16{
	"brb": 0x10,
	"brc": 0x11,
	"bre": 0x12,
	"brn": 0x13,
	"brg": 0x14,
	"bra": 0x15,
	"brl": 0x16,
	"bru": 0x17,
}
