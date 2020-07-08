package mocha

import "github.com/shepheb/drasm/core"

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
	} else if core.Fits16(value) || core.Fits16Signed(value) {
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
// - Binary (reg + EA)
// - SET (2 EAs)
// - IFx/BRx (2 EAs, optional branch target)
// - Unary (EA)
// - Immediates and bit twiddlers (EA + immediate word)
// - Register only (some with immediate too)
// - Nullary (immediates again)

type binary struct {
	opcode    uint16
	reg       uint16
	arg       operand
	argDst    bool
	longwords bool
}

func binaryOp(opcode uint16, arg operand, reg uint16, argDst, longwords bool) *binary {
	return &binary{
		opcode:    opcode,
		reg:       reg,
		arg:       arg,
		argDst:    argDst,
		longwords: longwords,
	}
}

var binaryOpcodes = map[string]uint16{
	"add": 8,
	"adx": 9,
	"sub": 10,
	"sbx": 11,
	"mul": 12,
	"mli": 13,
	"div": 14,
	"dvi": 15,
	"and": 16,
	"bor": 17,
	"xor": 18,
	"shr": 19,
	"asr": 20,
	"shl": 21,
}

const (
	lFlag uint16 = 0x40 // Its commonest position, bit 6.
)

func (b *binary) Assemble(s *core.AssemblyState) {
	bits := b.arg.Encode(s)
	word := (b.opcode << 11) | (b.reg << 8) | bits.eaField()
	if b.longwords {
		word |= lFlag
	}
	if b.argDst {
		word |= 0x80
	}
	s.Push(word)
	bits.assembleExtras(s)
}

type binaryImmediate struct {
	opcode    uint16
	literal   core.Expression
	dst       operand
	longwords bool
}

func immediateOp(opcode uint16, dst operand, lit core.Expression, longwords bool) *binaryImmediate {
	return &binaryImmediate{
		opcode:    opcode,
		literal:   lit,
		dst:       dst,
		longwords: longwords,
	}
}

var immediateOpcodes = map[string]uint16{
	"add": 1,
	"sub": 2,
	"and": 3,
	"bor": 4,
	"xor": 5,
}

func (b *binaryImmediate) Assemble(s *core.AssemblyState) {
	bits := b.dst.Encode(s)
	word := b.opcode<<7 | bits.eaField()
	if b.longwords {
		word |= lFlag
	}

	s.Push(word)
	value := b.literal.Evaluate(s)
	if b.longwords {
		s.Push(core.HighWord(value))
		s.Push(core.LowWord(value))
	} else {
		s.Push(core.LowWord(value))
	}

	bits.assembleExtras(s)
}

var bitTwiddlerOpcodes = map[string]uint16{
	"btx": 0,
	"bts": 1,
	"btc": 2,
	"btm": 3,
}

type bitTwiddlerOp struct {
	opcode    uint16
	longwords bool
	dst       operand
	bit       core.Expression
}

func (b *bitTwiddlerOp) Assemble(s *core.AssemblyState) {
	bits := b.dst.Encode(s)
	word := 0x0400 | (b.opcode << 7) | bits.eaField()
	if b.longwords {
		word |= lFlag
	}
	s.Push(word)

	value := core.Evaluate16(b.bit, s)
	s.Push(value)

	bits.assembleExtras(s)
}

type unaryOp struct {
	opcode uint16 // The low bit of this is considered the longwords bit by some.
	dst    operand
}

func (b *unaryOp) Assemble(s *core.AssemblyState) {
	bits := b.dst.Encode(s)
	s.Push(0x0800 | (b.opcode << 6) | bits.eaField())
	bits.assembleExtras(s)
}

var unaryOpcodes = map[string]uint16{
	"swp": 0,
	"pea": 1,
	"ext": 2,
	"int": 3,
	// Then for these the low bit is the L flag; we give the number with L clear.
	"not": 4,
	"neg": 6,
	"jsr": 8,
	"iaq": 10,
	"log": 12,
	"hwi": 14,
}

type regOp struct {
	opcode   uint16
	reg      uint16
	linkWord core.Expression
}

func (b *regOp) Assemble(s *core.AssemblyState) {
	s.Push(0x0020 | (b.opcode << 3) | b.reg)
	if b.opcode == regOpcodes["lnk"] {
		s.Push(core.Evaluate16(b.linkWord, s))
	}
}

var regOpcodes = map[string]uint16{
	"lnk": 0,
	"ulk": 1,
	"hwn": 2,
	"hwq": 3,
}

type nullaryOp struct {
	opcode uint16
}

func (b *nullaryOp) Assemble(s *core.AssemblyState) {
	s.Push(b.opcode)
}

var nullaryOpcodes = map[string]uint16{
	"nop": 0,
	"rfi": 1,
	"brk": 2,
	"hlt": 3,
}

type unaryBranchOp struct {
	opcode    uint16
	longwords bool
	dst       operand
	target    core.Expression
}

func (b *unaryBranchOp) Assemble(s *core.AssemblyState) {
	word := b.opcode
	if b.longwords {
		word |= 0x10 // Not the usual position for the L bit.
	}
	s.Push(word)

	bits := b.dst.Encode(s)
	s.Push(bits.eaField() | buildBranchWord(s, len(bits.extraWords), b.target))
	bits.assembleExtras(s)
}

func buildBranchWord(s *core.AssemblyState, extras int, target core.Expression) uint16 {
	var branchWord uint16

	if target != nil {
		// This is a branch, so compute the target.
		// Branch target is relative to PC after the end of this whole instruction.
		// s.Index is aimed at where the branch word will go, right now.
		base := int(s.Index()) + 1 + extras
		value := target.Evaluate(s)
		diff := int32(value) - int32(base)

		// There's only 10 bits available for the signed value, -512 to 511.
		if diff < -512 || diff > 511 {
			core.AsmError(target.Location(), "branch target is too far away (%d words), use skip + set pc instead", diff)
		}

		branchWord |= (uint16(diff & 0x3ff)) << 6
	}

	return branchWord
}

var unaryBranchOpcodes = map[string]uint16{
	"bzr":  8,
	"bnz":  9,
	"bps":  10,
	"bng":  11,
	"bzrd": 12,
	"bnzd": 13,
	"bpsd": 14,
	"bngd": 15,
	"szr":  8,
	"snz":  9,
	"sps":  10,
	"sng":  11,
	"szrd": 12,
	"snzd": 13,
	"spsd": 14,
	"sngd": 15,
}

type binaryBranchOp struct {
	opcode    uint16
	longwords bool
	left      operand
	right     operand
	target    core.Expression
}

func (b *binaryBranchOp) Assemble(s *core.AssemblyState) {
	leftBits := b.left.Encode(s)
	rightBits := b.right.Encode(s)
	word := 0x0c00 | (b.opcode << 7) | leftBits.eaField()
	if b.longwords {
		word |= lFlag
	}
	s.Push(word)
	extras := len(leftBits.extraWords) + len(rightBits.extraWords)
	s.Push(rightBits.eaField() | buildBranchWord(s, extras, b.target))
	rightBits.assembleExtras(s)
	leftBits.assembleExtras(s)
}

var binaryBranchOpcodes = map[string]uint16{
	"brb": 0,
	"brc": 1,
	"bre": 2,
	"brn": 3,
	"brg": 4,
	"bra": 5,
	"brl": 6,
	"bru": 7,
	"ifb": 0,
	"ifc": 1,
	"ife": 2,
	"ifn": 3,
	"ifg": 4,
	"ifa": 5,
	"ifl": 6,
	"ifu": 7,
}

type setOp struct {
	longwords bool
	src       operand
	dst       operand
}

func (b *setOp) Assemble(s *core.AssemblyState) {
	srcBits := b.src.Encode(s)
	dstBits := b.dst.Encode(s)
	word := 0x2000 | (dstBits.eaField() << 6) | srcBits.eaField()
	if b.longwords {
		word |= 0x1000 // Not the usual spot.
	}

	s.Push(word)
	srcBits.assembleExtras(s)
	dstBits.assembleExtras(s)
}

type leaOp struct {
	reg uint16
	src operand
}

func (b *leaOp) Assemble(s *core.AssemblyState) {
	srcBits := b.src.Encode(s)
	s.Push(0xc000 | (b.reg << 8) | srcBits.eaField())
	srcBits.assembleExtras(s)
}
