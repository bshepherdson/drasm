package mocha

import (
	"testing"

	"github.com/shepheb/drasm/core"
	"github.com/shepheb/psec"
)

func setup() *psec.Grammar {
	core.SetDriver(&Driver{})
	return buildMochaParser()
}

var mp = setup()

func loc(line, col int) *psec.Loc {
	return &psec.Loc{Filename: "test", Line: line, Col: col}
}

func locCol(col int) *psec.Loc {
	return loc(1, col)
}

func constAt(value uint32, col int) core.Expression {
	return &core.Constant{Value: value, Loc: locCol(col)}
}

// Slight hack: making *operandBits itself define the operand interface, so I
// can supply a literal operandBits to expectAM for testing.
func (bits *operandBits) Encode(s *core.AssemblyState) *operandBits {
	return bits
}

func (bits *operandBits) HasEffectiveAddress() bool {
	return false
}

func (bits *operandBits) ErrLabel() string {
	return "raw bits for testing"
}

func expectAM(t *testing.T, input string, expected operand) {
	res, err := mp.ParseStringWith("test", input, "operand")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if op, ok := res.(operand); ok {
		actualBits := op.Encode(&core.AssemblyState{})
		expectedBits := expected.Encode(&core.AssemblyState{})

		if actualBits.mode != expectedBits.mode {
			t.Errorf("expected mode %d got %d", expectedBits.mode, actualBits.mode)
		}
		if actualBits.regField != expectedBits.regField {
			t.Errorf("expected mode %d got %d", expectedBits.mode, actualBits.mode)
		}

		if len(actualBits.extraWords) != len(expectedBits.extraWords) {
			t.Errorf("expected %d extra words, got %d", len(expectedBits.extraWords),
				len(actualBits.extraWords))
		}

		for i, w := range expectedBits.extraWords {
			if w != actualBits.extraWords[i] {
				t.Errorf("expected extraWords[%d] to be %d got %d", i, w, actualBits.extraWords[i])
			}
		}
	}
}

func TestRegDirect(t *testing.T) {
	expectAM(t, "A", regDirect(0))
	expectAM(t, "b", regDirect(1))
	expectAM(t, "y", regDirect(4))
	expectAM(t, "J", regDirect(7))
}

func TestRegIndirect(t *testing.T) {
	expectAM(t, "[A]", &regSimple{reg: 0, mode: rmIndirect})
	expectAM(t, "[ x  ]", &regSimple{reg: 3, mode: rmIndirect})
}

func TestRegIncrement(t *testing.T) {
	expectAM(t, "-[B]", &regSimple{reg: 1, mode: rmPredecrement})
	expectAM(t, "[B]+", &regSimple{reg: 1, mode: rmPostincrement})
	expectAM(t, "[B ] +", &regSimple{reg: 1, mode: rmPostincrement})
}

func TestRegOffset(t *testing.T) {
	expectAM(t, "[A + 6]", &regOffset{reg: 0, offset: constAt(6, 5)})
	expectAM(t, "[A-18 + 6]", &regOffset{
		reg:    0,
		offset: core.Unary(core.MINUS, core.Binary(constAt(18, 3), core.PLUS, constAt(6, 8))),
	})
}

func TestRegIndex(t *testing.T) {
	expectAM(t, "[A, B]", &regIndexed{reg: 0, index: 1})
	expectAM(t, "[C   ,J]", &regIndexed{reg: 2, index: 7})
}

func TestSpecials(t *testing.T) {
	expectAM(t, "SP", &specialReg{sp: true})
	expectAM(t, "pc", &specialReg{pc: true})
	expectAM(t, "IA", &specialReg{ia: true})
	expectAM(t, "EX", &specialReg{ex: true})
}

func TestPushPopPeek(t *testing.T) {
	expectAM(t, "[SP]", &spRel{})
	expectAM(t, "PEEK", &spRel{})
	expectAM(t, "pop", &spRel{adjustSP: true})
	expectAM(t, "PUSH", &spRel{adjustSP: true})
	expectAM(t, "-[SP]", &spRel{adjustSP: true})
	expectAM(t, "[SP]+", &spRel{adjustSP: true})
}

func TestSPOffset(t *testing.T) {
	expectAM(t, "[SP + 6]", &spRel{offset: constAt(6, 6)})
	expectAM(t, "[SP-18 + 6]", &spRel{
		offset: core.Unary(core.MINUS, core.Binary(constAt(18, 4), core.PLUS, constAt(6, 9))),
	})
}

func TestPCRelative(t *testing.T) {
	expectAM(t, "[PC, B]", &pcRel{reg: 1})
	expectAM(t, "[PC+0]", &pcRel{offset: constAt(0, 4)})
}

func TestImmediates(t *testing.T) {
	expectAM(t, "[17 + 9]", &immediate{value: constAt(26, 1), indirect: true})
	expectAM(t, "17 + 9", &immediate{value: constAt(26, 0), indirect: false})

	// 32-bit literals
	expectAM(t, "[120000]", &immediate{value: constAt(120000, 1), indirect: true})
	expectAM(t, "120000", &immediate{value: constAt(120000, 1), indirect: false})

	// And the special cases for 0 and 1.
	expectAM(t, "1", &operandBits{mode: 6, regField: 7})
	expectAM(t, "0", &operandBits{mode: 6, regField: 6})
}

func expectOp(t *testing.T, rule, input string, expected []uint16) {
	res, err := mp.ParseStringWith("test", input, rule)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	ast := &core.AST{Lines: []core.Assembled{res.(core.Assembled)}}
	actual := core.AssembleAst(ast)

	if len(actual) != len(expected) {
		t.Errorf("expected %d assembled words, got %d", len(expected), len(actual))
	}

	for i, w := range expected {
		if w != actual[i] {
			t.Errorf("expected word %d of the assembly to be %04x, but got %04x",
				i, w, actual[i])
		}
	}
}

func expectError(t *testing.T, rule, input string) {
	_, err := mp.ParseStringWith("test", input, rule)
	if err == nil {
		t.Errorf("expected error, but got nil")
	}
}

func TestBinaryInstructions(t *testing.T) {
	expectOp(t, "binary instruction", "add.w a, b", []uint16{0x4001})
	expectOp(t, "binary instruction", "add.w a, [b]", []uint16{0x4009})
	expectOp(t, "binary instruction", "add.w [a], b", []uint16{0x4188})
	expectOp(t, "binary instruction", "add.l [a], b", []uint16{0x41c8})
	// Prefer the regular binary encoding where practical.
	expectOp(t, "binary instruction", "add.w a, 3", []uint16{0x403a, 3})
	expectOp(t, "binary instruction", "add.w a, -3", []uint16{0x403a, 0xfffd})
	// But if it's an  operand and literal, expect the immediate form.
	expectOp(t, "binary instruction",
		"add.w [a], -3", []uint16{0x0088, 0xfffd})
	expectOp(t, "binary instruction",
		"add.l [a], -3", []uint16{0x00c8, 0xffff, 0xfffd})

	// It fails if both are non-immediate operands.
	expectError(t, "binary instruction", "add.l [a], [3]")
	// Or if the binary op doesn't have an immediate version.
	expectError(t, "binary instruction", "shl.w [a], 3")
}

func TestBitTwiddlers(t *testing.T) {
	expectOp(t, "twiddler instruction",
		"btx.w [123], 9", []uint16{0x0438, 9, 123})
	expectOp(t, "twiddler instruction",
		"btc.l [123], b", []uint16{0x0778, 1, 123})
}

func TestUnaryOps(t *testing.T) {
	expectOp(t, "unary instruction", "neg.w b", []uint16{0x0981})
	expectOp(t, "unary instruction", "log.l [pc, c]", []uint16{0x0b7d, 2})
	expectOp(t, "unary instruction", "pea [pc, c]", []uint16{0x087d, 2})
	expectError(t, "unary instruction", "pea c")
}

func TestRegOps(t *testing.T) {
	expectOp(t, "reg instruction", "hwn x", []uint16{0x0033})
	expectOp(t, "reg instruction", "lnk x, 212", []uint16{0x0023, 212})
	expectError(t, "reg instruction", "lnk b")
	expectError(t, "reg instruction", "hwn b, 1")
}

func TestUnaryBranchOps(t *testing.T) {
	expectOp(t, "branch instruction", "bzr.l a, 90",
		[]uint16{0x0018, 88 << 6})
	expectOp(t, "branch instruction", "bzr.w [sp + 7], 90",
		[]uint16{0x0008, (87 << 6) | 0x3e, 7})
	expectOp(t, "branch instruction", "bzrd.w [sp + 7], 90",
		[]uint16{0x000c, (87 << 6) | 0x3e, 7})

	expectOp(t, "branch instruction", "sps.l [9]", []uint16{0x001a, 0x0038, 9})
	expectOp(t, "branch instruction", "sng.w ex", []uint16{0x000b, 0x0032})
}

func TestBinaryBranchOps(t *testing.T) {
	expectOp(t, "branch instruction", "ifn.l c, b", []uint16{0x0dc2, 0x0001})
	expectOp(t, "branch instruction", "brb.w [190000], [x, y], 90",
		[]uint16{0x0c39, 85<<6 | 0x2b, 4, core.HighWord(190000), core.LowWord(190000)})
}

func TestSetOps(t *testing.T) {
	expectOp(t, "instruction", "set.w c, b", []uint16{0x2081})
	expectOp(t, "instruction", "set.l [c], [b]", []uint16{0x3289})
	expectOp(t, "instruction", "set.w [c+1], [200000]",
		[]uint16{0x28b9, core.HighWord(200000), core.LowWord(200000), 1})
	expectOp(t, "instruction", "set.w c, [200000]",
		[]uint16{0x20b9, core.HighWord(200000), core.LowWord(200000)})

	expectOp(t, "instruction", "lea c, [200000]",
		[]uint16{0xc239, core.HighWord(200000), core.LowWord(200000)})
	expectOp(t, "instruction", "lea c, [pc, x]",
		[]uint16{0xc23d, 3})
	expectError(t, "instruction", "lea c, 200")
	expectError(t, "instruction", "lea c, x")
}
