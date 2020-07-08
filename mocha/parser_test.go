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
