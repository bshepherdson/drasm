package dcpu

import (
	"fmt"
	"testing"

	"github.com/shepheb/drasm/core"
	"github.com/shepheb/psec"
)

var dp = buildDcpuParser()

func expectArg(t *testing.T, g *psec.Grammar, startSym, input string, exp *arg) {
	res, err := g.ParseStringWith("test", input, startSym)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if r, ok := res.(*arg); ok {
		if r == nil {
			t.Errorf("failed to parse arg, got nil")
		} else if r.reg != exp.reg {
			t.Errorf("expected arg register %d, got %d", exp.reg, r.reg)
		} else if r.indirect != exp.indirect {
			t.Errorf("expected arg to be indirect=%t, got %t", exp.indirect, r.indirect)
		} else if r.offset != nil && exp.offset != nil && !r.offset.Equals(exp.offset) {
			t.Errorf("expected arg offset %#v, got %#v", exp.offset, r.offset)
		} else if r.special != exp.special {
			t.Errorf("expected special arg %d, got %d", exp.special, r.special)
		}
	} else {
		t.Errorf("expected *arg value, got %T", res)
	}
}

func expectError(t *testing.T, g *psec.Grammar, startSym, input, expected string) {
	_, err := g.ParseStringWith("test", input, startSym)
	if err == nil {
		t.Errorf("expected error")
	} else if err.Error() != fmt.Sprintf("test line 1 col 0: %s", expected) {
		t.Errorf("error mismatch, got %v", err)
	}
}

func TestReg(t *testing.T) {
	expectArg(t, dp, "reg", "A", &arg{reg: 0})
	expectArg(t, dp, "reg", "x", &arg{reg: 3})
	expectError(t, dp, "reg", "D", "expected one of: ABCXYZIJabcxyzij")
}

func TestRegIndirect(t *testing.T) {
	expectArg(t, dp, "[reg]", "[a]", &arg{reg: 0, indirect: true})
	expectArg(t, dp, "[reg]", "[Z]", &arg{reg: 5, indirect: true})
	expectError(t, dp, "[reg]", "[D]", "expected one of: ABCXYZIJabcxyzij")
}

func TestSpecials(t *testing.T) {
	expectArg(t, dp, "specialArgs", "sp", &arg{special: 0x1b})
	expectArg(t, dp, "specialArgs", "PC", &arg{special: 0x1c})
	expectArg(t, dp, "specialArgs", "EX", &arg{special: 0x1d})
	expectArg(t, dp, "specialArgs", "[--sp]", &arg{special: 0x18})
	expectArg(t, dp, "specialArgs", "[sp++]", &arg{special: 0x18})
	expectArg(t, dp, "specialArgs", "push", &arg{special: 0x18})
	expectArg(t, dp, "specialArgs", "pop", &arg{special: 0x18})
	expectArg(t, dp, "specialArgs", "peek", &arg{special: 0x19})
	expectArg(t, dp, "specialArgs", "[sp]", &arg{special: 0x19})
}

func expectExpr(t *testing.T, g *psec.Grammar, startSym, input string, expr core.Expression) {
	res, err := g.ParseStringWith("test", input, startSym)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if r, ok := res.(core.Expression); ok {
		if r == nil {
			t.Errorf("failed to parse expression, got nil")
		} else if !expr.Equals(r) {
			t.Errorf("expected expression %#v, got %#v", expr, r)
		}
	} else {
		t.Errorf("expected expression, but got %T", res)
	}
}

func TestLiteral(t *testing.T) {
	expectExpr(t, dp, "literal", "7", &core.Constant{Value: 7})
	expectExpr(t, dp, "literal", "0", &core.Constant{Value: 0})
	expectExpr(t, dp, "literal", "12345", &core.Constant{Value: 12345})
	expectExpr(t, dp, "literal", "65535", &core.Constant{Value: 65535})
	expectError(t, dp, "literal", "876543",
		"numeric literal 876543 is too big for 16-bit value")
}

var testLoc = &psec.Loc{Filename: "test", Line: 1, Col: 0}
var expr712 core.Expression = &core.Constant{Value: 712, Loc: testLoc}

// We test expr3 later because it can contain subexpressions.
func TestExpr2(t *testing.T) {
	expectExpr(t, dp, "expr2", "foo", core.UseLabel("foo", testLoc))
	expectExpr(t, dp, "expr2", "712", expr712)
	expectExpr(t, dp, "expr2", "+712", core.Unary(core.PLUS, expr712))
	expectExpr(t, dp, "expr2", "-712", core.Unary(core.MINUS, expr712))
	expectExpr(t, dp, "expr2", "-  712", core.Unary(core.MINUS, expr712))
	expectExpr(t, dp, "expr2", "~712", core.Unary(core.NOT, expr712))
}

func locCol(col int) *psec.Loc {
	return &psec.Loc{Filename: "test", Line: 1, Col: col}
}

func constAt(value uint16, col int) core.Expression {
	return &core.Constant{Value: value, Loc: locCol(col)}
}

func TestExpr1(t *testing.T) {
	expectExpr(t, dp, "expr1", "foo", core.UseLabel("foo", testLoc))
	expectExpr(t, dp, "expr1", "+712", core.Unary(core.PLUS, expr712))
	expectExpr(t, dp, "expr1", "712*foo",
		core.Binary(expr712, core.TIMES,
			core.UseLabel("foo", &psec.Loc{Filename: "test", Line: 1, Col: 4})))
	expectExpr(t, dp, "expr1", "712   >> foo",
		core.Binary(expr712, core.RANGLES,
			core.UseLabel("foo", &psec.Loc{Filename: "test", Line: 1, Col: 9})))

	// Test left-associativity
	e1 := core.Binary(constAt(1, 0), core.TIMES, constAt(2, 3))
	e2 := core.Binary(e1, core.DIVIDE, constAt(3, 9))
	e3 := core.Binary(e2, core.AND, constAt(4, 11))
	expectExpr(t, dp, "expr1", "1 *2", e1)
	expectExpr(t, dp, "expr1", "1 *2   / 3", e2)
	expectExpr(t, dp, "expr1", "1 *2   / 3&4", e3)
}

func TestExpr(t *testing.T) {
	expectExpr(t, dp, "expr", "foo", core.UseLabel("foo", testLoc))
	expectExpr(t, dp, "expr", "+712", core.Unary(core.PLUS, expr712))
	expectExpr(t, dp, "expr", "712*foo",
		core.Binary(expr712, core.TIMES, core.UseLabel("foo", locCol(4))))
	expectExpr(t, dp, "expr", "712   >> foo",
		core.Binary(expr712, core.RANGLES,
			core.UseLabel("foo", locCol(9))))

	// Test left-associativity
	left := core.Binary(constAt(1, 0), core.TIMES, constAt(2, 3))
	right := core.Binary(constAt(3, 9), core.AND, constAt(4, 11))
	plus := core.Binary(left, core.PLUS, right)
	expectExpr(t, dp, "expr", "1 *2", left)
	expectExpr(t, dp, "expr", "1 *2   + 3&4", plus)

	e4 := core.Binary(constAt(1, 0), core.PLUS, constAt(4, 5))
	e5 := core.Binary(e4, core.MINUS, core.Unary(core.MINUS, constAt(9, 10)))
	e6 := core.Binary(e5, core.MINUS, constAt(11, 14))
	expectExpr(t, dp, "expr", "1  + 4 -- 9 - 11", e6)

	// Parens to override the nesting.
	e7 := core.Binary(constAt(2, 5), core.MINUS, constAt(4, 9))
	e8 := core.Binary(constAt(7, 0), core.TIMES, e7)
	expectExpr(t, dp, "expr", "7 * (2 - 4)", e8)
}

func TestRegIndex(t *testing.T) {
	expectArg(t, dp, "[reg+index]", "[a+2]",
		&arg{reg: 0, indirect: true, offset: constAt(2, 3)})

	e1 := core.Binary(constAt(2, 7), core.TIMES, core.UseLabel("foo", locCol(9)))
	e2 := core.Unary(core.MINUS, e1)
	expectArg(t, dp, "[reg+index]", "[  j - 2*foo ]",
		&arg{reg: 7, indirect: true, offset: e2})

	expectError(t, dp, "[reg+index]", "[b ~3]", "expected + or -, or ], not ~")
}

func TestPick(t *testing.T) {
	expectArg(t, dp, "pick", "pick 9", &arg{special: 0x1a, offset: constAt(9, 5)})
	e1 := core.Binary(core.UseLabel("idx", locCol(9)), core.TIMES, constAt(4, 15))
	expectArg(t, dp, "pick", "pICk     idx * 4", &arg{special: 0x1a, offset: e1})
	expectError(t, dp, "pick", "pick0", "minimum 1") // Space is required.

	expectArg(t, dp, "[reg+index]", "[SP  + 6]",
		&arg{special: 0x1a, indirect: true, offset: constAt(6, 7)})
}

func TestLitIndirect(t *testing.T) {
	expectArg(t, dp, "[lit]", "[  8]",
		&arg{special: 0x1e, indirect: true, offset: constAt(8, 3)})
}

func TestLit(t *testing.T) {
	expectArg(t, dp, "lit arg", "8",
		&arg{special: 0x1f, indirect: false, offset: constAt(8, 0)})
}

func TestArg(t *testing.T) {
	expectArg(t, dp, "arg", "B", &arg{reg: 1})
	expectArg(t, dp, "arg", "[ y ]", &arg{reg: 4, indirect: true})
	expectArg(t, dp, "arg", "[ i+ 14]",
		&arg{reg: 6, indirect: true, offset: constAt(14, 5)})
	expectArg(t, dp, "arg", "push", &arg{special: 0x18})
	expectArg(t, dp, "arg", "POP", &arg{special: 0x18})
	expectArg(t, dp, "arg", "[--sp]", &arg{special: 0x18})
	expectArg(t, dp, "arg", "[SP++]", &arg{special: 0x18})
	expectArg(t, dp, "arg", "sp", &arg{special: 0x1b})
	expectArg(t, dp, "arg", "PC", &arg{special: 0x1c})
	expectArg(t, dp, "arg", "EX", &arg{special: 0x1d})
	expectArg(t, dp, "arg", "[12]",
		&arg{special: 0x1e, indirect: true, offset: constAt(12, 1)})

	expectArg(t, dp, "arg", "foo ^ ~7", &arg{
		special: 0x1f,
		offset: core.Binary(core.UseLabel("foo", locCol(0)), core.XOR,
			core.Unary(core.NOT, constAt(7, 7))),
	})
}
