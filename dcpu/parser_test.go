package dcpu

import (
	"fmt"
	"testing"

	"github.com/shepheb/drasm/core"
	"github.com/shepheb/psec"
)

func setup() *psec.Grammar {
	core.SetDriver(&Driver{})
	return buildDcpuParser()
}

var dp = setup()

func compareArgs(t *testing.T, exp, act *arg) {
	if act == nil {
		t.Errorf("failed to parse arg, got nil")
	} else if act.reg != exp.reg {
		t.Errorf("expected arg register %d, got %d", exp.reg, act.reg)
	} else if act.indirect != exp.indirect {
		t.Errorf("expected arg to be indirect=%t, got %t", exp.indirect, act.indirect)
	} else if act.offset != nil && exp.offset != nil && !act.offset.Equals(exp.offset) {
		t.Errorf("expected arg offset %#v, got %#v", exp.offset, act.offset)
	} else if act.special != exp.special {
		t.Errorf("expected special arg %d, got %d", exp.special, act.special)
	}
}

func expectArg(t *testing.T, g *psec.Grammar, startSym, input string, exp *arg) {
	res, err := g.ParseStringWith("test", input, startSym)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if r, ok := res.(*arg); ok {
		compareArgs(t, exp, r)
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

func loc(line, col int) *psec.Loc {
	return &psec.Loc{Filename: "test", Line: line, Col: col}
}

var testLoc = loc(1, 0)
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
	return loc(1, col)
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

func compareBinOp(t *testing.T, r interface{}, opcode uint16, b, a *arg) {
	if op, ok := r.(*binaryOp); ok {
		if op == nil {
			t.Errorf("failed to parse expression, got nil")
		} else if op.opcode != opcode {
			t.Errorf("wrong opcode: expected %d, got %d", opcode, op.opcode)
		} else {
			compareArgs(t, a, op.a)
			compareArgs(t, b, op.b)
		}
	} else {
		t.Errorf("expected *binaryOp, but got %T", r)
	}
}

func expectBinOp(t *testing.T, input string, opcode uint16, b, a *arg) {
	res, err := dp.ParseStringWith("test", input, "binary instruction")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	compareBinOp(t, res, opcode, b, a)
}

func TestBinaryInstructions(t *testing.T) {
	expectBinOp(t, "set b, a", 1, &arg{reg: 1}, &arg{reg: 0})
	expectBinOp(t, "adx [b+3], pop", 0x1a,
		&arg{reg: 1, indirect: true, offset: constAt(3, 7)},
		&arg{special: 0x18})
	expectBinOp(t, "ifg ex   ,pc", 0x14, &arg{special: 0x1d}, &arg{special: 0x1c})
}

func compareUnOp(t *testing.T, r interface{}, opcode uint16, a *arg) {
	if op, ok := r.(*unaryOp); ok {
		if op == nil {
			t.Errorf("failed to parse expression, got nil")
		} else if op.opcode != opcode {
			t.Errorf("wrong opcode: expected %d, got %d", opcode, op.opcode)
		} else {
			compareArgs(t, a, op.a)
		}
	} else {
		t.Errorf("expected *unaryOp, but got %T", r)
	}
}

func expectUnaryOp(t *testing.T, input string, opcode uint16, a *arg) {
	res, err := dp.ParseStringWith("test", input, "unary instruction")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	compareUnOp(t, res, opcode, a)
}

func TestUnaryInstructions(t *testing.T) {
	expectUnaryOp(t, "jsr somewhere", 1,
		&arg{special: 0x1f, offset: core.UseLabel("somewhere", locCol(4))})
	expectUnaryOp(t, "int 0", 8, &arg{special: 0x1f, offset: constAt(0, 4)})
	expectUnaryOp(t, "rfi pop", 11, &arg{special: 0x18})
}

func TestLabel(t *testing.T) {
	res, err := dp.ParseStringWith("test", ":foo", "label")
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
	r := res.(*core.LabelDef)
	if r == nil || r.Label != "foo" {
		t.Errorf("expected LabelDef for foo, got %#v", r)
	}
}

func TestLabeledInstruction(t *testing.T) {
	res, err := dp.ParseStringWith("test", "set b, a", "labeled instruction")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Should be a single *binaryOp for unlabeled.
	compareBinOp(t, res, 1, &arg{reg: 1}, &arg{reg: 0})

	// Now with labels
	res, err = dp.ParseStringWith("test", ":main :more set b, a", "labeled instruction")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should be an array of the two LabelDefs and the binaryOp.
	if rs, ok := res.([]interface{}); ok {
		// Check the LabelDefs
		expectLabel(t, rs[0], "main")
		expectLabel(t, rs[1], "more")
		compareBinOp(t, rs[2], 1, &arg{reg: 1}, &arg{reg: 0})
	} else {
		t.Errorf("expected a list, got %T", res)
	}
}

func expectLabel(t *testing.T, r interface{}, label string) {
	ld, ok := r.(*core.LabelDef)
	if !ok {
		t.Errorf("expected *LabelDef, got %T", r)
		return
	}

	if ld.Label != label {
		t.Errorf("label mismatch, expected %s got %s", label, ld.Label)
	}
}

func TestTrivialFile(t *testing.T) {
	ret, err := dp.ParseString("test", "set a, b")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	ast := ret.(*core.AST)
	if len(ast.Lines) != 1 {
		t.Errorf("bad line count, got %d expecting 1", len(ast.Lines))
	}

	compareBinOp(t, ast.Lines[0], 1, &arg{reg: 0}, &arg{reg: 1})
}

func TestFile(t *testing.T) {
	input := `
; Some file
.org 300
:main set a,b ; wut
rfi [a-7]

.def foo, 2
:function
adx a, pop
set [foo], b
set pc, pop`

	ret, err := dp.ParseString("test", input)
	if err != nil {
		t.Errorf("unexpected parser error: %v", err)
		return
	}

	ast, ok := ret.(*core.AST)
	if !ok {
		t.Errorf("expected *AST from ParseString, got %T", ret)
	}

	if len(ast.Lines) != 9 {
		t.Errorf("expected 9 assembled lines, got %d", len(ast.Lines))
	}

	// Item 0: .org
	if org, ok := ast.Lines[0].(*core.Org); ok {
		if !org.Abs.Equals(&core.Constant{Value: 300, Loc: loc(2, 0)}) {
			t.Errorf("bad .org expression %#v", org)
		}
	} else {
		t.Errorf("Expected item 0 to be org, got %T", ast.Lines[0])
	}

	// Item 1: label main
	if ld, ok := ast.Lines[1].(*core.LabelDef); ok {
		if ld.Label != "main" {
			t.Errorf("bad label main, got %s", ld.Label)
		}
	} else {
		t.Errorf("Expected item 1 to be LabelDef, got %T", ast.Lines[1])
	}

	// Item 2: set a, b
	compareBinOp(t, ast.Lines[2], 1, &arg{reg: 0}, &arg{reg: 1})

	// Item 3: rfi [a - 7]
	compareUnOp(t, ast.Lines[3], 11, &arg{
		reg:      0,
		indirect: true,
		offset:   core.Unary(core.MINUS, &core.Constant{Value: 7, Loc: loc(3, 7)}),
	})

	// Item 4: def foo, 2
	if def, ok := ast.Lines[4].(*core.SymbolDef); ok {
		if !def.Compare("foo", &core.Constant{Value: 2, Loc: loc(5, 100)}) {
			t.Errorf("expected SymbolDef('foo', 2), got %+v", def)
		}
	}

	// Item 5: :function label
	if ld, ok := ast.Lines[5].(*core.LabelDef); ok {
		if ld.Label != "function" {
			t.Errorf("expected label function, got %s", ld.Label)
		}
	}

	// Item 6: adx a, pop
	compareBinOp(t, ast.Lines[6], 0x1a, &arg{reg: 0}, &arg{special: 0x18})

	// Item 7: set [foo], b
	compareBinOp(t, ast.Lines[7], 1,
		&arg{special: 0x1e, indirect: true, offset: core.UseLabel("foo", loc(8, 5))},
		&arg{reg: 1})

	// Item 8: set pc, pop
	compareBinOp(t, ast.Lines[8], 1, &arg{special: 0x1c}, &arg{special: 0x18})
}
