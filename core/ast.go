package core

import (
	"fmt"
	"os"

	"github.com/shepheb/psec"
)

func Fits16(x uint32) bool {
	return x < 0x10000
}

func Fits16Signed(x uint32) bool {
	s := int32(x)
	return -32768 <= s && s <= 32767
}

func HighWord(x uint32) uint16 {
	return uint16(x >> 16)
}
func LowWord(x uint32) uint16 {
	return uint16(x)
}

// AST captures a complete syntax tree for an assembled file.
type AST struct {
	Lines []Assembled
}

func (a *AST) Assemble(s *AssemblyState) {
	for _, line := range a.Lines {
		line.Assemble(s)
	}
}

// Expression evaluates to a number, and keeps track of its location for error
// messages.
type Expression interface {
	Evaluate(s *AssemblyState) uint32
	Location() *psec.Loc
	Equals(expr Expression) bool
}

// LabelUse is a kind of expression.
// It might be a real label, or a define.
type LabelUse struct {
	label string
	loc   *psec.Loc
}

func Evaluate16(e Expression, s *AssemblyState) uint16 {
	value := e.Evaluate(s)
	if Fits16(value) || Fits16Signed(value) {
		return LowWord(value)
	}
	AsmError(e.Location(), "expression value does not fit in 16 bits: %d ($%x)", value)
	return 0
}

// UseLabel constructs a LabelUse AST node for where a label is used.
func UseLabel(label string, loc *psec.Loc) *LabelUse {
	return &LabelUse{label: label, loc: loc}
}

// Evaluate resolves the value of a label when it appears in an expression.
func (l *LabelUse) Evaluate(s *AssemblyState) uint32 {
	value, _, known := s.lookup(l.label)
	if !known {
		AsmError(l.loc, "Unknown label '%s'", l.label)
		os.Exit(1)
	}
	return value
}

// Location for a LabelUse
func (l *LabelUse) Location() *psec.Loc { return l.loc }

// Equals for LabelUse
func (l *LabelUse) Equals(expr Expression) bool {
	l2, ok := expr.(*LabelUse)
	return ok && l.label == l2.label
}

// Constant is a fixed-value Expression.
type Constant struct {
	Value uint32
	Loc   *psec.Loc
}

// Evaluate for Constant: return the value.
func (c *Constant) Evaluate(s *AssemblyState) uint32 { return c.Value }

// Location for Constant
func (c *Constant) Location() *psec.Loc { return c.Loc }

// Equals for Constant
func (c *Constant) Equals(expr Expression) bool {
	c2, ok := expr.(*Constant)
	return ok && c.Value == c2.Value
}

// BinExpr represents a binary express, such as addition.
type BinExpr struct {
	lhs      Expression
	operator Operator
	rhs      Expression
}

// Binary constructs a binary expression AST node.
func Binary(lhs Expression, op Operator, rhs Expression) *BinExpr {
	return &BinExpr{lhs, op, rhs}
}

// Evaluate for BinExpr recursively computes the left and right sides and
// performs the operation.
func (b *BinExpr) Evaluate(s *AssemblyState) uint32 {
	l := b.lhs.Evaluate(s)
	r := b.rhs.Evaluate(s)
	switch b.operator {
	case PLUS:
		return l + r
	case MINUS:
		return l - r
	case TIMES:
		return l * r
	case DIVIDE:
		return l / r
	case AND:
		return l & r
	case OR:
		return l | r
	case XOR:
		return l ^ r
	default:
		panic(fmt.Sprintf("unknown binary operation"))
	}
}

// Location for BinExpr
func (b *BinExpr) Location() *psec.Loc {
	return b.lhs.Location()
}

// Equals for BinExpr
func (b *BinExpr) Equals(expr Expression) bool {
	b2, ok := expr.(*BinExpr)
	return ok && b.lhs.Equals(b2.lhs) && b.rhs.Equals(b2.rhs) &&
		b.operator == b2.operator
}

// UnaryExpr captures a unary expression. There aren't as many of these, but
// there are unary + and -, and unary bitwise NOT.
type UnaryExpr struct {
	operator Operator
	expr     Expression
}

// Unary constructs a unary expression AST node.
func Unary(operator Operator, expr Expression) *UnaryExpr {
	return &UnaryExpr{operator, expr}
}

// Evaluate for UnaryExpr
func (u *UnaryExpr) Evaluate(s *AssemblyState) uint32 {
	value := u.expr.Evaluate(s)
	switch u.operator {
	case PLUS:
		return value
	case MINUS:
		return -value
	case NOT:
		return 0xffffffff ^ value
	default:
		panic(fmt.Sprintf("unknown unary operation"))
	}
}

// Location for UnaryExpr uses the inner expression's location.
func (u *UnaryExpr) Location() *psec.Loc { return u.expr.Location() }

// Equals for UnaryExpr
func (u *UnaryExpr) Equals(expr Expression) bool {
	u2, ok := expr.(*UnaryExpr)
	return ok && u.expr.Equals(u2.expr) && u.operator == u2.operator
}

// Assembled describes something that can be assembled into the binary,
// such as an instruction, and some directives.
type Assembled interface {
	Assemble(s *AssemblyState)
}

// Include directive giving a filename.
type Include struct{ filename string }

// Assemble for Include is impossible - it should have been resolved at parse
// time.
func (i *Include) Assemble(s *AssemblyState) {
	panic("can't happen! Include survived to assembly time")
}

// Org directives set the destination of all following assembled code.
type Org struct{ Abs Expression }

// Assemble for Org moves the state's index.
func (o *Org) Assemble(s *AssemblyState) {
	s.index = o.Abs.Evaluate(s)
}

// SymbolDef defines an assembler constant. Symbols can be overridden.
type SymbolDef struct {
	name  string
	value Expression
}

// DefineSymbol constructs a SymbolDef node, for a .define directive.
func DefineSymbol(name string, value Expression) *SymbolDef {
	return &SymbolDef{name, value}
}

func (sd *SymbolDef) Compare(name string, value Expression) bool {
	if sd.name != name {
		return false
	}
	return sd.value.Equals(value)
}

// Assemble for SymbolDef recomputes the value of the symbol, in case it has
// changed.
func (d *SymbolDef) Assemble(s *AssemblyState) {
	s.updateSymbol(d.name, d.value.Evaluate(s))
}

// DatBlock is a sequence of expressions to be assembled literally.
type DatBlock struct{ Values []Expression }

// Assemble for DatBlock: evaluate and write each one.
func (b *DatBlock) Assemble(s *AssemblyState) {
	for _, v := range b.Values {
		value := v.Evaluate(s)
		if !Fits16(value) && !Fits16Signed(value) {
			AsmError(v.Location(), "Dat value does not fit in a single word: %d", value)
			break
		}
		s.Push(LowWord(value))
	}
}

// FillBlock is a shorthand for writing the same literal many times.
type FillBlock struct {
	Length Expression
	Value  Expression
}

// Assemble for FillBlock: compute the expression's value, write it N times.
func (b *FillBlock) Assemble(s *AssemblyState) {
	len := b.Length.Evaluate(s)
	val := b.Value.Evaluate(s)
	for i := uint32(0); i < len; i++ {
		s.Push(LowWord(val))
	}
}

// LabelDef is issued when a new label is defined with :foo.
// Note that redefining a label is an error.
type LabelDef struct {
	Label string
	loc   *psec.Loc
}

// DefineLabel constructs a new LabelDef with the given name.
func DefineLabel(label string, loc *psec.Loc) *LabelDef {
	return &LabelDef{Label: label, loc: loc}
}

// Assemble for LabelDef: update the value of the label to the current index,
// since reassembling the above code might have moved it.
func (l *LabelDef) Assemble(s *AssemblyState) {
	// Labels are collected in an earlier pass, but we need to note the current
	// index as its value.
	s.updateLabel(l.Label, s.index)
}

type MacroDef struct {
	name string
	body string
}

func (m *MacroDef) Assemble(s *AssemblyState) {
	// Update the cached definitions, so we get the current one.
	addMacro(m.name, m.body)
}

type MacroUse struct {
	macro string
	args  []string
}

func (m *MacroUse) Assemble(s *AssemblyState) {
	text, err := doMacro(s, m.macro, m.args)
	if err != nil {
		panic(fmt.Sprintf("broken macro: %v", err))
	}

	parsed, err := currentDriver.ParseString("macro", text)
	if err != nil {
		// TODO Errors from Assemble? Probably wise.
		panic(fmt.Sprintf("failed to parse macro result: %v", err))
	}

	for _, asm := range parsed.Lines {
		asm.Assemble(s)
	}
}
