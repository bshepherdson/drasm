package core

import (
	"fmt"
	"os"
)

// AST captures a complete syntax tree for an assembled file.
type AST struct {
	Lines []Assembled
}

// Expression evaluates to a number, and keeps track of its location for error
// messages.
type Expression interface {
	Evaluate(s *AssemblyState) uint16
	Location() string
}

// LabelUse is a kind of expression.
// It might be a real label, or a define.
type LabelUse struct {
	label string
	loc   string
}

// UseLabel constructs a LabelUse AST node for where a label is used.
func UseLabel(label, loc string) *LabelUse {
	return &LabelUse{label, loc}
}

// Evaluate resolves the value of a label when it appears in an expression.
func (l *LabelUse) Evaluate(s *AssemblyState) uint16 {
	value, _, known := s.lookup(l.label)
	if !known {
		AsmError(l.loc, "Unknown label '%s'", l.label)
		os.Exit(1)
	}
	return value
}

// Location for a LabelUse
func (l *LabelUse) Location() string { return l.loc }

// Constant is a fixed-value Expression.
type Constant struct {
	Value uint16
	Loc   string
}

// Evaluate for Constant: return the value.
func (c *Constant) Evaluate(s *AssemblyState) uint16 { return c.Value }

// Location for Constant
func (c *Constant) Location() string { return c.Loc }

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
func (b *BinExpr) Evaluate(s *AssemblyState) uint16 {
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
func (b *BinExpr) Location() string {
	return b.lhs.Location()
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
func (u *UnaryExpr) Evaluate(s *AssemblyState) uint16 {
	value := u.expr.Evaluate(s)
	switch u.operator {
	case PLUS:
		return value
	case MINUS:
		return -value
	case NOT:
		return 0xffff ^ value
	default:
		panic(fmt.Sprintf("unknown unary operation"))
	}
}

// Location for UnaryExpr uses the inner expression's location.
func (u *UnaryExpr) Location() string { return u.expr.Location() }

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
		s.Push(v.Evaluate(s))
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
	for i := uint16(0); i < len; i++ {
		s.Push(val)
	}
}

// LabelDef is issued when a new label is defined with :foo.
// Note that redefining a label is an error.
type LabelDef struct{ label string }

// DefineLabel constructs a new LabelDef with the given name.
func DefineLabel(label string) *LabelDef {
	return &LabelDef{label}
}

// Assemble for LabelDef: update the value of the label to the current index,
// since reassembling the above code might have moved it.
func (l *LabelDef) Assemble(s *AssemblyState) {
	// Labels are collected in an earlier pass, but we need to note the current
	// index as its value.
	s.updateLabel(l.label, s.index)
}
