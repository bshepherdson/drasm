package core

import (
	"fmt"
	"strconv"

	"github.com/shepheb/psec"
)

// Wrap the most common parser ops for brevity.
func lit(s string) psec.Parser {
	return psec.Literal(s)
}
func litIC(s string) psec.Parser {
	return psec.LiteralIC(s)
}
func sym(s string) psec.Parser {
	return psec.Symbol(s)
}
func ws() psec.Parser {
	return psec.Symbol("ws")
}

func addExprParsers(g *psec.Grammar) {
	// Expressions
	g.WithAction("unaryOp", psec.OneOf("+-~"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return OperatorNames[string((r.(byte)))], nil
		})
	g.WithAction("addOp", psec.OneOf("+-|^"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return OperatorNames[string((r.(byte)))], nil
		})
	g.WithAction("mulOp",
		psec.Alt(psec.OneOf("*/&"), lit("<<"), lit(">>")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			switch rr := r.(type) {
			case string:
				if rr == "<<" {
					return LANGLES, nil
				}
				return RANGLES, nil
			case byte:
				return OperatorNames[string(rr)], nil
			}
			return nil, fmt.Errorf("can't happen: unrecognized mulOp %v", r)
		})

	g.WithAction("expr",
		psec.Seq(sym("expr1"),
			psec.Many(psec.Seq(ws(), sym("addOp"), ws(), sym("expr1")))),
		binaryAction)

	g.WithAction("expr1",
		psec.Seq(sym("expr2"),
			psec.Many(psec.Seq(ws(), sym("mulOp"), ws(), sym("expr2")))),
		binaryAction)

	g.WithAction("expr2",
		psec.Seq(psec.Optional(psec.SeqAt(0, sym("unaryOp"), ws())), sym("expr3")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			rs := r.([]interface{})
			if rs[0] == nil {
				return rs[1], nil
			}

			return Unary(rs[0].(Operator), rs[1].(Expression)), nil
		})

	g.AddSymbol("expr3", psec.Alt(sym("label_use"), sym("literal"),
		psec.SeqAt(2, lit("("), ws(), sym("expr"), ws(), lit(")"))))

	g.WithAction("label_use", sym("identifier"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return UseLabel(r.(string), loc), nil
		})

	// TODO: hex and binary literals, maybe character literals?
	g.WithAction("hex literal",
		psec.SeqAt(1, litIC("0x"), psec.Stringify(psec.Many1(sym("hex digit")))),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			i, err := strconv.ParseInt(r.(string), 16, 32)
			if err != nil {
				return nil, fmt.Errorf("failed to parse integer literal '%s': %v", r, err)
			}

			if i > 65535 {
				return nil, fmt.Errorf("numeric literal %x is too big for 16-bit value", i)
			}
			return &Constant{Value: uint16(i), Loc: loc}, nil
		})
	g.AddSymbol("hex digit", psec.Alt(psec.Range('0', '9'), psec.Range('a', 'f'),
		psec.Range('A', 'F')))

	g.WithAction("decimal literal", psec.Stringify(psec.Many1(psec.Range('0', '9'))),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			i, err := strconv.ParseInt(r.(string), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("failed to parse integer literal '%s': %v", r, err)
			}

			if i > 65535 {
				return nil, fmt.Errorf("numeric literal %d is too big for 16-bit value", i)
			}
			return &Constant{Value: uint16(i), Loc: loc}, nil
		})

	g.AddSymbol("literal", psec.Alt(sym("hex literal"), sym("decimal literal")))
}

func binaryAction(r interface{}, loc *psec.Loc) (interface{}, error) {
	rs := r.([]interface{})
	expr := rs[0].(Expression)

	tail := rs[1].([]interface{})
	for _, tailChunk := range tail {
		seq := tailChunk.([]interface{})
		op := seq[1].(Operator)
		rhs := seq[3].(Expression)
		expr = Binary(expr, op, rhs)
	}

	return expr, nil
}
