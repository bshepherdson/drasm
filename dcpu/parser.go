package dcpu

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/shepheb/drasm/core"
	"github.com/shepheb/psec"
)

var regNumbers map[byte]int = map[byte]int{
	'A': 0,
	'B': 1,
	'C': 2,
	'X': 3,
	'Y': 4,
	'Z': 5,
	'I': 6,
	'J': 7,
	'a': 0,
	'b': 1,
	'c': 2,
	'x': 3,
	'y': 4,
	'z': 5,
	'i': 6,
	'j': 7,
}

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

func binaryAction(r interface{}, loc *psec.Loc) (interface{}, error) {
	rs := r.([]interface{})
	expr := rs[0].(core.Expression)

	tail := rs[1].([]interface{})
	for _, tailChunk := range tail {
		seq := tailChunk.([]interface{})
		op := seq[1].(core.Operator)
		rhs := seq[3].(core.Expression)
		expr = core.Binary(expr, op, rhs)
	}

	return expr, nil
}

func buildDcpuParser() *psec.Grammar {
	g := psec.NewGrammar()
	g.AddSymbol("START", sym("reg"))
	g.AddSymbol("ws", psec.ManyDrop(psec.OneOf(" \t\r\n")))
	g.AddSymbol("ws1", psec.Many1(psec.OneOf(" \t\r\n")))

	addArgParsers(g)
	g.AddSymbol("letterish",
		psec.Alt(psec.OneOf("$_"), psec.Range('a', 'z'), psec.Range('A', 'Z')))
	g.WithAction("identifier", psec.Seq(sym("letterish"),
		psec.Stringify(psec.Many(psec.Alt(psec.Range('0', '9'), sym("letterish"))))),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			rs := r.([]interface{})
			return fmt.Sprintf("%c%s", rs[0].(byte), rs[1].(string)), nil
		})

	return g
}

func addArgParsers(g *psec.Grammar) {
	// Registers in expressions
	g.WithAction("reg", psec.OneOf("ABCXYZIJabcxyzij"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &arg{reg: regNumbers[r.(byte)]}, nil
		})

	g.WithAction("[reg]",
		psec.SeqAt(2, lit("["), ws(), sym("reg"), ws(), lit("]")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			reg := r.(*arg)
			reg.indirect = true
			return reg, nil
		})

	// Special registers
	g.WithAction("sp", litIC("sp"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &arg{special: 0x1b}, nil
		})
	g.WithAction("pc", litIC("pc"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &arg{special: 0x1c}, nil
		})
	g.WithAction("ex", litIC("ex"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &arg{special: 0x1d}, nil
		})
	g.WithAction("peek", psec.Alt(litIC("peek"), litIC("[sp]")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &arg{special: 0x19}, nil
		})
	g.WithAction("pushPop",
		psec.Alt(litIC("push"), litIC("pop"), litIC("[--sp]"), litIC("[sp++]")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &arg{special: 0x18}, nil
		})
	g.AddSymbol("specialArgs",
		psec.Alt(sym("sp"), sym("pc"), sym("ex"), sym("pushPop"), sym("peek")))

	addExprParsers(g)

	// Also handles [SP + foo] syntax for PICK.
	g.WithAction("[reg+index]",
		psec.Seq(lit("["), ws(), psec.Alt(sym("reg"), litIC("sp")), ws(),
			sym("unaryOp"), ws(), sym("expr"), ws(), lit("]")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			rs := r.([]interface{})
			var a *arg
			if reg, ok := rs[2].(*arg); ok {
				a = reg
			} else if sp, ok := rs[2].(string); ok && strings.ToLower(sp) == "sp" {
				a = &arg{special: 0x1a}
			}

			op := rs[4].(core.Operator)
			index := rs[6].(core.Expression)

			if op == core.NOT {
				// Not actually legal to use ~, I'm just abusing the unaryOp for + and -
				return nil, fmt.Errorf("expected + or -, or ], not ~")
			}

			if op == core.MINUS {
				index = core.Unary(core.MINUS, index)
			}

			return &arg{
				// One of these two is set
				reg:      a.reg,
				special:  a.special,
				indirect: true,
				offset:   index,
			}, nil
		})

	g.WithAction("pick", psec.SeqAt(2, litIC("pick"), sym("ws1"), sym("expr")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &arg{special: 0x1a, offset: r.(core.Expression)}, nil
		})

	g.WithAction("[lit]", psec.SeqAt(2, lit("["), ws(), sym("expr"), ws(), lit("]")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &arg{special: 0x1e, indirect: true, offset: r.(core.Expression)}, nil
		})
	g.WithAction("lit arg", sym("expr"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &arg{special: 0x1f, offset: r.(core.Expression)}, nil
		})

	g.AddSymbol("arg", psec.Alt(
		sym("reg"), sym("[reg]"), sym("[reg+index]"),
		sym("specialArgs"), sym("pick"),
		sym("[lit]"), sym("lit arg")))
}

func addExprParsers(g *psec.Grammar) {
	// Expressions
	g.WithAction("unaryOp", psec.OneOf("+-~"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return core.OperatorNames[string((r.(byte)))], nil
		})
	g.WithAction("addOp", psec.OneOf("+-|^"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return core.OperatorNames[string((r.(byte)))], nil
		})
	g.WithAction("mulOp",
		psec.Alt(psec.OneOf("*/&"), lit("<<"), lit(">>")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			switch rr := r.(type) {
			case string:
				if rr == "<<" {
					return core.LANGLES, nil
				}
				return core.RANGLES, nil
			case byte:
				return core.OperatorNames[string(rr)], nil
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

			return core.Unary(rs[0].(core.Operator), rs[1].(core.Expression)), nil
		})

	g.AddSymbol("expr3", psec.Alt(sym("label_use"), sym("literal"),
		psec.SeqAt(2, lit("("), ws(), sym("expr"), ws(), lit(")"))))

	g.WithAction("label_use", sym("identifier"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return core.UseLabel(r.(string), loc), nil
		})

	// TODO: hex and binary literals, maybe character literals?
	g.WithAction("literal", psec.Stringify(psec.Many1(psec.Range('0', '9'))),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			i, err := strconv.ParseInt(r.(string), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("failed to parse integer literal '%s': %v", r, err)
			}

			if i > 65535 {
				return nil, fmt.Errorf("numeric literal %d is too big for 16-bit value", i)
			}
			return &core.Constant{Value: uint16(i), Loc: loc}, nil
		})
}
