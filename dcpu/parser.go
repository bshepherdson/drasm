package dcpu

import (
	"fmt"
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

func buildDcpuParser() *psec.Grammar {
	g := psec.NewGrammar()
	core.AddBasicParsers(g) // Adds ws, identifiers, etc.
	core.AddDirectiveParsers(g)
	core.AddExprParsers(g)

	g.AddSymbol("START", sym("file"))
	addArgParsers(g)
	addBinaryOpParsers(g)
	addUnaryOpParsers(g)
	g.AddSymbol("instruction",
		psec.Alt(sym("binary instruction"), sym("unary instruction")))

	g.AddSymbol("content",
		// This backtracking is probably slow, but I'm not sure how to do better.
		psec.Alt(sym("directive"), sym("labeled instruction"), sym("label")))

	g.WithAction("labeled instruction",
		psec.Seq(psec.Many(psec.SeqAt(0, sym("label"), sym("ws1"))), sym("instruction")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			// Returns either a single instruction, or a list of Assembled values,
			// for the labels and then the instruction.
			rs := r.([]interface{})
			if rs[0] == nil {
				return rs[1], nil
			}

			labels := rs[0].([]interface{})
			if len(labels) == 0 {
				return rs[1], nil
			}

			return append(labels, rs[1]), nil
		})

	// The preamble or postamble, whitespace and comments on either end of a file.
	g.AddSymbol("amble",
		psec.Seq(ws(), psec.Many(psec.Seq(sym("comment"), ws()))))

	g.WithAction("file",
		psec.SeqAt(1, sym("amble"), psec.SepBy(sym("content"), sym("eol")), sym("amble")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			// Comments give nil, the rest give Assembled values.
			rs := r.([]interface{})
			var asm []core.Assembled
			for _, val := range rs {
				if val != nil {
					if asms, ok := val.([]interface{}); ok {
						for _, a := range asms {
							asm = append(asm, a.(core.Assembled))
						}
					} else {
						asm = append(asm, val.(core.Assembled))
					}
				}
			}
			return &core.AST{Lines: asm}, nil
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

var binaryOpcodes = map[string]uint16{
	"set": 1,
	"add": 2,
	"sub": 3,
	"mul": 4,
	"mli": 5,
	"div": 6,
	"dvi": 7,
	"mod": 8,
	"mdi": 9,
	"and": 10,
	"bor": 11,
	"xor": 12,
	"shr": 13,
	"asr": 14,
	"shl": 15,
	"ifb": 16,
	"ifc": 17,
	"ife": 18,
	"ifn": 19,
	"ifg": 20,
	"ifa": 21,
	"ifl": 22,
	"ifu": 23,
	"adx": 0x1a,
	"sbx": 0x1b,
	"sti": 0x1e,
	"std": 0x1f,
}

func addBinaryOpParsers(g *psec.Grammar) {
	var opcodes []psec.Parser
	for op := range binaryOpcodes {
		opcodes = append(opcodes, litIC(op))
	}
	g.WithAction("binary opcode", psec.Alt(opcodes...),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return binaryOpcodes[r.(string)], nil
		})

	g.WithAction("binary instruction",
		psec.Seq(sym("binary opcode"), sym("ws1"),
			sym("arg"), ws(), lit(","), ws(), sym("arg")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			rs := r.([]interface{})
			op := rs[0].(uint16)
			b := rs[2].(*arg)
			a := rs[6].(*arg)
			return &binaryOp{opcode: op, b: b, a: a}, nil
		})
}

var unaryOpcodes = map[string]uint16{
	"jsr": 1,
	"int": 8,
	"iag": 9,
	"ias": 10,
	"rfi": 11,
	"iaq": 12,
	"hwn": 16,
	"hwq": 17,
	"hwi": 18,
	"log": 19,
	"brk": 20,
	"hlt": 21,
}

func addUnaryOpParsers(g *psec.Grammar) {
	var opcodes []psec.Parser
	for op := range unaryOpcodes {
		opcodes = append(opcodes, litIC(op))
	}

	g.WithAction("unary opcode", psec.Alt(opcodes...),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return unaryOpcodes[r.(string)], nil
		})

	g.WithAction("unary instruction",
		psec.Seq(sym("unary opcode"), sym("ws1"), sym("arg")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			rs := r.([]interface{})
			op := rs[0].(uint16)
			a := rs[2].(*arg)
			return &unaryOp{opcode: op, a: a}, nil
		})
}
