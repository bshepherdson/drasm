package rq

import (
	"strings"

	"github.com/shepheb/drasm/core"
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
func seq(args ...psec.Parser) psec.Parser {
	return psec.Seq(args...)
}

func buildRisqueParser() *psec.Grammar {
	g := psec.NewGrammar()
	core.AddBasicParsers(g)

	g.WithAction("gpReg", psec.SeqAt(1, litIC("r"), psec.OneOf("01234567")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			i := r.(byte) - '0'
			return &arg{kind: atReg, reg: uint16(i)}, nil
		})

	g.WithAction("imm", psec.SeqAt(1, lit("#"), sym("expr")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &arg{kind: atLiteral, lit: r.(core.Expression)}, nil
		})

	g.WithAction("sp", litIC("sp"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &arg{kind: atSP}, nil
		})
	g.WithAction("pc", litIC("pc"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &arg{kind: atPC}, nil
		})
	g.WithAction("labelArg", sym("expr"),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &arg{kind: atLabel, label: r.(core.Expression)}, nil
		})

	g.AddSymbol("comma", psec.Seq(sym("wsline"), lit(","), sym("wsline")))
	g.AddSymbol("arg", psec.Alt(sym("imm"), sym("gpReg"), sym("sp"), sym("pc"),
		sym("labelArg")))

	g.AddSymbol("arg-list", psec.SepBy(sym("arg"), sym("comma")))

	// The common types of instructions: moves, arithmetic, comparison, hardware.
	g.WithAction("basic instruction",
		psec.Seq(sym("opcode"), psec.Optional(psec.SeqAt(1, sym("ws1"), sym("arg-list")))),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			rs := r.([]interface{})
			opcode := rs[0].(string)
			op := &instruction{opcode: opcode, loc: loc}

			if args, ok := rs[1].([]interface{}); ok {
				for _, a := range args {
					op.args = append(op.args, a.(*arg))
				}
			}

			return op, nil
		})

	ops := []string{
		"MOV", "MVH", "MVN", "NEG", "XSR",
		"ADD", "ADC", "SUB", "SBC", "MUL",
		"LSL", "LSR", "ASR", "AND", "ORR", "XOR", "ROR",
		"CMP", "CMN", "TST", "BRK",
		"BEQ", "BNE", "BCS", "BCC", "BMI", "BPL", "BVS", "BVC",
		"BHI", "BLS", "BGE", "BLT", "BGT", "BLE",
		"RET", "BX", "BLX", "BL", "B",
		"HWN", "HWQ", "HWI", "SWI", "RFI",
		"IFC", "IFS", "POPSP",
	}
	var opLits []psec.Parser
	for _, op := range ops {
		opLits = append(opLits, litIC(op))
	}

	g.AddSymbol("opcode", psec.Alt(opLits...))

	g.AddSymbol("instruction", psec.Alt(sym("load-store instruction"), sym("stack op instruction"), sym("basic instruction")))

	addLoadStoreParsers(g)
	addStackOpParsers(g)

	return g
}

func addLoadStoreParsers(g *psec.Grammar) {
	g.WithAction("load-store instruction",
		psec.Seq(sym("lsOp"), sym("wsline"), sym("gpReg"), sym("comma"), sym("address"),
			psec.Optional(psec.SeqAt(1, sym("comma"), sym("imm")))),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			rs := r.([]interface{})

			ls := rs[4].(*loadStore) // The address block returns the starter LS.
			if strings.ToLower(rs[0].(string)) == "str" {
				ls.storing = true
			}
			ls.dest = rs[2].(*arg).reg

			if post, ok := rs[5].(*arg); ok && post != nil {
				ls.postLit = post.lit
			}
			return ls, nil
		})

	g.AddSymbol("lsOp", psec.Alt(litIC("ldr"), litIC("str")))

	g.WithAction("address",
		psec.Seq(lit("["), sym("wsline"), psec.Alt(sym("gpReg"), sym("sp")),
			psec.Optional(psec.SeqAt(1, sym("comma"), psec.Alt(sym("imm"), sym("gpReg")))), sym("wsline"), lit("]")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			rs := r.([]interface{})
			base := rs[2].(*arg)
			ls := &loadStore{}

			if base.kind == atSP {
				ls.base = 0xffff
			} else {
				ls.base = base.reg
			}

			if index, ok := rs[3].(*arg); ok && index != nil {
				if index.kind == atReg {
					ls.preReg = index.reg
				} else {
					ls.preLit = index.lit
				}
			} else {
				ls.preReg = 0xffff // Signals no preReg, the zero value is r0.
			}

			return ls, nil
		})
}

func addStackOpParsers(g *psec.Grammar) {
	g.WithAction("comma-regs",
		psec.SepBy(psec.Alt(sym("gpReg"), litIC("pc"), litIC("lr")), sym("comma")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			// We turn the registers into a bitmap, r0 = bit 0, r7 = bit 7, in the reg
			// field.
			ret := &arg{kind: atRlist}
			regs := r.([]interface{})
			for _, reg := range regs {
				if a, ok := reg.(*arg); ok {
					ret.reg |= 1 << uint(a.reg)
				} else {
					ret.lrpc = true
				}
			}

			return ret, nil
		})

	g.AddSymbol("rlist",
		psec.SeqAt(2, lit("{"), ws(), sym("comma-regs"), ws(), lit("}")))

	g.AddSymbol("stack op instruction",
		psec.Alt(sym("push-pop instruction"), sym("lsMultiple instruction")))

	g.WithAction("push-pop instruction",
		psec.Seq(psec.Alt(litIC("push"), litIC("pop")), sym("wsline"), sym("rlist")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			rs := r.([]interface{})
			op := &stackOp{base: 0xffff}
			if rs[0].(string) == "push" {
				op.storing = true
			}

			rlist := rs[2].(*arg)
			op.regs = rlist.reg
			op.lrpc = rlist.lrpc
			return op, nil
		})

	g.WithAction("lsMultiple instruction",
		psec.Seq(psec.Alt(litIC("ldmia"), litIC("stmia")), sym("wsline"), sym("gpReg"), sym("comma"), sym("rlist")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			rs := r.([]interface{})
			op := &stackOp{base: 0xffff}
			if rs[0].(string) == "stmia" {
				op.storing = true
			}

			op.base = rs[2].(*arg).reg

			rlist := rs[4].(*arg)
			op.regs = rlist.reg
			op.lrpc = rlist.lrpc
			return op, nil
		})
}
