package core

import (
	"fmt"

	"github.com/shepheb/psec"
)

// AddBasicParsers sets up most of the core structures needed by the assembler's
// parser.
// The machine-specific parser is only responsible for parsing instructions.
// Define a symbol "instruction" that parses an instruction (without labels),
// which returns either Assembled or []Assembled.
func AddBasicParsers(g *psec.Grammar) {
	g.AddSymbol("START", sym("file"))
	g.AddSymbol("ws", psec.ManyDrop(psec.OneOf(" \t\r\n")))
	g.AddSymbol("ws1", psec.Many1(psec.OneOf(" \t\r")))
	g.AddSymbol("wsline", psec.Many(psec.OneOf(" \t\r")))

	// Same-line whitespace, optional comment, and newline.
	g.AddSymbol("eol", psec.Seq(psec.Symbol("wsline"),
		psec.Optional(psec.Symbol("comment")), psec.Literal("\n"), psec.Symbol("ws")))
	g.WithAction("comment", psec.Seq(lit(";"), psec.ManyDrop(psec.NoneOf("\n"))),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return nil, nil
		})

	g.AddSymbol("letterish",
		psec.Alt(psec.OneOf("$_"), psec.Range('a', 'z'), psec.Range('A', 'Z')))
	g.WithAction("identifier", psec.Seq(sym("letterish"),
		psec.Stringify(psec.Many(psec.Alt(psec.Range('0', '9'), sym("letterish"))))),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			rs := r.([]interface{})
			return fmt.Sprintf("%c%s", rs[0].(byte), rs[1].(string)), nil
		})

	g.WithAction("label",
		psec.SeqAt(1, lit(":"), sym("identifier")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return DefineLabel(r.(string), loc), nil
		})

	g.AddSymbol("string", psec.SeqAt(1, lit("\""),
		psec.Stringify(psec.ManyTill(psec.AnyChar(), lit("\"")))))

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
			var asm []Assembled
			for _, val := range rs {
				if val != nil {
					if asms, ok := val.([]interface{}); ok {
						for _, a := range asms {
							asm = append(asm, a.(Assembled))
						}
					} else {
						asm = append(asm, val.(Assembled))
					}
				}
			}
			return &AST{Lines: asm}, nil
		})

	addExprParsers(g)
	addDirectiveParsers(g)
}
