package core

import (
	"fmt"

	"github.com/shepheb/psec"
)

func AddBasicParsers(g *psec.Grammar) {
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
}
