package core

import "github.com/shepheb/psec"

// Shared psec parsers for the assembler directives.
func AddDirectiveParsers(g *psec.Grammar) {
	g.WithAction("dir:org",
		psec.SeqAt(2, litIC("org"), sym("ws1"), sym("expr")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			return &Org{Abs: r.(Expression)}, nil
		})
	g.WithAction("dir:fill",
		psec.Seq(litIC("fill"), sym("ws1"), sym("expr"),
			ws(), lit(","), ws(), sym("expr")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			// Value, then Length.
			rs := r.([]interface{})
			return &FillBlock{Value: rs[2].(Expression), Length: rs[6].(Expression)}, nil
		})
	g.WithAction("dir:include",
		psec.SeqAt(2, litIC("include"), sym("ws1"), sym("string")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			// Recursively parse the file.
			return currentDriver.ParseFile(r.(string))
		})
	g.WithAction("dir:symbol",
		psec.Seq(psec.Alt(litIC("symbol"), litIC("sym"), litIC("equ"),
			litIC("set"), litIC("def"), litIC("define")),
			sym("ws1"), sym("identifier"), ws(), lit(","), ws(), sym("expr")),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			rs := r.([]interface{})
			return DefineSymbol(rs[2].(string), rs[6].(Expression)), nil
		})
	g.WithAction("dir:dat",
		psec.SeqAt(2, litIC("dat"), sym("ws1"),
			psec.SepBy(sym("expr"), psec.Seq(ws(), lit(","), ws()))),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			var values []Expression
			for _, expr := range r.([]interface{}) {
				values = append(values, expr.(Expression))
			}
			return &DatBlock{Values: values}, nil
		})

	g.AddSymbol("directive",
		psec.SeqAt(1, psec.Literal("."),
			psec.Alt(sym("dir:fill"), sym("dir:include"),
				sym("dir:org"), sym("dir:dat"), sym("dir:symbol"))))
}
