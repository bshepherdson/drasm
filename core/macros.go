package core

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/shepheb/psec"
)

var macros map[string]string

// TODO This would probably be better handled with improving psec to allow
// carrying user parser state.
func FreshMacros() {
	macros = map[string]string{}
}

func addMacro(name, body string) {
	macros[name] = body
}

func isMacro(name string) bool {
	_, ok := macros[name]
	return ok
}

// This just does the string replacements, the Assemble routine is responsible
// for inline parsing.
func doMacro(s *AssemblyState, name string, args []string) (string, error) {
	text := macros[name]

	for i, arg := range args {
		basic := fmt.Sprintf("%%%d", i)   // %i
		evaled := fmt.Sprintf("%%e%d", i) // %ei

		if strings.Contains(text, evaled) {
			expr, err := currentDriver.ParseExpr("macro expr", strings.TrimSpace(arg))
			if err != nil {
				return "", fmt.Errorf("Could not parse expression for %s: %v", evaled, err)
			}
			value := expr.Evaluate(s)
			text = strings.ReplaceAll(text, evaled, strconv.FormatUint(uint64(value), 10))
		}

		text = strings.ReplaceAll(text, basic, arg)
	}

	text = strings.ReplaceAll(text, "%n", "\n")

	//fmt.Printf("Macro: %s %v\n%s\n=========\n", name, args, text)
	return text, nil
}

func addMacroParsers(g *psec.Grammar) {
	// This is even looser than an instruction, just a name and comma-separated
	// list, but the name must be defined as a macro or the action errors out.
	// This rule should be used as the last option for a legal line of assembly.
	g.WithAction("macro use",
		psec.Seq(sym("identifier"), psec.Optional(
			psec.SeqAt(1, sym("ws1"), psec.SepBy(psec.Stringify(psec.Many1(psec.NoneOf(",;\n"))), lit(","))))),
		func(r interface{}, loc *psec.Loc) (interface{}, error) {
			rs := r.([]interface{})
			macro := rs[0].(string)
			if !isMacro(macro) {
				return nil, fmt.Errorf("unknown macro %s", macro)
			}

			var args []string
			if rawArgs, ok := rs[1].([]interface{}); ok {
				for _, arg := range rawArgs {
					args = append(args, strings.TrimSpace(arg.(string)))
				}
			}
			return &MacroUse{macro: macro, args: args, loc: loc}, nil
		})
}
