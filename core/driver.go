package core

import (
	"fmt"
	"os"
)

type Driver interface {
	ParseExpr(filename, text string) (Expression, error)
	ParseString(filename, test string) (*AST, error)
	ParseFile(filename string) (*AST, error)
}

// Used by Include to recursively parse.
var currentDriver Driver

// TODO This sucks and should be replaced by a payload on the parser.
func SetDriver(machine Driver) {
	currentDriver = machine
}

func MasterAssembler(machine Driver, file, outfile string) {
	currentDriver = machine

	FreshMacros()
	ast, err := machine.ParseFile(file)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	rom := AssembleAst(ast)

	// Now output the binary, big-endian.
	// TODO: Flexible endianness.
	// TODO: Include support.
	out, _ := os.Create(outfile)
	defer out.Close()
	for _, w := range rom {
		out.Write([]byte{byte(w >> 8), byte(w & 0xff)})
	}
}

func AssembleAst(ast *AST) []uint16 {
	s := new(AssemblyState)
	s.labels = make(map[string]*labelRef)
	s.reset()
	collectLabels(ast, s)
	assemble(ast, s)
	return s.rom[:s.index]
}

// TODO: This might be better as a method on Assembled? Most of them are empty,
// though.
func collectLabels(ast *AST, s *AssemblyState) error {
	// Collect the labels.
	for _, l := range ast.Lines {
		if labelDef, ok := l.(*LabelDef); ok {
			//fmt.Printf("Label: '%s'\n", labelDef.Label)
			s.addLabel(labelDef.Label)
		} else if ast, ok := l.(*AST); ok {
			err := collectLabels(ast, s) // Recursively collect included files.
			if err != nil {
				return err
			}
			//} else if mu, ok := l.(*MacroUse); ok {
			//	// Recursively collect labels defined in macros.
			//	text, err := doMacro(s, mu.macro, mu.args)
			//	if err != nil {
			//		return err
			//	}
			//	parsed, err := currentDriver.ParseString("macro", text)
			//	if err != nil {
			//		return err
			//	}
			//	collectLabels(parsed, s)
		}
	}
	return nil
}

func assemble(ast *AST, s *AssemblyState) error {
	// Now actually assemble everything.
	s.dirty = true
	passes := 0
	for s.dirty || !s.resolved {
		s.reset()
		for _, l := range ast.Lines {
			l.Assemble(s)
		}
		passes++
		if passes > 100 {
			fmt.Printf("Attempted 100 passes but the assembly won't settle\n")
			fmt.Printf("Dirty labels %v\n", s.dirtyLabels)
			os.Exit(1)
		}
	}
	return nil
}
