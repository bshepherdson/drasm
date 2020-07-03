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
		return
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
	collectLabels(ast, s)
	assemble(ast, s)
	return s.rom[:s.index]
}

func collectLabels(ast *AST, s *AssemblyState) error {
	s.labels = make(map[string]*labelRef)
	s.reset()
	// Collect the labels.
	for _, l := range ast.Lines {
		labelDef, ok := l.(*LabelDef)
		if ok {
			s.addLabel(labelDef.Label)
		}
	}
	return nil
}

func assemble(ast *AST, s *AssemblyState) error {
	// Now actually assemble everything.
	s.dirty = true
	for s.dirty || !s.resolved {
		s.reset()
		for _, l := range ast.Lines {
			l.Assemble(s)
		}
	}
	return nil
}
