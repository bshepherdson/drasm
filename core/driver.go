package core

import (
	"fmt"
	"os"
)

type Driver interface {
	ParseFile(filename string) (*AST, error)
}

// Used by Include to recursively parse.
var currentDriver Driver

func MasterAssembler(machine Driver, file, outfile string) {
	currentDriver = machine

	ast, err := machine.ParseFile(file)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	s := new(AssemblyState)
	collectLabels(ast, s)
	assemble(ast, s)
	rom := s.rom[:s.index]

	// Now output the binary, big-endian.
	// TODO: Flexible endianness.
	// TODO: Include support.
	out, _ := os.Create(outfile)
	defer out.Close()
	for _, w := range rom {
		out.Write([]byte{byte(w >> 8), byte(w & 0xff)})
	}
}

func collectLabels(ast *AST, s *AssemblyState) error {
	s.labels = make(map[string]*labelRef)
	s.reset()
	// Collect the labels.
	fmt.Printf("===========================\n")
	for _, l := range ast.Lines {
		fmt.Printf("line: %#v\n", l)
		labelDef, ok := l.(*LabelDef)
		if ok {
			fmt.Printf("label added: %s\n", labelDef.Label)
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
		fmt.Printf("resolved %t dirty %t\n", s.resolved, s.dirty)
	}
	return nil
}
