package core

import "fmt"

type Driver interface {
	ParseFile(filename string) (*AST, error)
}

func RunAssembler(ast *AST) ([]uint16, error) {
	s := new(AssemblyState)
	collectLabels(ast, s)
	assemble(ast, s)
	return s.rom[:s.index], nil
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
