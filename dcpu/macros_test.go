package dcpu

import (
	"testing"

	"github.com/shepheb/drasm/core"
)

func TestBasicMacros(t *testing.T) {
	core.FreshMacros()
	input := `
.macro foo=set a, b
foo
foo
foo`
	ast, err := dp.ParseString("test", input)
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	ls := ast.(*core.AST).Lines
	if _, ok := ls[0].(*core.MacroDef); !ok {
		t.Errorf("Expected the first output to be a MacroDef, got %T", ls[0])
	}
	for _, mu := range ls[1:] {
		if _, ok := mu.(*core.MacroUse); !ok {
			t.Errorf("Expected the first output to be a MacroUse, got %T", mu)
		}
	}

	// The more interesting test is that it assembles properly.
	rom := core.AssembleAst(ast.(*core.AST))
	if len(rom) != 3 {
		t.Errorf("rom should be length 3, got %d", len(rom))
		return
	}

	for i, op := range rom {
		if op != 0x0401 {
			t.Errorf("rom[%d] should be 0x0401 (set a, b) but got 0x%04x", i, op)
		}
	}
}

func TestChainedMacros(t *testing.T) {
	input := `
.def num0, 5
.def num1, 60
.def num2, 108
.def num3, 201
.def num_counter, 0

.macro dat_num=.dat num%e0
.macro do_num=dat_num num_counter %n .def num_counter, num_counter+1
do_num
do_num
do_num`
	// That should expand to effectively dat num0, num1, num2, and leave
	// num_counter set to 3.
	ast, err := dp.ParseString("test", input)
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	rom := core.AssembleAst(ast.(*core.AST))
	if len(rom) != 3 {
		t.Errorf("rom should be length 3, got %d", len(rom))
		return
	}

	if rom[0] != 5 {
		t.Errorf("expected the first DAT (num0) to be 5, got %d", rom[0])
	}
	if rom[1] != 60 {
		t.Errorf("expected the second DAT (num1) to be 60, got %d", rom[1])
	}
	if rom[2] != 108 {
		t.Errorf("expected the third DAT (num2) to be 108, got %d", rom[2])
	}
}
