package rq

import (
	"testing"

	"github.com/shepheb/drasm/core"
	"github.com/shepheb/psec"
)

var rp = buildRisqueParser()

func expectLoadStore(t *testing.T, input string, exp *loadStore) {
	ast, err := rp.ParseStringWith("test", input, "load-store instruction")
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	ls := ast.(*loadStore)
	if ls.storing != exp.storing {
		t.Errorf("expected LS storing %t, got %t", exp.storing, ls.storing)
	}

	if ls.dest != exp.dest {
		t.Errorf("expected LS dest r%d, got r%d", exp.dest, ls.dest)
	}
	if ls.base != exp.base {
		t.Errorf("expected LS base r%d, got r%d", exp.base, ls.base)
	}
	if (exp.preLit == nil) != (ls.preLit == nil) {
		t.Errorf("expected LS prelit == nil %t but it was %t", exp.preLit == nil, ls.preLit == nil)
	}
	if exp.preLit != nil && !exp.preLit.Equals(ls.preLit) {
		t.Errorf("expression mismatch for LS preLit, %v expected got %v", exp.preLit, ls.preLit)
	}
	if (exp.postLit == nil) != (ls.postLit == nil) {
		t.Errorf("expected LS prelit == nil %t but it was %t", exp.preLit == nil, ls.preLit == nil)
	}
	if exp.postLit != nil && !exp.postLit.Equals(ls.postLit) {
		t.Errorf("expression mismatch for LS preLit, %v expected got %v", exp.preLit, ls.preLit)
	}

	if exp.preReg != ls.preReg {
		t.Errorf("expected LS preReg r%d, got r%d", exp.preReg, ls.preReg)
	}
}

func TestLoadStore(t *testing.T) {
	expectLoadStore(t, "ldr r4, [r2]", &loadStore{dest: 4, base: 2, preReg: 0xffff})
	expectLoadStore(t, "str r4, [r2]",
		&loadStore{storing: true, dest: 4, base: 2, preReg: 0xffff})
	expectLoadStore(t, "str r4, [r2, r6]",
		&loadStore{storing: true, dest: 4, base: 2, preReg: 6})
	expectLoadStore(t, "str r4, [r2, r6], #7",
		&loadStore{storing: true, dest: 4, base: 2, preReg: 6, postLit: &core.Constant{Value: 7}})
	expectLoadStore(t, "ldr  r4 , [  r2 , #7  ]",
		&loadStore{dest: 4, base: 2, preLit: &core.Constant{Value: 7}})
}

func expectStackOp(t *testing.T, input string, exp *stackOp) {
	ast, err := rp.ParseStringWith("test", input, "stack op instruction")
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	so := ast.(*stackOp)
	if exp.regs != so.regs {
		t.Errorf("SO regs mismatch, expected $%02x got $%02x", exp.regs, so.regs)
	}
	if exp.base != so.base {
		t.Errorf("SO base mismatch, expected %d got %d", exp.base, so.base)
	}
	if exp.storing != so.storing {
		t.Errorf("SO storing %t expected, got %t", exp.storing, so.storing)
	}
	if exp.lrpc != so.lrpc {
		t.Errorf("SO lr/pc %t expected, got %t", exp.lrpc, so.lrpc)
	}
}

func TestStackOp(t *testing.T) {
	expectStackOp(t, "push {r3, r0, r5}",
		&stackOp{base: 0xffff, regs: 0x29, storing: true})
	expectStackOp(t, "push {r3, r0, r5, lr}", // actually not really allowed
		&stackOp{base: 0xffff, regs: 0x29, lrpc: true, storing: true})
	expectStackOp(t, "push {}",
		&stackOp{base: 0xffff, regs: 0, storing: true})
	expectStackOp(t, "push {lr}",
		&stackOp{base: 0xffff, regs: 0, lrpc: true, storing: true})
	expectStackOp(t, "POP {PC}",
		&stackOp{base: 0xffff, regs: 0, lrpc: true})

	expectStackOp(t, "ldmia r2, {r0, r1}", &stackOp{base: 2, regs: 3})
	expectStackOp(t, "stmia r2, {r0, r1}", &stackOp{base: 2, regs: 3, storing: true})
}

func expectArg(t *testing.T, exp, act *arg) {
	if exp.kind != act.kind {
		t.Errorf("expected arg kind %v got %v", exp.kind, act.kind)
	}
	if exp.reg != act.reg {
		t.Errorf("expected arg reg %d got %d", exp.reg, act.reg)
	}
	if exp.lrpc != act.lrpc {
		t.Errorf("expected arg lrpc %t got %t", exp.lrpc, act.lrpc)
	}
	if (exp.lit == nil) != (act.lit == nil) {
		t.Errorf("expected arg lit nil %t got %t", exp.lit == nil, act.lit == nil)
	}
	if exp.lit != nil && !exp.lit.Equals(act.lit) {
		t.Errorf("expected arg lit %v got %v", exp.lit, act.lit)
	}

	if (exp.label == nil) != (act.label == nil) {
		t.Errorf("expected arg label nil %t got %t", exp.label == nil, act.label == nil)
	}
	if exp.label != nil && !exp.label.Equals(act.label) {
		t.Errorf("expected arg label %v got %v", exp.label, act.label)
	}
}

func tryBasicOp(t *testing.T, input, opcode string, args ...*arg) {
	ast, err := rp.ParseStringWith("test", input, "instruction")
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	inst := ast.(*instruction)
	if inst.opcode != opcode {
		t.Errorf("expected opcode %s got %s", opcode, inst.opcode)
	}

	if len(args) != len(inst.args) {
		t.Errorf("args mismatch: expected %d args got %d", len(args), len(inst.args))
	}

	for i, a := range args {
		expectArg(t, a, inst.args[i])
	}
}

func reg(n uint16) *arg {
	return &arg{kind: atReg, reg: n}
}

func imm(e core.Expression) *arg {
	return &arg{kind: atLiteral, lit: e}
}

func TestBasicOp(t *testing.T) {
	tryBasicOp(t, "mov r0, r1, r2", "MOV", reg(0), reg(1), reg(2))
	tryBasicOp(t, "mov r0, r1", "MOV", reg(0), reg(1))
	tryBasicOp(t, "add r0, r1, #77 + 8", "ADD", reg(0), reg(1),
		imm(core.Binary(&core.Constant{Value: 77}, core.PLUS, &core.Constant{Value: 8})))

	tryBasicOp(t, "popsp", "POPSP")
	tryBasicOp(t, "HWN r2", "HWN", reg(2))
	tryBasicOp(t, "SWI #9", "SWI", imm(&core.Constant{Value: 9}))
	tryBasicOp(t, "SWI #9", "SWI", imm(&core.Constant{Value: 9}))
	tryBasicOp(t, "bne home", "BNE", &arg{
		kind:  atLabel,
		label: core.UseLabel("home", &psec.Loc{Filename: "test", Line: 1, Col: 4}),
	})

	tryBasicOp(t, "sub sp, #7", "SUB", &arg{kind: atSP}, imm(&core.Constant{Value: 7}))
}
