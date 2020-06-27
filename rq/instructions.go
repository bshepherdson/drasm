package rq

import (
	"fmt"
	"strings"

	"github.com/shepheb/drasm/core"
)

func showArgs(args []*arg) string {
	strs := make([]string, len(args))
	for i, a := range args {
		strs[i] = showArg(a)
	}
	return strings.Join(strs, ", ")
}

func showArg(arg *arg) string {
	switch arg.kind {
	case atPC:
		return "PC"
	case atSP:
		return "SP"
	case atReg:
		return fmt.Sprintf("r%d", arg.reg)
	case atLiteral:
		return "literal"
	case atLabel:
		return "label"
	default:
		return "unknown"
	}
}

func opRI(loc, mnemonic string, opcode uint16, args []*arg, s *core.AssemblyState) {
	if mnemonic == "MOV" {
		// Special case for MOV: We can encode it as NEG or as MOV+MVH.
		value := args[1].lit.Evaluate(s)
		if value <= 255 {
			s.Push((opcode << 11) | (args[0].reg << 8) | value)
		} else if value > 0xff00 {
			s.Push(0x1000 | (args[0].reg << 8) | -value)
		} else {
			s.Push(0x0800 | (args[0].reg << 8) | (value & 0xff))
			s.Push(0x7800 | (args[0].reg << 8) | (value >> 8))
		}
	} else {
		value := checkLiteral(s, args[1].lit, false, 8)
		s.Push((opcode << 11) | (args[0].reg << 8) | value)
	}
}

func opRRR(loc, mnemonic string, opcode uint16, args []*arg, s *core.AssemblyState) {
	s.Push(0x8000 | (opcode << 9) | (args[2].reg << 6) | (args[1].reg << 3) | args[0].reg)
}

func opRR(loc, mnemonic string, opcode uint16, args []*arg, s *core.AssemblyState) {
	s.Push(0x8000 | (opcode << 6) | (args[1].reg << 3) | args[0].reg)
}

func opR(loc, mnemonic string, opcode uint16, args []*arg, s *core.AssemblyState) {
	s.Push(0x8000 | (opcode << 3) | args[0].reg)
}

func opVoid(loc, mnemonic string, opcode uint16, s *core.AssemblyState) {
	s.Push(0x8000 | opcode)
}

func opBranch(loc, mnemonic string, opcode uint16, args []*arg, s *core.AssemblyState) {
	// Convert the argument to an absolute address.
	target := args[0].label.Evaluate(s)
	diff := target - (s.Index() + 1)
	// Special case: if the diff happens to be -1, need to use the long form.
	if diff != 0xffff && (diff < 256 || -diff <= 256) {
		// Fits into the single instruction.
		s.Push(0xa000 | (opcode << 9) | (diff & 0x1ff))
	} else {
		// Needs the long form.
		s.Push(0xa000 | (opcode << 9) | 0x1ff)
		s.Push(target)
	}
}

func opAddSub(loc, mnemonic string, args []*arg, s *core.AssemblyState) {
	// ADD and SUB both support several argument types: RI, RRR, SP-Imm.
	// ADD additionally has reg-PC-imm and reg-SP-imm
	if len(args) == 2 && args[0].kind == atReg && args[1].kind == atLiteral {
		opcode := uint16(4)
		if mnemonic == "SUB" {
			opcode = 5
		}
		opRI(loc, mnemonic, opcode, args, s)
	} else if len(args) == 3 && args[0].kind == atReg && args[1].kind == atReg && args[2].kind == atReg {
		opcode := uint16(1)
		if mnemonic == "SUB" {
			opcode = 3
		}
		opRRR(loc, mnemonic, opcode, args, s)
	} else if mnemonic == "ADD" && len(args) == 3 && args[0].kind == atReg && args[1].kind == atPC && args[2].kind == atLiteral {
		value := checkLiteral(s, args[2].lit, false, 8)
		s.Push((0xd << 11) | (args[0].reg << 8) | value)
	} else if mnemonic == "ADD" && len(args) == 3 && args[0].kind == atReg && args[1].kind == atSP && args[2].kind == atLiteral {
		value := checkLiteral(s, args[2].lit, false, 8)
		s.Push((0xe << 11) | (args[0].reg << 8) | value)
	} else if len(args) == 2 && args[0].kind == atSP && args[1].kind == atLiteral {
		value := checkLiteral(s, args[1].lit, false, 8)
		opcode := uint16(0)
		if mnemonic == "SUB" {
			opcode++
		}
		s.Push((opcode << 8) | value)
	} else {
		// Unrecognized set of arguments.
		core.AsmError(loc, "Unrecognized arguments to %s: %s", mnemonic, showArgs(args))
	}
}

func opSWI(loc, mnemonic string, args []*arg, s *core.AssemblyState) {
	// SWI accepts either a single register or a literal.
	if len(args) == 1 && args[0].kind == atReg {
		// 1000000000011ddd
		s.Push(0x8018 | args[0].reg)
	} else if len(args) == 1 && args[0].kind == atLiteral {
		// 00000010XXXXXXXX
		value := checkLiteral(s, args[0].lit, false, 8)
		s.Push(0x0200 | value)
	} else {
		core.AsmError(loc, "Invalid arguments to SWI: %s", showArgs(args))
	}
}
