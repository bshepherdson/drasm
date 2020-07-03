package core

import "fmt"

// labelRef captures the state of a label during assembly. Since it can be a
// forward reference, it might not have a known value yet. If an expression
// contains an unknown label, that makes the pass of the assembler unresolved,
// meaning a second pass is needed.
type labelRef struct {
	value   uint16
	defined bool
}

// AssemblyState tracks the state of the assembly so far.
type AssemblyState struct {
	// Fixed labels in the code, defined with :label.
	// These must be unique, and cannot be redefined.
	// These are collected early and added with addLabel(), but their values are
	// set to null initially.
	labels map[string]*labelRef

	// Updateable defines.
	symbols map[string]*labelRef

	macros map[string]string

	// True when all labels are resolved, false otherwise.
	resolved bool
	// True when something has changed this pass (eg. a label's value).
	dirty bool

	rom   [65536]uint16
	index uint16
	used  map[uint16]bool
}

func (s *AssemblyState) lookup(key string) (uint16, bool, bool) {
	if lr, ok := s.labels[key]; ok {
		return lr.value, lr.defined, true
	}
	if lr, ok := s.symbols[key]; ok {
		return lr.value, lr.defined, true
	}
	return 0, false, false
}

func (s *AssemblyState) addLabel(l string) {
	s.labels[l] = &labelRef{0, false}
}

func (s *AssemblyState) updateLabel(l string, loc uint16) {
	if lr, ok := s.labels[l]; ok {
		if !lr.defined || lr.value != loc {
			s.dirty = true
		}
		lr.value = loc
		lr.defined = true
	} else {
		panic(fmt.Sprintf("unknown label: '%s'", l))
	}
}

func (s *AssemblyState) updateSymbol(l string, val uint16) {
	s.symbols[l] = &labelRef{val, true}
}

func (s *AssemblyState) reset() {
	s.symbols = make(map[string]*labelRef)
	s.resolved = true
	s.dirty = false
	s.index = 0
	s.used = make(map[uint16]bool)
}

// Index gives the address of the next instruction to assemble.
// That is, a call to Push(x) would write x at this offset in the file.
func (s *AssemblyState) Index() uint16 {
	return s.index
}

// Push is the basic instruction to assemble a word into the output. It's
// exported because machine-specific code needs to push their encoded values to
// it.
func (s *AssemblyState) Push(x uint16) {
	if s.used[s.index] {
		panic(fmt.Sprintf("overlapping regions at $%04x", s.index))
	}
	s.used[s.index] = true
	s.rom[s.index] = x
	s.index++
}

func (s *AssemblyState) addMacro(name, body string) {

}
