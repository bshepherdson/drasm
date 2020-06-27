package core

// Machine hides the differences between various CPUs behind an interface. The
// driver can call into the right Machine instance for the target CPU to perform
// the machine-specific parsing into a common(ish) AST.
type Machine interface {
	ParseFile(filename string) (*AST, error)
}
