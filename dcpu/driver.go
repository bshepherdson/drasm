package dcpu

import (
	"io/ioutil"

	"github.com/shepheb/drasm/core"
)

// Driver is the host for some methods.
type Driver struct{}

// ParseFile parses a file by name, returning an AST.
func (d *Driver) ParseFile(filename string) (*core.AST, error) {
	text, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ast, err := buildDcpuParser().ParseString(filename, string(text))
	if err != nil {
		return nil, err
	}
	return ast.(*core.AST), nil
}
