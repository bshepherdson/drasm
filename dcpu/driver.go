package dcpu

import (
	"io/ioutil"

	"github.com/shepheb/drasm/core"
)

// Driver is the host for some methods.
type Driver struct{}

var parser = buildDcpuParser()

// ParseFile parses a file by name, returning an AST.
func (d *Driver) ParseFile(filename string) (*core.AST, error) {
	text, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ast, err := parser.ParseString(filename, string(text))
	if err != nil {
		return nil, err
	}
	return ast.(*core.AST), nil
}

func (d *Driver) ParseString(filename, text string) (*core.AST, error) {
	ast, err := parser.ParseString(filename, text)
	if err != nil {
		return nil, err
	}
	return ast.(*core.AST), nil
}

func (d *Driver) ParseExpr(filename, text string) (core.Expression, error) {
	expr, err := parser.ParseStringWith(filename, text, "expr")
	if err != nil {
		return nil, err
	}
	return expr.(core.Expression), nil
}
