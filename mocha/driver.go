package mocha

import (
	"io/ioutil"

	"github.com/shepheb/drasm/core"
)

// Driver is the host for some methods.
type Driver struct{}

var pr = buildMochaParser()

// ParseFile parses a file by name, returning an AST.
func (d *Driver) ParseFile(filename string) (*core.AST, error) {
	text, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ast, err := pr.ParseString(filename, string(text))
	if err != nil {
		return nil, err
	}
	return ast.(*core.AST), nil
}

func (d *Driver) ParseString(filename, text string) (*core.AST, error) {
	ast, err := pr.ParseString(filename, text)
	if err != nil {
		return nil, err
	}
	return ast.(*core.AST), nil
}

func (d *Driver) ParseExpr(filename, text string) (core.Expression, error) {
	expr, err := pr.ParseStringWith(filename, text, "expr")
	if err != nil {
		return nil, err
	}
	return expr.(core.Expression), nil
}
