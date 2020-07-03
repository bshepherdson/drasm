package rq

import (
	"bufio"
	"os"
	"strings"

	"github.com/shepheb/drasm/core"
)

// Driver is the host for some methods.
type Driver struct{}

// ParseFile parses a file by name, returning an AST.
func (d *Driver) ParseFile(filename string) (*core.AST, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	p := newParser(filename, bufio.NewReader(f))
	return p.Parse()
}

func (d *Driver) ParseString(filename, str string) (*core.AST, error) {
	return newParser(filename, strings.NewReader(str)).Parse()
}

func (d *Driver) ParseExpr(filename, str string) (core.Expression, error) {
	return newParser(filename, strings.NewReader(str)).parseSimpleExpr()
}
