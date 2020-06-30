package core

import (
	"testing"

	"github.com/shepheb/psec"
)

func buildParser() *psec.Grammar {
	g := psec.NewGrammar()
	AddBasicParsers(g)
	return g
}

var p = buildParser()

func TestString(t *testing.T) {
	r, err := p.ParseStringWith("test", "\"foo bar\"", "string")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	s, ok := r.(string)
	if !ok {
		t.Errorf("wanted string, got %T", r)
	} else {
		if s != "foo bar" {
			t.Errorf("wrong string, wanted 'foo bar' but got '%s'", s)
		}
	}
}
