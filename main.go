package main

import (
	"fmt"
	"os"

	"github.com/shepheb/drasm/core"
	"github.com/shepheb/drasm/rq"
)

func main() {
	// Grab the first argument and assemble it.
	file := os.Args[1]
	machine := &rq.Driver{}
	ast, err := machine.ParseFile(file)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	rom, err := core.RunAssembler(ast)
	if err != nil {
		fmt.Printf("Failed to assemble: %v", err)
	}

	// Now output the binary, big-endian.
	// TODO: Flexible endianness.
	// TODO: Output filename.
	// TODO: Include support.
	out, _ := os.Create("out.bin")
	defer out.Close()
	for _, w := range rom {
		out.Write([]byte{byte(w >> 8), byte(w & 0xff)})
	}
}
