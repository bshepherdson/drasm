package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shepheb/drasm/core"
	"github.com/shepheb/drasm/dcpu"
	"github.com/shepheb/drasm/rq"
)

var output = flag.String("out", "out.bin", "file name for the output")
var arch = flag.String("arch", "dcpu", "Architecture, dcpu or rq. (default dcpu)")

func main() {
	flag.Parse()

	// Grab the first argument and assemble it.
	file := flag.Arg(0)

	var machine core.Driver
	if *arch == "dcpu" {
		machine = &dcpu.Driver{}
	} else if *arch == "rq" {
		machine = &rq.Driver{}
	} else {
		fmt.Printf("Unknown arch: %s", *arch)
		return
	}

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
	// TODO: Include support.
	out, _ := os.Create(*output)
	defer out.Close()
	for _, w := range rom {
		out.Write([]byte{byte(w >> 8), byte(w & 0xff)})
	}
}
