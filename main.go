package main

import (
	"flag"
	"fmt"

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

	core.MasterAssembler(machine, file, *output)
}
