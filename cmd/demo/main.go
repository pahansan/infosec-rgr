package main

import (
	"flag"
	"fmt"
	"infosec-rgr/internal/gamilton"
	"infosec-rgr/internal/rsa"
	"log"
)

func main() {
	fileName := flag.String("name", "graph.txt", "<path/to/file>")
	flag.Parse()
	g, cycle, err := gamilton.NewGraphFromFile(*fileName)
	if err != nil {
		log.Fatal(err)
	}
	keys := rsa.GenerateKeys()
	if gamilton.Protocol(g, cycle, 0, &keys) {
		fmt.Println("Cool")
	} else {
		fmt.Println("Jopa")
	}
	if gamilton.Protocol(g, cycle, 1, &keys) {
		fmt.Println("Cool")
	} else {
		fmt.Println("Jopa")
	}
}
