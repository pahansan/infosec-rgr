package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"infosec-rgr/internal/gamilton"
	"log"
)

func main() {
	fileName := flag.String("name", "graph.txt", "<path/to/file>")
	flag.Parse()
	g, cycle, err := gamilton.NewGraphFromFile(*fileName)
	if err != nil {
		log.Fatal(err)
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := &privateKey.PublicKey
	if gamilton.Protocol(g, cycle, 0, publicKey, privateKey) {
		fmt.Println("Cool")
	} else {
		fmt.Println("Jopa")
	}
	if gamilton.Protocol(g, cycle, 1, publicKey, privateKey) {
		fmt.Println("Cool")
	} else {
		fmt.Println("Jopa")
	}
}
