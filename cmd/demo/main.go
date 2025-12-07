package main

import (
	"flag"
	"fmt"
	"infosec-rgr/internal/gamilton"
	"infosec-rgr/internal/rsa"
	"log"
	"math/big"
	"math/rand"
)

func main() {
	fileName := flag.String("name", "graph.txt", "<path/to/file>")
	t := flag.Int("t", 10, "<count of quetions>")
	flag.Parse()
	g, cycle, err := gamilton.NewGraphFromFile(*fileName)
	if err != nil {
		log.Fatal(err)
	}
	keys, err := rsa.GenerateKeys()
	if err != nil {
		log.Fatal(err)
	}

	lie := big.NewFloat(0.5)
	for i := range *t {
		fmt.Print(i+1, ": ")
		status := gamilton.Protocol(g, cycle, rand.Intn(2), keys)
		if status == true {
			fmt.Println("Проверка успешна.")
		} else {
			fmt.Println("Проверка не прошла. Обман раскрыт.")
			return
		}
		fmt.Print("Вероятность обмана: ", lie, "\n\n")
		lie.Mul(lie, lie)
	}
}
