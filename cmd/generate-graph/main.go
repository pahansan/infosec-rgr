package main

import (
	"flag"
	"fmt"
	"infosec-rgr/internal/gamilton"
	"log"
	"os"
)

func main() {
	fileName := flag.String("name", "graph.txt", "<path/to/file>")
	size := flag.Int("size", 10, "<number of vertexes>")
	nExtraEdges := flag.Int("extra", 0, "<number of edges except cycle>")
	flag.Parse()
	nEdges := *size + *nExtraEdges
	maxEdges := *size * (*size - 1) / 2
	
	if nEdges > maxEdges {
		log.Fatalf("Sum of vertexes in cycle and extra vertexes can't be bigger than square size")
	}

	g, cycle := gamilton.NewGraphWithCycle(*size)
	g.AddNEdges(*nExtraEdges)

	file, err := os.Create(*fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	fmt.Fprintf(file, "%d %d\n", *size, nEdges)

	for i := range *size {
		for j := i + 1; j < *size; j++ {
			exists, _ := g.CheckEdge(i, j)
			if exists {
				fmt.Fprintf(file, "%d %d\n", i, j)
			}
		}
	}

	for i := range cycle {
		fmt.Fprintf(file, "%d ", cycle[i])
	}

	// tmp := make([]int, 5)
	// str := "1 2 3 4 5"
	// fields := strings.Fields(str)
	// for i, v := range fields {
	// 	fmt.Sscan(v, &tmp[i])
	// }
	// fmt.Print(tmp)
}
