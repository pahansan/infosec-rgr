package gamilton

import (
	"fmt"
	"infosec-rgr/internal/rsa"
	"math/rand"
)

func GamiltonCycle(size int) []int {
	cycle := make([]int, size)
	for i := range size {
		cycle[i] = i
	}
	rand.Shuffle(size, func(i, j int) {
		cycle[i], cycle[j] = cycle[j], cycle[i]
	})
	return cycle
}

func NewGraphWithCycle(size int) (*Graph, []int) {
	cycle := GamiltonCycle(size)
	graph := NewGraph(size)
	for i := 1; i < size; i++ {
		graph.AddEdge(cycle[i-1], cycle[i])
	}
	graph.AddEdge(cycle[0], cycle[size-1])
	return graph, cycle
}

func transformCycle(cycle, permutations []int) []int {
	newCycle := make([]int, len(cycle))
	for i := range len(cycle) {
		newCycle[i] = permutations[cycle[i]]
	}
	return newCycle
}

func Protocol(g *Graph, cycle []int, q int, keys *rsa.Keys) bool {
	h, perms := g.IsomorphicCopy()
	hTilda := h.AddPadding()
	f := hTilda.EncryptRSA(keys)
	switch q {
	case 0:
		fmt.Println("Боб задаёт вопрос: Каков гамильтонов цикл для графа H?")
		fmt.Print("Алиса расшифровывает рёбра цикла: ")
		newCycle := transformCycle(cycle, perms)
		fDecrypted := f.DecryptCycleRSA(keys, newCycle)
		if !fDecrypted.CheckCycle(newCycle) {
			return false
		}
		fmt.Print("Боб убедился в наличии цикла. ")
		fmt.Print("Боб шифрует цикл снова: ")
		fEncrypted := fDecrypted.EncryptCycleRSA(keys, newCycle)
		if f.Equals(fEncrypted) {
			fmt.Print("граф снова равен F. ")
			return true
		} else {
			return false
		}
	case 1:
		fmt.Println("Боб задаёт вопрос: Действительно ли граф H изоморфен G?")
		fmt.Print("Алиса демонстрирует перестановки: ")
		fDecrypted := f.DecryptRSA(keys)
		original := fDecrypted.IsomorphicOriginal(perms)
		if !original.SameAs(g) {
			return false
		}
		fmt.Print("G и H совпадают. ")
		fmt.Print("Боб повторно шифрует H: ")
		fEncrypted := fDecrypted.EncryptRSA(keys)
		if !fEncrypted.Equals(f) {
			return false
		}
		fmt.Print("H == F. ")
		return true
	default:
		return false
	}
}
