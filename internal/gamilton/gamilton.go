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
	if q == 0 {
		newCycle := transformCycle(cycle, perms)
		fDecrypted := f.DecryptCycleRSA(keys, newCycle)
		if !fDecrypted.CheckCycle(newCycle) {
			fmt.Println("CheckCycle failed")
			return false
		}
		fEncrypted := fDecrypted.EncryptCycleRSA(keys, newCycle)
		if f.Equals(fEncrypted) {
			return true
		} else {
			fmt.Println("Equals failed")
			return false
		}
	} else if q == 1 {
		fDecrypted := f.DecryptRSA(keys)
		original := fDecrypted.IsomorphicOriginal(perms)
		if !original.SameAs(g) {
			return false
		}
		fEncrypted := fDecrypted.EncryptRSA(keys)
		if !fEncrypted.Equals(f) {
			return false
		}
		return true
	}
	return false
}
