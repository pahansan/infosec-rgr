package gamilton

import (
	"crypto/rsa"
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

func transformCycle(other, permutations []int) []int {
	cycle := make([]int, len(other))
	for i := range len(cycle) {
		newI := permutations[i]
		cycle[i] = other[newI]
	}
	return cycle
}

func Protocol(g *Graph, cycle []int, q int, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) bool {
	h, perms := g.IsomorphicCopy()
	f, _ := h.EncryptRSA(publicKey)
	if q == 0 {
		newCycle := transformCycle(cycle, perms)
		fDecrypted, _ := f.DecryptCycleRSA(privateKey, newCycle)
		if !fDecrypted.CheckCycle(newCycle) {
			return false
		}
		fEncrypted, _ := fDecrypted.EncryptCycleRSA(publicKey, newCycle)
		if f.Equals(fEncrypted) {
			return true
		} else {
			return false
		}
	} else if q == 1 {
		fDecrypted, _ := f.DecryptRSA(privateKey)
		original := fDecrypted.IsomorphicOriginal(perms)
		if !original.SameAs(g) {
			return false
		}
		fEncrypted, _ := fDecrypted.EncryptRSA(publicKey)
		if !fEncrypted.Equals(f) {
			return false
		}
		return true
	}
	return false
}
