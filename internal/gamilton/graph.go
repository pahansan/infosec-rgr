package gamilton

import (
	"bufio"
	"infosec-rgr/internal/filereader"
	"infosec-rgr/internal/rsa"
	"math/big"
	"math/rand"
	"os"
)

type Graph struct {
	v [][]*big.Int
}

func NewGraph(size int) *Graph {
	g := &Graph{v: make([][]*big.Int, size)}
	for i := range size {
		g.v[i] = make([]*big.Int, size)
		for j := range size {
			g.v[i][j] = new(big.Int)
		}
	}
	return g
}

func NewGraphFromFile(filename string) (*Graph, []int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	size, nEdges, err := filereader.Read2Numbers(scanner)
	if err != nil {
		return nil, nil, err
	}

	g := NewGraph(size)
	for range nEdges {
		r, c, err := filereader.Read2Numbers(scanner)
		if err != nil {
			return nil, nil, err
		}
		g.AddEdge(r, c)
	}

	cycle, err := filereader.ReadSlice(scanner, size)
	if err != nil {
		return nil, nil, err
	}

	return g, cycle, nil
}

func (g *Graph) Copy() *Graph {
	size := g.Size()
	newGraph := NewGraph(size)
	for i := range size {
		for j := range size {
			newGraph.v[i][j].Set(g.v[i][j])
		}
	}
	return newGraph
}

func (g *Graph) IsomorphicCopy() (*Graph, []int) {
	size := g.Size()

	permutation := make([]int, size)
	for i := range size {
		permutation[i] = i
	}

	rand.Shuffle(size, func(i, j int) {
		permutation[i], permutation[j] = permutation[j], permutation[i]
	})

	newGraph := NewGraph(size)

	for i := range size {
		for j := range size {
			newI := permutation[i]
			newJ := permutation[j]
			newGraph.v[newI][newJ].Set(g.v[i][j])
		}
	}
	return newGraph, permutation
}

func (g *Graph) IsomorphicOriginal(permutation []int) *Graph {
	size := g.Size()

	inverse := make([]int, size)
	for i, p := range permutation {
		inverse[p] = i
	}

	original := NewGraph(size)

	for i := range size {
		for j := range size {
			origI := inverse[i]
			origJ := inverse[j]
			original.v[origI][origJ].Set(g.v[i][j])
		}
	}

	return original
}

func (g *Graph) Size() int {
	return len(g.v)
}

func (g *Graph) AddEdge(i, j int) {
	g.v[i][j].SetInt64(1)
	g.v[j][i].SetInt64(1)
}

func (g *Graph) RemoveEdge(i, j int) {
	g.v[i][j].SetInt64(0)
	g.v[j][i].SetInt64(0)
}

func (g *Graph) EdgeExists(i, j int) bool {
	size := g.Size()
	if i >= size || j >= size {
		return false
	}
	return g.v[i][j].Bit(0) == 1
}

func (g *Graph) SetEdge(i, j int, value *big.Int) {
	g.v[i][j].Set(value)
	g.v[j][i].Set(value)
}

func (g *Graph) GetEdge(i, j int) *big.Int {
	return new(big.Int).Set(g.v[i][j])
}

func (g *Graph) AddNRandEdges(n int) {
	i := 0
	size := g.Size()
	for i < n {
		r := rand.Intn(size)
		c := rand.Intn(size)
		if r == c {
			continue
		}
		if g.EdgeExists(r, c) {
			continue
		}
		g.AddEdge(r, c)
		i++
	}
}

func (g *Graph) padWithRandomness(i, j int) *big.Int {
	randomPart := big.NewInt(rand.Int63())
	randomPart.Lsh(randomPart, 1)

	if g.EdgeExists(i, j) {
		randomPart.Or(randomPart, big.NewInt(1))
	}

	return randomPart
}

func (g *Graph) AddPadding() *Graph {
	size := g.Size()
	newG := NewGraph(size)
	for i := range size {
		for j := i + 1; j < size; j++ {
			newValue := g.padWithRandomness(i, j)
			newG.SetEdge(i, j, newValue)
		}
	}
	return newG
}

func (g *Graph) RemovePadding() *Graph {
	size := g.Size()
	newG := NewGraph(size)
	for i := range size {
		for j := i + 1; j < size; j++ {
			if g.EdgeExists(i, j) {
				newG.AddEdge(i, j)
			} else {
				newG.RemoveEdge(i, j)
			}
		}
	}
	return newG
}

func (g *Graph) encryptEdgeRSA(i, j int, keys *rsa.Keys) {
	plain := g.GetEdge(i, j)
	cipher, _ := rsa.Encrypt(plain, keys.D, keys.N)
	g.SetEdge(i, j, cipher)
}

func (g *Graph) decryptEdgeRSA(i, j int, keys *rsa.Keys) {
	cipher := g.GetEdge(i, j)
	plain, _ := rsa.Decrypt(cipher, keys.C, keys.N)
	g.SetEdge(i, j, plain)
}

func (g *Graph) EncryptRSA(keys *rsa.Keys) *Graph {
	size := g.Size()
	encrypted := g.Copy()

	for i := range size {
		for j := i + 1; j < size; j++ {
			encrypted.encryptEdgeRSA(i, j, keys)
		}
	}
	return encrypted
}

func (g *Graph) DecryptRSA(keys *rsa.Keys) *Graph {
	size := g.Size()
	decrypted := g.Copy()

	for i := range size {
		for j := i + 1; j < size; j++ {
			decrypted.decryptEdgeRSA(i, j, keys)
		}
	}
	return decrypted
}

func (g *Graph) EncryptCycleRSA(keys *rsa.Keys, cycle []int) *Graph {
	size := g.Size()
	encrypted := g.Copy()

	for i := 1; i < size; i++ {
		encrypted.encryptEdgeRSA(cycle[i-1], cycle[i], keys)
	}
	encrypted.encryptEdgeRSA(cycle[0], cycle[size-1], keys)
	return encrypted
}

func (g *Graph) DecryptCycleRSA(keys *rsa.Keys, cycle []int) *Graph {
	size := g.Size()
	decrypted := g.Copy()

	for i := 1; i < size; i++ {
		decrypted.decryptEdgeRSA(cycle[i-1], cycle[i], keys)
	}
	decrypted.decryptEdgeRSA(cycle[0], cycle[size-1], keys)
	return decrypted
}

func (g *Graph) Equals(other *Graph) bool {
	size := g.Size()
	if size != other.Size() {
		return false
	}
	for i := range size {
		for j := i + 1; j < size; j++ {
			if g.v[i][j].Cmp(other.v[i][j]) != 0 {
				return false
			}
		}
	}
	return true
}

func (g *Graph) CheckCycle(cycle []int) bool {
	for i := 1; i < len(cycle); i++ {
		if !g.EdgeExists(cycle[i-1], cycle[i]) {
			return false
		}
	}
	if !g.EdgeExists(cycle[0], cycle[len(cycle)-1]) {
		return false
	}
	return true
}

func (g *Graph) SameAs(other *Graph) bool {
	size := g.Size()
	if size != other.Size() {
		return false
	}
	for i := range size {
		for j := i + 1; j < size; j++ {
			if g.EdgeExists(i, j) != other.EdgeExists(i, j) {
				return false
			}
		}
	}
	return true
}
