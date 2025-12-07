package gamilton

import (
	"bufio"
	"fmt"
	"infosec-rgr/internal/rsa"
	"math/big"
	mrand "math/rand"
	"os"
	"strings"
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
		return nil, []int{}, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Scan()
	line := scanner.Text()
	var size, nEdges int
	fmt.Sscanf(line, "%d %d", &size, &nEdges)
	g := NewGraph(size)
	for range nEdges {
		var r, c int
		scanner.Scan()
		line := scanner.Text()
		fmt.Sscanf(line, "%d %d", &r, &c)
		g.AddEdge(r, c)
	}
	cycle := make([]int, size)
	scanner.Scan()
	line = scanner.Text()
	fields := strings.Fields(line)
	for i, v := range fields {
		fmt.Sscan(v, &cycle[i])
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

	mrand.Shuffle(size, func(i, j int) {
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

func (g *Graph) AddEdge(i, j int) error {
	size := g.Size()
	if i >= size || j >= size {
		return fmt.Errorf("incorrect input: i = %d and j = %d for graph with size %d", i, j, size)
	}
	g.v[i][j].SetInt64(1)
	g.v[j][i].SetInt64(1)
	return nil
}

func (g *Graph) RemoveEdge(i, j int) error {
	size := g.Size()
	if i >= size || j >= size {
		return fmt.Errorf("incorrect input: i = %d and j = %d for graph with size %d", i, j, size)
	}
	g.v[i][j].SetInt64(0)
	return nil
}

func (g *Graph) CheckEdge(i, j int) (bool, error) {
	size := g.Size()
	if i >= size || j >= size {
		return false, fmt.Errorf("incorrect input: i = %d and j = %d for graph with size %d", i, j, size)
	}

	exists := g.v[i][j].Bit(0) == 1

	return exists, nil
}

func (g *Graph) SetEdge(i, j int, value *big.Int) error {
	size := g.Size()
	if i >= size || j >= size {
		return fmt.Errorf("incorrect input: i = %d and j = %d for graph with size %d", i, j, size)
	}
	g.v[i][j].Set(value)
	g.v[j][i].Set(value)
	return nil
}

func (g *Graph) GetEdge(i, j int) (*big.Int, error) {
	size := g.Size()
	if i >= size || j >= size {
		return nil, fmt.Errorf("incorrect input: i = %d and j = %d for graph with size %d", i, j, size)
	}
	return new(big.Int).Set(g.v[i][j]), nil
}

func (g *Graph) AddNEdges(n int) {
	if n == 0 {
		return
	}
	i := 0
	size := g.Size()
	for i < n {
		r := mrand.Intn(size)
		c := mrand.Intn(size)
		if r == c {
			continue
		}
		if exist, _ := g.CheckEdge(r, c); exist {
			continue
		}
		g.AddEdge(r, c)
		i++
	}
}

func (g *Graph) padWithRandomness(i, j int) *big.Int {
	thereEdge, _ := g.CheckEdge(i, j)

	randomPart := new(big.Int).SetInt64(mrand.Int63())
	randomPart.Lsh(randomPart, 1)

	if thereEdge {
		randomPart.Or(randomPart, big.NewInt(1))
	}

	return randomPart
}

func (g *Graph) AddPadding() *Graph {
	size := g.Size()
	newG := g.Copy()
	for i := range size {
		for j := i + 1; j < size; j++ {
			newValue := newG.padWithRandomness(i, j)
			newG.SetEdge(i, j, newValue)
		}
	}
	return newG
}

func (g *Graph) RemovePadding() *Graph {
	size := g.Size()
	newG := g.Copy()
	for i := range size {
		for j := i + 1; j < size; j++ {
			exists, _ := newG.CheckEdge(i, j)
			if exists {
				newG.AddEdge(i, j)
			} else {
				newG.RemoveEdge(i, j)
			}
		}
	}
	return newG
}

func (g *Graph) encryptEdgeRSA(i, j int, keys *rsa.Keys) {
	plain, _ := g.GetEdge(i, j)
	cipher := rsa.Encrypt(plain, keys.D, keys.N)
	g.SetEdge(i, j, cipher)
}

func (g *Graph) decryptEdgeRSA(i, j int, keys *rsa.Keys) {
	cipher, _ := g.GetEdge(i, j)
	plain := rsa.Decrypt(cipher, keys.C, keys.N)
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
		exists, _ := g.CheckEdge(cycle[i-1], cycle[i])
		if !exists {
			return false
		}
	}
	exists, _ := g.CheckEdge(cycle[0], cycle[len(cycle)-1])
	if !exists {
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
			gExists, _ := g.CheckEdge(i, j)
			otherExists, _ := other.CheckEdge(i, j)
			if gExists != otherExists {
				return false
			}
		}
	}
	return true
}
