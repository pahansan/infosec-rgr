package gamilton

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
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
	for i := range g.v {
		g.v[i] = make([]*big.Int, size)
		for j := range g.v[i] {
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
	other := NewGraph(g.Size())
	for i := range other.v {
		for j := range other.v[i] {
			other.v[i][j].Set(g.v[i][j])
		}
	}
	return other
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

	other := NewGraph(size)

	for i := range size {
		for j := range size {
			newI := permutation[i]
			newJ := permutation[j]
			other.v[newI][newJ].Set(g.v[i][j])
		}
	}
	return other, permutation
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
	return g.v[i][j].Cmp(big.NewInt(0)) == 1, nil
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

func (g *Graph) EncryptRSA(publicKey *rsa.PublicKey) (*Graph, error) {
	size := g.Size()
	encrypted := NewGraph(size)

	for i := range size {
		for j := i + 1; j < size; j++ {
			plaintext := g.padWithRandomness(i, j)

			ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext.Bytes(), nil)
			if err != nil {
				return nil, err
			}

			encrypted.SetEdge(i, j, new(big.Int).SetBytes(ciphertext))
		}
	}
	return encrypted, nil
}

func (g *Graph) DecryptRSA(privateKey *rsa.PrivateKey) (*Graph, error) {
	size := g.Size()
	decrypted := NewGraph(size)

	for i := range size {
		for j := i + 1; j < size; j++ {
			ciphertext := g.v[i][j].Bytes()

			plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
			if err != nil {
				return nil, err
			}

			decrypted.SetEdge(i, j, new(big.Int).SetBytes(plaintext))
		}
	}
	return decrypted, nil
}

func (g *Graph) EncryptCycleRSA(publicKey *rsa.PublicKey, cycle []int) (*Graph, error) {
	size := g.Size()
	encrypted := NewGraph(size)

	for i := 1; i < size; i++ {
		plainText := g.v[i-1][i].Bytes()

		cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plainText, nil)
		if err != nil {
			return nil, err
		}

		encrypted.SetEdge(i-1, i, new(big.Int).SetBytes(cipherText))
	}
	plainText := g.v[0][size-1].Bytes()

	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plainText, nil)
	if err != nil {
		return nil, err
	}

	encrypted.SetEdge(0, size-1, new(big.Int).SetBytes(cipherText))
	return encrypted, nil
}

func (g *Graph) DecryptCycleRSA(privateKey *rsa.PrivateKey, cycle []int) (*Graph, error) {
	size := g.Size()
	decrypted := NewGraph(size)

	for i := 1; i < size; i++ {
		ciphertext := g.v[i-1][i].Bytes()

		plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
		if err != nil {
			return nil, err
		}

		decrypted.SetEdge(i-1, i, new(big.Int).SetBytes(plaintext))
	}
	ciphertext := g.v[0][size-1].Bytes()

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	decrypted.SetEdge(0, size-1, new(big.Int).SetBytes(plaintext))
	return decrypted, nil
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
		exists, _ := g.CheckEdge(i-1, i)
		if !exists {
			return false
		}
	}
	exists, _ := g.CheckEdge(0, len(cycle)-1)
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
