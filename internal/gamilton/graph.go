package gamilton

import (
	"bufio"
	"infosec-rgr/internal/filereader"
	"infosec-rgr/internal/rsa"
	"math/big"
	"math/rand"
	"os"
)

// Graph представляет граф как матрицу смежности, где каждое ребро - это *big.Int.
type Graph struct {
	v [][]*big.Int
}

// NewGraph создает новый граф заданного размера, инициализируя матрицу нулями.
func NewGraph(size int) *Graph {
	g := &Graph{v: make([][]*big.Int, size)}
	for i := range size {
		g.v[i] = make([]*big.Int, size)
		for j := range size {
			g.v[i][j] = new(big.Int) // Инициализация каждого элемента big.Int
		}
	}
	return g
}

// NewGraphFromFile считывает граф и Гамильтонов цикл из указанного файла.
func NewGraphFromFile(filename string) (*Graph, []int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Считывание количества вершин (size) и количества рёбер (nEdges)
	size, nEdges, err := filereader.Read2Numbers(scanner)
	if err != nil {
		return nil, nil, err
	}

	g := NewGraph(size)
	// Считывание и добавление nEdges рёбер
	for range nEdges {
		r, c, err := filereader.Read2Numbers(scanner)
		if err != nil {
			return nil, nil, err
		}
		g.AddEdge(r, c)
	}

	// Считывание Гамильтонова цикла (ожидается size вершин)
	cycle, err := filereader.ReadSlice(scanner, size)
	if err != nil {
		return nil, nil, err
	}

	return g, cycle, nil
}

// Copy создает глубокую копию графа.
func (g *Graph) Copy() *Graph {
	size := g.Size()
	newGraph := NewGraph(size)
	for i := range size {
		for j := range size {
			// Копирование значения big.Int
			newGraph.v[i][j].Set(g.v[i][j])
		}
	}
	return newGraph
}

// IsomorphicCopy создает изоморфную копию графа и возвращает примененную перестановку.
func (g *Graph) IsomorphicCopy() (*Graph, []int) {
	size := g.Size()

	// Создание случайной перестановки вершин
	permutation := make([]int, size)
	for i := range size {
		permutation[i] = i
	}
	rand.Shuffle(size, func(i, j int) {
		permutation[i], permutation[j] = permutation[j], permutation[i]
	})

	newGraph := NewGraph(size)

	// Применение перестановки к матрице смежности
	for i := range size {
		for j := range size {
			newI := permutation[i] // Новая координата для i
			newJ := permutation[j] // Новая координата для j
			// Ребро (newI, newJ) в новом графе равно ребру (i, j) в исходном
			newGraph.v[newI][newJ].Set(g.v[i][j])
		}
	}
	return newGraph, permutation
}

// IsomorphicOriginal восстанавливает исходный граф G из изоморфной копии H, используя обратную перестановку.
func (g *Graph) IsomorphicOriginal(permutation []int) *Graph {
	size := g.Size()

	// Вычисление обратной перестановки
	inverse := make([]int, size)
	for i, p := range permutation {
		inverse[p] = i // inverse[новое_i] = старое_i
	}

	original := NewGraph(size)

	// Применение обратной перестановки
	for i := range size {
		for j := range size {
			origI := inverse[i] // Восстановленная исходная координата i
			origJ := inverse[j] // Восстановленная исходная координата j
			// Ребро (origI, origJ) в оригинальном графе равно ребру (i, j) в изоморфной копии
			original.v[origI][origJ].Set(g.v[i][j])
		}
	}

	return original
}

// Size возвращает количество вершин в графе.
func (g *Graph) Size() int {
	return len(g.v)
}

// AddEdge добавляет ребро между вершинами i и j (устанавливает значение в 1).
func (g *Graph) AddEdge(i, j int) {
	g.v[i][j].SetInt64(1)
	g.v[j][i].SetInt64(1) // Граф неориентированный
}

// RemoveEdge удаляет ребро между вершинами i и j (устанавливает значение в 0).
func (g *Graph) RemoveEdge(i, j int) {
	g.v[i][j].SetInt64(0)
	g.v[j][i].SetInt64(0)
}

// EdgeExists проверяет, существует ли ребро между i и j, проверяя младший бит (наличие = 1, отсутствие = 0).
func (g *Graph) EdgeExists(i, j int) bool {
	size := g.Size()
	// Проверка границ
	if i >= size || j >= size {
		return false
	}
	// Проверка младшего бита: 1 = существует, 0 = отсутствует
	return g.v[i][j].Bit(0) == 1
}

// SetEdge устанавливает значение ребра (i, j) и (j, i) на заданное big.Int.
func (g *Graph) SetEdge(i, j int, value *big.Int) {
	g.v[i][j].Set(value)
	g.v[j][i].Set(value)
}

// GetEdge возвращает копию значения ребра (i, j).
func (g *Graph) GetEdge(i, j int) *big.Int {
	return new(big.Int).Set(g.v[i][j])
}

// AddNRandEdges добавляет n случайных рёбер в граф.
func (g *Graph) AddNRandEdges(n int) {
	i := 0
	size := g.Size()
	for i < n {
		r := rand.Intn(size)
		c := rand.Intn(size)
		if r == c { // Пропуск петель
			continue
		}
		if g.EdgeExists(r, c) { // Пропуск уже существующих рёбер
			continue
		}
		g.AddEdge(r, c)
		i++
	}
}

// padWithRandomness генерирует случайное большое число, сохраняя информацию о ребре в младшем бите.
// Младший бит: 1, если ребро существует; 0, если не существует.
func (g *Graph) padWithRandomness(i, j int) *big.Int {
	// Генерация случайной части (гарантированно четной, так как сдвигаем влево)
	randomPart := big.NewInt(rand.Int63())
	randomPart.Lsh(randomPart, 1)

	// Установка младшего бита в 1, если ребро существует
	if g.EdgeExists(i, j) {
		randomPart.Or(randomPart, big.NewInt(1))
	}

	return randomPart
}

// AddPadding создает копию графа, где каждое ребро заменено большим числом со случайным padding'ом.
// Младший бит числа указывает на наличие ребра.
func (g *Graph) AddPadding() *Graph {
	size := g.Size()
	newG := NewGraph(size)
	for i := range size {
		for j := i + 1; j < size; j++ { // Обход только верхней треугольной части
			newValue := g.padWithRandomness(i, j)
			newG.SetEdge(i, j, newValue)
		}
	}
	return newG
}

// RemovePadding создает копию графа, удаляя padding и восстанавливая исходные значения рёбер (0 или 1).
func (g *Graph) RemovePadding() *Graph {
	size := g.Size()
	newG := NewGraph(size)
	for i := range size {
		for j := i + 1; j < size; j++ { // Обход только верхней треугольной части
			// Проверка младшего бита: 1 = ребро существует
			if g.EdgeExists(i, j) {
				newG.AddEdge(i, j)
			} else {
				newG.RemoveEdge(i, j)
			}
		}
	}
	return newG
}

// encryptEdgeRSA шифрует значение ребра (i, j) с использованием публичного ключа RSA.
func (g *Graph) encryptEdgeRSA(i, j int, keys *rsa.Keys) {
	plain := g.GetEdge(i, j)
	// Шифрование: m^d mod N
	cipher, _ := rsa.Encrypt(plain, keys.D, keys.N)
	g.SetEdge(i, j, cipher)
}

// decryptEdgeRSA расшифровывает значение ребра (i, j) с использованием приватного ключа RSA.
func (g *Graph) decryptEdgeRSA(i, j int, keys *rsa.Keys) {
	cipher := g.GetEdge(i, j)
	// Расшифрование: e^c mod N
	plain, _ := rsa.Decrypt(cipher, keys.C, keys.N)
	g.SetEdge(i, j, plain)
}

// EncryptRSA создает копию графа и шифрует ВСЕ его рёбра.
func (g *Graph) EncryptRSA(keys *rsa.Keys) *Graph {
	size := g.Size()
	encrypted := g.Copy()

	for i := range size {
		for j := i + 1; j < size; j++ { // Обход только верхней треугольной части
			encrypted.encryptEdgeRSA(i, j, keys)
		}
	}
	return encrypted
}

// DecryptRSA создает копию графа и расшифровывает ВСЕ его рёбра.
func (g *Graph) DecryptRSA(keys *rsa.Keys) *Graph {
	size := g.Size()
	decrypted := g.Copy()

	for i := range size {
		for j := i + 1; j < size; j++ { // Обход только верхней треугольной части
			decrypted.decryptEdgeRSA(i, j, keys)
		}
	}
	return decrypted
}

// EncryptCycleRSA создает копию графа и шифрует ТОЛЬКО рёбра, входящие в заданный цикл.
func (g *Graph) EncryptCycleRSA(keys *rsa.Keys, cycle []int) *Graph {
	size := g.Size()
	encrypted := g.Copy()

	// Шифрование рёбер цикла (от i-1 к i)
	for i := 1; i < size; i++ {
		encrypted.encryptEdgeRSA(cycle[i-1], cycle[i], keys)
	}
	// Шифрование замыкающего ребра
	encrypted.encryptEdgeRSA(cycle[0], cycle[size-1], keys)
	return encrypted
}

// DecryptCycleRSA создает копию графа и расшифровывает ТОЛЬКО рёбра, входящие в заданный цикл.
func (g *Graph) DecryptCycleRSA(keys *rsa.Keys, cycle []int) *Graph {
	size := g.Size()
	decrypted := g.Copy()

	// Расшифрование рёбер цикла (от i-1 к i)
	for i := 1; i < size; i++ {
		decrypted.decryptEdgeRSA(cycle[i-1], cycle[i], keys)
	}
	// Расшифрование замыкающего ребра
	decrypted.decryptEdgeRSA(cycle[0], cycle[size-1], keys)
	return decrypted
}

// Equals сравнивает два графа (включая значения padding/шифротекста), возвращая true, если они идентичны.
func (g *Graph) Equals(other *Graph) bool {
	size := g.Size()
	if size != other.Size() {
		return false
	}
	for i := range size {
		for j := i + 1; j < size; j++ { // Обход только верхней треугольной части
			if g.v[i][j].Cmp(other.v[i][j]) != 0 {
				return false // Сравнение big.Int значений
			}
		}
	}
	return true
}

// CheckCycle проверяет, что все рёбра в заданном цикле существуют в графе (т.е. младший бит = 1).
func (g *Graph) CheckCycle(cycle []int) bool {
	for i := 1; i < len(cycle); i++ {
		if !g.EdgeExists(cycle[i-1], cycle[i]) {
			return false
		}
	}
	// Проверка замыкающего ребра
	if !g.EdgeExists(cycle[0], cycle[len(cycle)-1]) {
		return false
	}
	return true
}

// SameAs сравнивает два графа, игнорируя padding, проверяя только наличие рёбер (младший бит).
func (g *Graph) SameAs(other *Graph) bool {
	size := g.Size()
	if size != other.Size() {
		return false
	}
	for i := range size {
		for j := i + 1; j < size; j++ { // Обход только верхней треугольной части
			// Сравнение только факта существования ребра (младшего бита)
			if g.EdgeExists(i, j) != other.EdgeExists(i, j) {
				return false
			}
		}
	}
	return true
}
