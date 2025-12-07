package gamilton

import (
	"fmt"
	"infosec-rgr/internal/rsa"
	"math/rand"
)

// GamiltonCycle генерирует случайную перестановку вершин, которая служит Гамильтоновым циклом.
func GamiltonCycle(size int) []int {
	cycle := make([]int, size)
	// Инициализация вершин от 0 до size-1
	for i := range size {
		cycle[i] = i
	}
	// Случайное перемешивание вершин
	rand.Shuffle(size, func(i, j int) {
		cycle[i], cycle[j] = cycle[j], cycle[i]
	})
	return cycle
}

// NewGraphWithCycle создает новый граф заданного размера, гарантированно содержащий Гамильтонов цикл.
func NewGraphWithCycle(size int) (*Graph, []int) {
	// Генерация случайного Гамильтонова цикла
	cycle := GamiltonCycle(size)
	// Создание пустого графа
	graph := NewGraph(size)
	// Добавление рёбер цикла (от i-1 к i)
	for i := 1; i < size; i++ {
		graph.AddEdge(cycle[i-1], cycle[i])
	}
	// Замыкание цикла (от последней вершины к первой)
	graph.AddEdge(cycle[0], cycle[size-1])
	return graph, cycle
}

// transformCycle применяет перестановку к вершинам Гамильтонова цикла.
func transformCycle(cycle, permutations []int) []int {
	newCycle := make([]int, len(cycle))
	for i := range len(cycle) {
		newCycle[i] = permutations[cycle[i]]
	}
	return newCycle
}

// Protocol реализует один раунд протокола с нулевым разглашением для задачи о Гамильтоновом цикле.
// g - исходный граф G (Алиса утверждает, что знает Гамильтонов цикл в нем).
// cycle - Гамильтонов цикл в G.
// q - вопрос, задаваемый Бобом (0 или 1).
// keys - ключи RSA Алисы.
func Protocol(g *Graph, cycle []int, q int, keys *rsa.Keys) bool {
	// Алиса (Prover):
	// 1. Создание изоморфной копии H графа G и запоминание перестановки perms.
	h, perms := g.IsomorphicCopy()
	// 2. Добавление случайного заполнения (padding) к рёбрам H.
	hTilda := h.AddPadding()
	// 3. Шифрование всех рёбер H' с помощью RSA.
	f := hTilda.EncryptRSA(keys)

	// Боб (Verifier) задает вопрос q:
	switch q {
	case 0: // Вопрос 1: Докажи знание Гамильтонова цикла в H
		fmt.Println("Боб задаёт вопрос: Каков гамильтонов цикл для графа H?")
		fmt.Print("Алиса расшифровывает рёбра цикла: ")
		// Алиса вычисляет Гамильтонов цикл в H, применяя перестановку к циклу G
		newCycle := transformCycle(cycle, perms)
		// Алиса расшифровывает только рёбра, входящие в newCycle
		fDecrypted := f.DecryptCycleRSA(keys, newCycle)
		// Боб проверяет, что расшифрованные рёбра образуют цикл (т.е. они = 1)
		if !fDecrypted.CheckCycle(newCycle) {
			return false
		}
		fmt.Print("Боб убедился в наличии цикла. ")
		// Боб проверяет, что расшифрованные рёбра при повторном шифровании
		// совпадают с исходными зашифрованными рёбрами F
		fmt.Print("Боб шифрует цикл снова: ")
		fEncrypted := fDecrypted.EncryptCycleRSA(keys, newCycle)
		if f.Equals(fEncrypted) { // Сравнение F_зашифрованного_цикла с F
			fmt.Print("граф снова равен F. ")
			return true
		} else {
			return false
		}
	case 1: // Вопрос 2: Докажи, что H изоморфен G
		fmt.Println("Боб задаёт вопрос: Действительно ли граф H изоморфен G?")
		fmt.Print("Алиса демонстрирует перестановки: ")
		// Алиса расшифровывает ВЕСЬ граф H'
		fDecrypted := f.DecryptRSA(keys)
		// Боб удаляет padding из H' и применяет обратную перестановку для получения исходного G
		original := fDecrypted.IsomorphicOriginal(perms)
		// Боб сравнивает восстановленный G с исходным G
		if !original.SameAs(g) {
			return false
		}
		fmt.Print("G и H совпадают. ")
		// Боб проверяет, что расшифрованный H' при повторном шифровании
		// совпадает с исходным зашифрованным F
		fmt.Print("Боб повторно шифрует H: ")
		fEncrypted := fDecrypted.EncryptRSA(keys)
		if !fEncrypted.Equals(f) { // Сравнение F_зашифрованного_H' с F
			return false
		}
		fmt.Print("H == F. ")
		return true
	default:
		return false
	}
}