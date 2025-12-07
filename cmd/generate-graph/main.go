package main

import (
	"flag"
	"fmt"
	"infosec-rgr/internal/gamilton"
	"log"
	"os"
)

// main - Точка входа для программы генерации графа.
// Создает граф, содержащий Гамильтонов цикл, и записывает его в файл.
func main() {
	// Определение и парсинг аргументов командной строки
	fileName := flag.String("name", "graph.txt", "<path/to/file>")        // Имя выходного файла
	size := flag.Int("size", 10, "<number of vertexes>")                  // Количество вершин (размер графа)
	nExtraEdges := flag.Int("extra", 0, "<number of edges except cycle>") // Количество дополнительных рёбер
	flag.Parse()

	// Расчет общего количества рёбер (рёбра цикла + дополнительные)
	nEdges := *size + *nExtraEdges
	// Расчет максимально возможного количества рёбер в простом графе
	maxEdges := *size * (*size - 1) / 2

	// Проверка на превышение максимального количества рёбер
	if nEdges > maxEdges {
		log.Fatalf("Sum of vertexes in cycle and extra vertexes can't be bigger than square size")
	}

	// Создание нового графа с Гамильтоновым циклом
	g, cycle := gamilton.NewGraphWithCycle(*size)
	// Добавление заданного количества случайных дополнительных рёбер
	g.AddNRandEdges(*nExtraEdges)

	// Создание (или перезапись) выходного файла
	file, err := os.Create(*fileName)
	if err != nil {
		log.Fatal(err)
	}
	// Гарантированное закрытие файла при завершении функции
	defer file.Close()

	// Запись в файл первой строки: количество вершин и общее количество рёбер
	fmt.Fprintf(file, "%d %d\n", *size, nEdges)

	// Запись рёбер графа в файл (обход только верхней треугольной части, так как граф неориентированный)
	for i := range *size {
		for j := i + 1; j < *size; j++ {
			if g.EdgeExists(i, j) {
				fmt.Fprintf(file, "%d %d\n", i, j)
			}
		}
	}

	// Запись найденного Гамильтонова цикла в файл (последовательность вершин)
	for i := range cycle {
		fmt.Fprintf(file, "%d ", cycle[i])
	}
}
