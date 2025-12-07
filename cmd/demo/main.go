package main

import (
	"flag"
	"fmt"
	"infosec-rgr/internal/gamilton"
	"infosec-rgr/internal/rsa"
	"log"
	"math/big"
	"math/rand"
)

// main - Точка входа для демонстрации протокола
// Считывает граф, генерирует ключи RSA и запускает T раундов протокола
func main() {
	// Определение и парсинг аргументов командной строки
	fileName := flag.String("name", "graph.txt", "<path/to/file>") // Имя файла с графом
	t := flag.Int("t", 10, "<count of quetions>")                  // Количество раундов протокола
	flag.Parse()

	// Считывание графа и его Гамильтонова цикла из файла
	g, cycle, err := gamilton.NewGraphFromFile(*fileName)
	if err != nil {
		log.Fatal(err)
	}
	// Генерация пары ключей RSA для Алисы
	keys, err := rsa.GenerateKeys()
	if err != nil {
		log.Fatal(err)
	}

	// Инициализация вероятности обмана (по умолчанию 0.5 для первого раунда)
	lie := big.NewFloat(0.5)
	// Запуск T раундов протокола
	for i := range *t {
		fmt.Print(i+1, ": ")
		// Выполнение одного раунда протокола. Случайным образом выбирается вопрос (0 или 1).
		status := gamilton.Protocol(g, cycle, rand.Intn(2), keys)
		if status == true {
			fmt.Println("Проверка успешна.")
		} else {
			fmt.Println("Проверка не прошла. Обман раскрыт.")
			// Если один раунд не пройден, обман раскрыт, и программа завершается
			return
		}
		// Вывод текущей вероятности обмана (уменьшается в 2 раза с каждым успешным раундом)
		fmt.Print("Вероятность обмана: ", lie, "\n\n")
		// Обновление вероятности обмана: P_обмана(i) = P_обмана(i-1) * 0.5
		lie.Mul(lie, lie)
	}
}
