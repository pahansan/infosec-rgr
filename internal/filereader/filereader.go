package filereader

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// Read2Numbers считывает одну строку из сканера, ожидая два целых числа, разделенных пробелом.
// Возвращает два считанных числа или ошибку, если формат строки не соответствует ожиданиям.
func Read2Numbers(scanner *bufio.Scanner) (int, int, error) {
	// Попытка считать следующую строку
	if !scanner.Scan() {
		// Если сканер не смог считать строку (например, достигнут конец файла)
		return 0, 0, fmt.Errorf("bad file format: expected two numbers, but reached end of file")
	}
	line := scanner.Text()
	var n1, n2 int
	// Считывание двух целых чисел из строки
	n, err := fmt.Sscanf(line, "%d %d", &n1, &n2)
	if err != nil {
		// Ошибка преобразования или форматирования
		return 0, 0, err
	}
	if n != 2 {
		// Прочитано не 2 числа
		return 0, 0, fmt.Errorf("bad file format: expected 2 numbers, got %d", n)
	}
	return n1, n2, nil
}

// ReadSlice считывает одну строку из сканера и парсит ее как слайс целых чисел заданного размера.
// Возвращает слайс целых чисел или ошибку, если формат строки или размер неверны.
func ReadSlice(scanner *bufio.Scanner, size int) ([]int, error) {
	// Попытка считать следующую строку
	if !scanner.Scan() {
		return nil, fmt.Errorf("bad file format: expected a slice of numbers, but reached end of file")
	}

	line := scanner.Text()
	// Разбиение строки на отдельные поля (числа) по пробелам
	fields := strings.Fields(line)

	// Проверка, что количество элементов соответствует ожидаемому размеру
	if len(fields) != size {
		return nil, fmt.Errorf("bad file format: expected %d elements, got %d", size, len(fields))
	}

	array := make([]int, size)
	// Преобразование каждого строкового поля в целое число
	for i, v := range fields {
		num, err := strconv.Atoi(v)
		if err != nil {
			// Ошибка при попытке преобразования элемента в число
			return nil, fmt.Errorf("bad file format: element '%s' is not an integer", v)
		}
		array[i] = num
	}

	return array, nil
}
