package filereader

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

func Read2Numbers(scanner *bufio.Scanner) (int, int, error) {
	if !scanner.Scan() {
		return 0, 0, fmt.Errorf("bad file format")
	}
	line := scanner.Text()
	var n1, n2 int
	n, err := fmt.Sscanf(line, "%d %d", &n1, &n2)
	if err != nil {
		return 0, 0, err
	}
	if n != 2 {
		return 0, 0, fmt.Errorf("bad file format")
	}
	return n1, n2, nil
}

func ReadSlice(scanner *bufio.Scanner, size int) ([]int, error) {
	if !scanner.Scan() {
		return nil, fmt.Errorf("bad file format")
	}

	line := scanner.Text()
	fields := strings.Fields(line)

	if len(fields) != size {
		return nil, fmt.Errorf("bad file format")
	}

	array := make([]int, size)
	for i, v := range fields {
		num, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("bad file format")
		}
		array[i] = num
	}

	return array, nil
}
