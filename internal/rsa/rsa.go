package rsa

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Keys хранит компоненты ключей RSA.
// C (private) - приватная экспонента (d' в некоторых обозначениях)
// D (public) - публичная экспонента (e в некоторых обозначениях)
// N (public) - модуль
type Keys struct {
	C *big.Int // private key exponent
	D *big.Int // public key exponent
	N *big.Int // modulus
}

// GenerateKeys генерирует пару ключей RSA.
func GenerateKeys() (*Keys, error) {
	// Генерация двух больших простых чисел P и Q (256 бит)
	P, err := rand.Prime(rand.Reader, 256)
	if err != nil {
		return nil, err
	}
	Q, err := rand.Prime(rand.Reader, 256)
	if err != nil {
		return nil, err
	}
	// Генерация случайной публичной экспоненты D (должна быть взаимно простой с phi)
	d, err := rand.Prime(rand.Reader, 256)
	if err != nil {
		return nil, err
	}
	// Вычисление модуля N = P * Q
	N := new(big.Int).Mul(P, Q)
	// Вычисление функции Эйлера phi(N) = (P-1) * (Q-1)
	phi := new(big.Int).Mul(P.Sub(P, big.NewInt(1)), Q.Sub(Q, big.NewInt(1)))
	gcd := new(big.Int)
	// Проверка, что НОД(d, phi) = 1. Если нет, генерируем новое d.
	for {
		gcd.GCD(nil, nil, d, phi)
		if gcd.Cmp(big.NewInt(1)) == 0 {
			break
		}
		d, err = rand.Prime(rand.Reader, 256)
		if err != nil {
			return nil, err
		}
	}
	// Вычисление приватной экспоненты C = d^(-1) mod phi (обратный элемент по модулю)
	c := new(big.Int).ModInverse(d, phi)

	return &Keys{c, d, N}, nil
}

// Encrypt выполняет шифрование RSA: e = m^d mod N.
// Используется публичная экспонента D для шифрования.
func Encrypt(m, d, N *big.Int) (*big.Int, error) {
	// Проверка, что сообщение m меньше модуля N
	if m.Cmp(N) != -1 {
		return nil, fmt.Errorf("message size must be less than key N")
	}

	// Вычисление модульной экспоненты
	e := new(big.Int).Exp(m, d, N)
	return e, nil
}

// Decrypt выполняет расшифрование RSA: m = e^c mod N.
// Используется приватная экспонента C для расшифрования.
func Decrypt(e, c, N *big.Int) (*big.Int, error) {
	// Проверка, что шифротекст e меньше модуля N
	if e.Cmp(N) != -1 {
		return nil, fmt.Errorf("message size must be less than key N")
	}

	// Вычисление модульной экспоненты
	m := new(big.Int).Exp(e, c, N)
	return m, nil
}
