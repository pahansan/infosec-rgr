package rsa

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type Keys struct {
	C *big.Int // private
	D *big.Int // public
	N *big.Int // public
}

func GenerateKeys() (*Keys, error) {
	P, err := rand.Prime(rand.Reader, 256)
	if err != nil {
		return nil, err
	}
	Q, err := rand.Prime(rand.Reader, 256)
	if err != nil {
		return nil, err
	}
	d, err := rand.Prime(rand.Reader, 256)
	if err != nil {
		return nil, err
	}
	N := new(big.Int).Mul(P, Q)
	phi := new(big.Int).Mul(P.Sub(P, big.NewInt(1)), Q.Sub(Q, big.NewInt(1)))
	gcd := new(big.Int)
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
	c := new(big.Int).ModInverse(d, phi)

	return &Keys{c, d, N}, nil
}

func Encrypt(m, d, N *big.Int) (*big.Int, error) {
	if m.Cmp(N) != -1 {
		return nil, fmt.Errorf("message size must be less than key N")
	}

	e := new(big.Int).Exp(m, d, N)
	return e, nil
}

func Decrypt(e, c, N *big.Int) (*big.Int, error) {
	if e.Cmp(N) != -1 {
		return nil, fmt.Errorf("message size must be less than key N")
	}

	m := new(big.Int).Exp(e, c, N)
	return m, nil
}
