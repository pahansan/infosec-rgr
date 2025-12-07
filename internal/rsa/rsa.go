package rsa

import (
	"crypto/rand"
	"log"
	"math/big"
)

type Keys struct {
	C *big.Int // private
	D *big.Int // public
	N *big.Int // public
}

func GenerateKeys() Keys {
	P, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		log.Fatalf("Something went wrong:%s", err.Error())
	}
	Q, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		log.Fatalf("Something went wrong:%s", err.Error())
	}
	d, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		log.Fatalf("Something went wrong:%s", err.Error())
	}
	N := new(big.Int).Mul(P, Q)
	phi := new(big.Int).Mul(P.Sub(P, big.NewInt(1)), Q.Sub(Q, big.NewInt(1)))
	gcd := new(big.Int)
	for {
		gcd.GCD(nil, nil, d, phi)
		if gcd.Cmp(big.NewInt(1)) == 0 {
			break
		}
		d, err = rand.Prime(rand.Reader, 1024)
		if err != nil {
			log.Fatalf("Something went wrong:%s", err.Error())
		}
	}
	c := new(big.Int).ModInverse(d, phi)

	return Keys{c, d, N}
}

func Encrypt(m, d, N *big.Int) *big.Int {
	if m.Cmp(N) != -1 {
		return nil
	}

	e := new(big.Int).Exp(m, d, N)
	return e
}

func Decrypt(e, c, N *big.Int) *big.Int {
	if e.Cmp(N) != -1 {
		return nil
	}

	m := new(big.Int).Exp(e, c, N)
	return m
}
