package main

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func checkerr(err error) {
	if err != nil {
		panic(err)
	}
}

type TrueClaims struct {
	Key string `json:"Key"`
	jwt.RegisteredClaims
}

func GenerateJWT(key string) (token string, err error) {
	claim := TrueClaims{
		Key: key,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			Issuer:    "REDROCK@2023",
		},
	}
	token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claim).SignedString([]byte(secret_key))
	return token, err
}

func ParseJWT(token string) (Username string, err error) {
	claim := TrueClaims{}
	_, err = jwt.ParseWithClaims(token, &claim, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret_key), nil
	})
	if err != nil {
		return "", err
	}
	return claim.Key, err
}
