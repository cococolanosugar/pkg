package jwttoken

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"os"
	"strconv"
	"time"
)

type Claims struct {
	//UserId   int    `json:"userId"`
	//Username string `json:"username"`
	//IsAdmin  bool   `json:"isAdmin"`
	Data string `json:"data"`
	jwt.RegisteredClaims
}

const TokenExpiredTimeInSecond = 3600
const TokenExpiration = "TOKEN_EXPIRATION"
const SecretSalt = "IGAME_SECRET"
const Issuer = "Igame-Issue"

var secretKey interface{}
var tokenExpiration int64

func Generate(data string) (string, error) {
	now := time.Now()
	claims := Claims{
		//UserId:   0,
		//Username: username,
		//IsAdmin:  isAdmin,
		Data: data,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  []string{""},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Second * time.Duration(GetTokenExpirationFromEnv()))),
			ID:        "",
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    Issuer,
			NotBefore: jwt.NewNumericDate(now),
			Subject:   "",
		},
	}
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tokenClaims.SignedString(GetSecretKeyFromEnv())
}

func Parse(token string) (*Claims, error) {
	tokenClaims, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return GetSecretKeyFromEnv(), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := tokenClaims.Claims.(*Claims); ok && tokenClaims.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("failed vaild tokenClaims:%#v", tokenClaims)
}

func GetSecretKeyFromEnv() interface{} {
	if secretKey != nil {
		return secretKey
	}
	secretKey = []byte(SecretSalt)
	key := os.Getenv(SecretSalt)
	if key == "" {
		return secretKey
	}
	secretKey = []byte(key)
	return secretKey
}

func GetTokenExpirationFromEnv() int64 {
	if tokenExpiration != 0 {
		return tokenExpiration
	}
	tokenExpiration = TokenExpiredTimeInSecond
	key := os.Getenv(TokenExpiration)
	if key == "" {
		return tokenExpiration
	}
	t, err := strconv.Atoi(key)
	if err != nil {
		return tokenExpiration
	}
	tokenExpiration = int64(t)
	return tokenExpiration
}
