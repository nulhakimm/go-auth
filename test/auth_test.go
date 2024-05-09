package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	Username string `json:"username"`
	*jwt.RegisteredClaims
}

func TestPrint(t *testing.T) {
	fmt.Println("Hello World")
}

func GenerateAndStorePrivateKey(filePath string) (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	derStream, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EC private key to DER: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derStream,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	if pemBytes == nil {
		return nil, errors.New("failed to encode private key to PEM format")
	}

	err = os.WriteFile(filePath, pemBytes, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write private key to file: %v", err)
	}

	return privateKey, nil
}

func LoadPrivateKey(filepath string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("failed to decode private key PEM block")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA private key: %v", err)
	}

	return privateKey, nil
}

func GenerateToken(privateKey *ecdsa.PrivateKey) (string, *ecdsa.PrivateKey, error) {

	claim := Claims{
		Username: "jhon doe",
		RegisteredClaims: &jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claim)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", nil, err
	}

	return tokenString, privateKey, nil

}

func VerifyToken(tokenString string, publicKey *ecdsa.PublicKey) (*Claims, error) {

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Check if the signing method is ES256.
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Return the public key for verification.
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	// Check if the token is valid.
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")

}

func TestGenerateToken(t *testing.T) {

	privateKey, err := LoadPrivateKey("private.pem")
	if err != nil {
		panic(err)
	}

	token, privateLey, err := GenerateToken(privateKey)
	if err != nil {
		panic(err)
	}

	fmt.Println("Generated Token:", token)

	claims, err := VerifyToken(token, &privateLey.PublicKey)
	if err != nil {
		panic(err)
	}

	fmt.Println("Verified Token Claims:", claims)
}

func TestLoginRegister(t *testing.T) {

	// Register a new user
	if err := RegisterUser("john_doe", "secret123"); err != nil {
		t.Errorf("Error registering user: %v", err)
		return
	}

	// Login with the registered user
	if err := LoginUser("john_doe", "secret123"); err != nil {
		t.Errorf("Error logging in: %v", err)
		return
	}

}
