package test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func generateSalt() []byte {
	salt := make([]byte, 16)
	rand.Read(salt)
	return salt
}

func hashPassword(password string, salt []byte) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword(append(salt, []byte(password)...), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return hashedPassword, nil
}

type User struct {
	Username string
}

var userDatabase = map[string]struct {
	Salt           []byte
	HashedPassword []byte
}{}

func RegisterUser(username, password string) error {
	salt := generateSalt()

	hashedPassword, err := hashPassword(password, salt)
	if err != nil {
		return err
	}

	userDatabase[username] = struct {
		Salt           []byte
		HashedPassword []byte
	}{
		Salt:           salt,
		HashedPassword: hashedPassword,
	}

	return nil
}

func LoginUser(username, password string) error {
	user, ok := userDatabase[username]
	if !ok {
		return errors.New("user not found")
	}

	hashedPassword, err := hashPassword(password, user.Salt)
	if err != nil {
		return err
	}

	if !bytes.Equal(hashedPassword, user.HashedPassword) {
		return errors.New("invalid password")
	}

	fmt.Println("Authentication successful for user:", username)
	return nil
}

// func storeUser(username string, salt, hashedPassword []byte) {

// 	userDatabase[username] = struct {
// 		Salt           []byte
// 		HashedPassword []byte
// 	}{
// 		Salt:           salt,
// 		HashedPassword: hashedPassword,
// 	}

// }
