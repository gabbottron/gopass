package gopass

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	mathrand "math/rand"

	"golang.org/x/crypto/argon2"
)

type Config struct {
	MinPassLength       int // minimum allowed character length
	MaxPassLength       int // maximum allowed character length
	ReqSpecialChars     int // minimum number of special characters in password
	ReqNumbers          int // minimum number of numeric characters in password
	MaxRepeatedChars    int // maximum number of repeated characters in password
	MaxNumericSeqLength int // maximum number of sequential numeric characters in password (e.g. 3 -> 1234 BAD)

	// Settings for Argon2
	HashTime      uint32 // ???
	HashMemory    uint32 // in mb, minimum 64
	HashThreads   uint8  // minimum 4
	HashKeyLength uint32 // minimum 128
	SaltBytes     int    // minimum 128
}

type PasswordValidationError struct {
	Errors []string
}

func (e *PasswordValidationError) Error() string {
	return fmt.Sprintf("Password validation failed: %s", strings.Join(e.Errors, ", "))
}

// gopass holds the instance level variable for settings
type gopass struct {
	settings Config
}

// Since this library is meant to be used in production systems that are generating and
// storing passwords, any program that is using this library should fail at startup
// if we can't generate good random values. Doing it this way prevents runtime errors
// that happen periodically in an API given the user creation will only happen intermittently
func init() {
	// if no cryptographically secure PRNG is available it is unsafe to use this library on this system
	if err := assertAvailablePRNG(); err != nil {
		panic(fmt.Errorf("crypto initialization failed: %v", err))
	}

	mathrand.Seed(time.Now().UnixNano())
}

// New creates a new Gopass instance and assigns the provided Settings object
func New(settings Config) (*gopass, error) {
	if err := checkCryptoSettingsForSanity(settings); err != nil {
		return nil, fmt.Errorf("invalid crypto settings: %w", err)
	}

	return &gopass{settings: settings}, nil
}

// temporary
func (g *gopass) ShowSettings() {
	fmt.Printf("MinPassLength: %d\n", g.settings.MinPassLength)
}

// this will generate a password hash and salt using the Argon2 lib IDKey method
func (g *gopass) HashAndSalt(plainPass string) ([]byte, []byte, error) {
	pass_bytes := []byte(plainPass)

	salt, err := generateRandomBytes(g.settings.SaltBytes)
	if err != nil {
		return nil, nil, err
	}

	key := argon2.IDKey(pass_bytes, salt, g.settings.HashTime, g.settings.HashMemory*1024, g.settings.HashThreads, g.settings.HashKeyLength)

	return key, salt, nil
}

func (g *gopass) GenerateRandomPass(length int) (string, error) {
	return generateRandomStringURLSafe(length)
}

// will hash and salt plainPass with provided salt and compare it to hashedPass
func (g *gopass) ComparePasswords(hashedPass []byte, salt []byte, plainPass string) bool {
	plainPassHashed := g.hashAndSaltWithSalt(plainPass, salt)

	if !reflect.DeepEqual(hashedPass, plainPassHashed) {
		return false
	}

	return true
}

// Checks the password supplied against our password configuration standards
// and returns prescriptive error messages
func (g *gopass) ValidatePassword(password string) error {
	var errors []string

	if len(password) < g.settings.MinPassLength {
		errors = append(errors, fmt.Sprintf("Password length must be at least %d characters", g.settings.MinPassLength))
	}
	if len(password) > g.settings.MaxPassLength {
		errors = append(errors, fmt.Sprintf("Password length cannot exceed %d characters", g.settings.MaxPassLength))
	}
	if countSpecialChars(password) < g.settings.ReqSpecialChars {
		errors = append(errors, fmt.Sprintf("Password must contain at least %d special characters", g.settings.ReqSpecialChars))
	}
	if countNumbers(password) < g.settings.ReqNumbers {
		errors = append(errors, fmt.Sprintf("Password must contain at least %d numbers", g.settings.ReqNumbers))
	}
	if maxRepeatedChars(password) > g.settings.MaxRepeatedChars {
		errors = append(errors, fmt.Sprintf("Password cannot contain more than %d repeated characters in sequence", g.settings.MaxRepeatedChars))
	}

	if len(errors) > 0 {
		return &PasswordValidationError{Errors: errors}
	}

	return nil
}

// SpeedTest generates and hashes a specified number of random passwords, measuring the duration of the operation.
func (g *gopass) SpeedTest(numPasswords int, minPassLength int, maxPassLength int) float64 {
	start := time.Now() // Start the timer

	for i := 0; i < numPasswords; i++ {
		passLength := mathrand.Intn(maxPassLength - minPassLength + 1)
		password, err := g.GenerateRandomPass(passLength) // Generate a random password
		if err != nil {
			fmt.Println("Error generating password:", err)
			continue
		}

		_, _, err = g.HashAndSalt(password) // Hash and salt the generated password
		if err != nil {
			fmt.Println("Error hashing password:", err)
			continue
		}
	}

	elapsed := time.Since(start) // Calculate the elapsed time
	return elapsed.Seconds()     // Return the duration in seconds
}

// will hash password with supplied salt and return it
func (g *gopass) hashAndSaltWithSalt(plainPass string, salt []byte) []byte {
	pass_bytes := []byte(plainPass)

	key := argon2.IDKey(pass_bytes, salt, g.settings.HashTime, g.settings.HashMemory*1024, g.settings.HashThreads, g.settings.HashKeyLength)

	return key
}

func generateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	bytes, err := generateRandomBytes(n)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return string(bytes), nil
}

// GenerateRandomStringURLSafe returns a URL-safe, base64 encoded
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func generateRandomStringURLSafe(n int) (string, error) {
	b, err := generateRandomBytes(n)
	return base64.URLEncoding.EncodeToString(b), err
}

func assertAvailablePRNG() error {
	// Assert that a cryptographically secure PRNG is available.
	// Panic otherwise.
	buf := make([]byte, 1)

	_, err := io.ReadFull(rand.Reader, buf)
	return err
}

func checkCryptoSettingsForSanity(settings Config) error {
	if settings.HashTime < 1 {
		return errors.New("HashTime must be >= 1")
	}
	if settings.HashMemory < 64 {
		return errors.New("HashMemory must be >= 64")
	}
	if settings.HashThreads < 4 {
		return errors.New("HashThreads must be >= 4")
	}
	if settings.HashKeyLength < 128 {
		return errors.New("HashKeyLength must be >= 128")
	}
	if settings.SaltBytes < 128 {
		return errors.New("SaltBytes must be >= 128")
	}

	return nil
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}