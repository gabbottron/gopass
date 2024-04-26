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
	// Minimum allowed password character length.
	MinPassLength int

	// Maximum allowed password character length.
	MaxPassLength int

	// Minimum number of special characters required in the password.
	ReqSpecialChars int

	// Minimum number of numeric characters required in the password.
	ReqNumbers int

	// Maximum number of consecutive repeated characters allowed in the password.
	MaxRepeatedChars int

	// Maximum length of sequential numeric characters allowed in the password (e.g., 1234 is bad).
	MaxNumericSeqLength int

	// Argon2 settings:
	//  - HashTime: The number of iterations for password hashing (higher is more secure, but slower).
	//  - HashMemory: The memory cost for password hashing (higher is more secure, but uses more memory).
	//  - HashThreads: The number of threads to use for parallel password hashing.
	//  - HashKeyLength: The desired length of the derived key from Argon2 (in bytes).
	//  - SaltBytes: The length of the random salt to use for password hashing (in bytes).
	HashTime      uint32
	HashMemory    uint32 // in MB
	HashThreads   uint8
	HashKeyLength uint32
	SaltBytes     int
}

type PasswordValidationError struct {
	Errors []string // list of prescriptive error messages
}

func (e *PasswordValidationError) Error() string {
	return fmt.Sprintf("Password validation failed: %s", strings.Join(e.Errors, ", "))
}

// gopass holds the instance level variable for settings
type gopass struct {
	settings Config // password library configuration
}

// Since this library is meant to be used in production systems that are generating and
// storing passwords, any program that is using this library should fail at startup
// if we can't generate good random values. Doing it this way prevents runtime errors
// that happen periodically in an API given the user creation will only happen intermittently
func init() {
	// Enforce presence of a cryptographically secure random number generator (CSPRNG).
	// If unavailable, panic to prevent insecure password storage.
	if err := assertAvailablePRNG(); err != nil {
		panic(fmt.Errorf("crypto initialization failed: %v", err))
	}

	// Seed the math/rand package for random password generation.
	mathrand.Seed(time.Now().UnixNano())
}

// New creates a new Gopass instance and validates the provided configuration settings.
// Returns an error if the settings are invalid.
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

// HashAndSalt generates a random salt, hashes the provided password using Argon2id,
// and returns the derived key and salt.
func (g *gopass) HashAndSalt(plainPass string) ([]byte, []byte, error) {
	pass_bytes := []byte(plainPass)

	salt, err := generateRandomBytes(g.settings.SaltBytes)
	if err != nil {
		return nil, nil, err
	}

	key := argon2.IDKey(pass_bytes, salt, g.settings.HashTime, g.settings.HashMemory*1024, g.settings.HashThreads, g.settings.HashKeyLength)

	return key, salt, nil
}

// GenerateRandomPass generates a random URL-safe, base64 encoded string of the specified length.
func (g *gopass) GenerateRandomPass(length int) (string, error) {
	return generateRandomStringURLSafe(length)
}

// ComparePasswords compares a plain text password against a hashed password and salt.
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

// hashAndSaltWithSalt will hash password with supplied salt and return it
func (g *gopass) hashAndSaltWithSalt(plainPass string, salt []byte) []byte {
	pass_bytes := []byte(plainPass)

	key := argon2.IDKey(pass_bytes, salt, g.settings.HashTime, g.settings.HashMemory*1024, g.settings.HashThreads, g.settings.HashKeyLength)

	return key
}

// generateRandomString will generate a random string of n length with the provided letters
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

// assertAvailablePRNG will return an error if the system can't generate
// sufficiently random values
func assertAvailablePRNG() error {
	// Assert that a cryptographically secure PRNG is available.
	// Panic otherwise.
	buf := make([]byte, 1)

	_, err := io.ReadFull(rand.Reader, buf)
	return err
}

// checkCryptoSettingsForSanity will enforce sensible defaults
// by returning prescriptive errors if validation fails based
// on settings
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

// generateRandomBytes will return a random byte slice
// for use as salt
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
