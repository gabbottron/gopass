package gopass_test

import (
	"testing"

	"github.com/gabbottron/gopass"
)

func TestConfigValidation(t *testing.T) {
	// Test cases for invalid configurations
	invalidConfigs := []gopass.Config{
		{MinPassLength: 0},        // Minimum password length must be greater than 0
		{MaxPassLength: 7},        // Maximum password length must be greater than minimum
		{ReqSpecialChars: -1},     // Minimum special characters cannot be negative
		{ReqNumbers: -2},          // Minimum numbers cannot be negative
		{MaxRepeatedChars: -3},    // Maximum repeated chars cannot be negative
		{MaxNumericSeqLength: -4}, // Maximum numeric seq cannot be negative
		{HashTime: 0},             // Hash time must be greater than 0
		{HashMemory: 0},           // Hash memory must be greater than 0
		{HashThreads: 0},          // Hash threads must be greater than 0
		{HashKeyLength: 0},        // Hash key length must be greater than 0
		{SaltBytes: 0},            // Salt bytes must be greater than 0
	}

	for _, config := range invalidConfigs {
		_, err := gopass.New(config)
		if err == nil {
			t.Errorf("Expected error for invalid config: %v", config)
		}
	}

	// Test case for valid configuration
	validConfig := gopass.Config{
		MinPassLength:       8,
		MaxPassLength:       22,
		ReqSpecialChars:     1,
		ReqNumbers:          1,
		MaxRepeatedChars:    2,
		MaxNumericSeqLength: 3,
		HashTime:            1,
		HashMemory:          1024,
		HashThreads:         16,
		HashKeyLength:       128,
		SaltBytes:           128,
	}

	_, err := gopass.New(validConfig)
	if err != nil {
		t.Errorf("Unexpected error for valid config: %v", err)
	}
}

func TestPasswordValidation(t *testing.T) {
	gp, err := gopass.New(gopass.Config{
		MinPassLength:       8,
		MaxPassLength:       22,
		ReqSpecialChars:     1,
		ReqNumbers:          1,
		MaxRepeatedChars:    2,
		MaxNumericSeqLength: 3,
		HashTime:            1,
		HashMemory:          1024,
		HashThreads:         16,
		HashKeyLength:       128,
		SaltBytes:           128,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test cases for invalid passwords
	invalidPasswords := []string{
		"short",            // Less than minimum length
		"verylongpassword", // More than maximum length
		"password",         // No special characters
		"n0numb3rs",        // No numbers
		"aaaaaaA1!",        // More than 2 repeated characters
		"123456",           // Sequential numeric sequence
	}

	for _, password := range invalidPasswords {
		err := gp.ValidatePassword(password)
		if err == nil {
			t.Errorf("Expected error for invalid password: %s", password)
		}
	}

	// Test case for valid password
	validPassword := "P@ssw0rd!"
	err = gp.ValidatePassword(validPassword)
	if err != nil {
		t.Errorf("Unexpected error for valid password: %s", validPassword)
	}
}

func TestHashAndSalt(t *testing.T) {
	gp, err := gopass.New(gopass.Config{
		MinPassLength:       8,
		MaxPassLength:       22,
		ReqSpecialChars:     1,
		ReqNumbers:          1,
		MaxRepeatedChars:    2,
		MaxNumericSeqLength: 3,
		HashTime:            1,
		HashMemory:          1024,
		HashThreads:         16,
		HashKeyLength:       128,
		SaltBytes:           128,
	})
	if err != nil {
		t.Fatal(err)
	}

	password := "mySecretPassword"
	hashedPass, salt, err := gp.HashAndSalt(password)
	if err != nil {
		t.Errorf("Error hashing password: %v", err)
	}

	// Hashed password and salt should not be empty
	if len(hashedPass) == 0 || len(salt) == 0 {
		t.Errorf("Hashed password or salt is empty")
	}
}
func TestComparePasswords(t *testing.T) {
	gp, err := gopass.New(gopass.Config{
		MinPassLength:       8,
		MaxPassLength:       22,
		ReqSpecialChars:     1,
		ReqNumbers:          1,
		MaxRepeatedChars:    2,
		MaxNumericSeqLength: 3,
		HashTime:            1,
		HashMemory:          1024,
		HashThreads:         16,
		HashKeyLength:       128,
		SaltBytes:           128,
	})
	if err != nil {
		t.Fatal(err)
	}

	password := "correctHorseBatteryStaple"
	hashedPass, salt, err := gp.HashAndSalt(password)
	if err != nil {
		t.Errorf("Error hashing password: %v", err)
	}

	// Test valid comparison
	valid, _ := gp.ComparePasswords(hashedPass, salt, password)
	if !valid {
		t.Errorf("Expected password to be valid")
	}

	// Test invalid comparison (wrong password)
	invalidPassword := "incorrectHorseBatteryStaple"
	valid, _ = gp.ComparePasswords(hashedPass, salt, invalidPassword)
	if valid {
		t.Errorf("Expected password to be invalid")
	}
}
