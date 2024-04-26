## gopass - Secure Password Management Library

This Go library, `gopass`, provides functions for securely generating, hashing, validating, and comparing passwords. It prioritizes security by enforcing strong password complexity rules and using Argon2id for password hashing with configurable parameters.

**Features:**

* Enforces minimum and maximum password length requirements.
* Requires a minimum number of special characters and numeric digits.
* Limits the number of consecutive repeated characters.
* Prevents sequential numeric sequences (e.g., "1234").
* Hashes passwords using the secure Argon2id algorithm with configurable parameters.
* Generates cryptographically secure random passwords.
* Compares plain text passwords against hashed passwords and salts.
* Performs password complexity validation with informative error messages.

**Installation:**

```
go get -u github.com/gabbottron/gopass
```

**Usage:**

1. **Import the library:**

```go
import (
    "fmt"

    "github.com/gabbottron/gopass"
)
```

2. **Define Password Configuration:**

Create a `gopass.Config` struct to define your desired password complexity and Argon2 settings:

```go
passSettings := gopass.Config{
    MinPassLength:       8,  // Minimum password length
    MaxPassLength:       22,  // Maximum password length
    ReqSpecialChars:     1,  // Minimum number of special characters
    ReqNumbers:          1,  // Minimum number of numeric digits
    MaxRepeatedChars:    2,  // Maximum consecutive repeated characters
    MaxNumericSeqLength: 3,  // Maximum length of sequential numeric characters

    HashTime:      1,     // Argon2 iterations (higher is more secure, but slower)
    HashMemory:    1024,  // Argon2 memory cost in MB
    HashThreads:   16,    // Argon2 threads (adjust based on CPU cores)
    HashKeyLength: 128,  // Desired key length from Argon2 (in bytes)
    SaltBytes:     128,  // Length of random salt for password hashing (in bytes)
}
```

3. **Create a gopass Instance:**

```go
gp, err := gopass.New(passSettings)
if err != nil {
    panic("invalid crypto settings")
}
```

**Password Generation:**

```go
// Generate a random URL-safe, base64 encoded password of length 16
newPass, err := gp.GenerateRandomPass(16)
if err != nil {
    fmt.Println("Error generating password:", err)
} else {
    fmt.Println("New password:", newPass)
}
```

**Password Validation:**

```go
userPass := "Pa$$w0rd!" // Example password

err = gp.ValidatePassword(userPass)
if err != nil {
    fmt.Println("Invalid password:", err.Error())
} else {
    fmt.Println("Password meets complexity requirements")
}
```

**Password Hashing:**

```go
hashedPass, salt, err := gp.HashAndSalt(userPass)
if err != nil {
    fmt.Println("Error hashing password:", err)
} else {
    fmt.Println("Hashed password:", hashedPass)
    fmt.Println("Salt:", salt)
}
```

**Password Comparison:**

```go
// Assuming hashedPass and salt are obtained from previous hashing

valid := gp.ComparePasswords(hashedPass, salt, userPass)
if valid {
    fmt.Println("Password is valid")
} else {
    fmt.Println("Password is invalid")
}
```

**Speed Test (Optional):**

This function measures the time it takes to hash a specified number of random passwords. It can be helpful for evaluating performance implications of different Argon2 settings.

```go
elapsed := gp.SpeedTest(100, 8, 24) // Test 100 hashes between 8-24 characters
fmt.Printf("Time to hash 100 passwords: %f seconds\n", elapsed)
```

**Important Notes:**

* It's crucial to ensure a cryptographically secure random number generator (CSPRNG) is available during library initialization. If unavailable, the program panics to prevent insecure password storage.
* This library is designed for secure password management and should not be used for other purposes where different hashing algorithms might be more suitable.
* Carefully consider the trade-off between security and performance when selecting Argon2 parameters (HashTime, HashMemory, HashThreads).
