package gopass

/*
  These are a collection of functions for password strength validation
*/

// returns a count of non-alphanumeric characters in a string
func countSpecialChars(s string) int {
	count := 0
	for _, ch := range s {
		if !isLetter(ch) && !isNumber(ch) {
			count++
		}
	}
	return count
}

// returns a count of numeric characters in a string
func countNumbers(s string) int {
	count := 0
	for _, ch := range s {
		if isNumber(ch) {
			count++
		}
	}
	return count
}

// returns the count of the longest set of repeated characters in a string
func maxRepeatedChars(s string) int {
	max := 0
	cur := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			cur++
		} else {
			if cur > max {
				max = cur
			}
			cur = 1
		}
	}
	if cur > max {
		max = cur
	}
	return max
}

// returns true if the character is a letter
func isLetter(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

// returns true if the character is a number
func isNumber(ch rune) bool {
	return ch >= '0' && ch <= '9'
}
