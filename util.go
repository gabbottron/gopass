package gopass

func countSpecialChars(s string) int {
	count := 0
	for _, ch := range s {
		if !isLetter(ch) && !isNumber(ch) {
			count++
		}
	}
	return count
}

func countNumbers(s string) int {
	count := 0
	for _, ch := range s {
		if isNumber(ch) {
			count++
		}
	}
	return count
}

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

func isLetter(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

func isNumber(ch rune) bool {
	return ch >= '0' && ch <= '9'
}
