package passgen

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

const (
	uppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowercaseLetters = "abcdefghijklmnopqrstuvwxyz"
	digits           = "0123456789"
	symbols          = `!"#$%&'()*+,-./:;<=>?@[\]^_{|}~`
)

// Generator is a password generator.
type Generator struct {
	// reader is the source of entropy used to generate passwords.
	reader io.Reader
}

// GeneratorOpt is an option for configuring a password generator.
type GeneratorOpt func(*Generator) error

// WithReader sets the source of entropy used to generate passwords.
//
// The default reader is crypto/rand.Reader. This option is useful for testing
// purposes.
func WithReader(reader io.Reader) GeneratorOpt {
	return func(g *Generator) error {
		g.reader = reader
		return nil
	}
}

// NewGenerator returns a new password generator.
func NewGenerator(opts ...GeneratorOpt) (*Generator, error) {
	generator := &Generator{reader: rand.Reader}

	for _, opt := range opts {
		if err := opt(generator); err != nil {
			return nil, fmt.Errorf("error applying option: %w", err)
		}
	}

	return generator, nil
}

// CharSetExclusion is a character set exclusion.
type CharSetExclusion byte

const (
	// ExcludeUppercaseLetters excludes uppercase letters from the character pool.
	ExcludeUppercaseLetters CharSetExclusion = 1 << iota

	// ExcludeLowercaseLetters excludes lowercase letters from the character pool.
	ExcludeLowercaseLetters

	// ExcludeDigits excludes digits from the character pool.
	ExcludeDigits

	// ExcludeSymbols excludes symbols from the character pool.
	ExcludeSymbols
)

var (
	ErrInvalidLength = errors.New("length must be greater than 0")
	ErrNoCategories  = errors.New("no character categories selected")
)

// Generate returns a randomly generated password.
func (g *Generator) Generate(length int, charsetExclusions ...CharSetExclusion) (string, error) {
	if length < 1 {
		return "", ErrInvalidLength
	}

	charPool := g.getCharPool(charsetExclusions)
	if len(charPool) == 0 {
		return "", ErrNoCategories
	}

	password := make([]byte, length)
	for i := 0; i < length; i++ {
		charIndex, err := rand.Int(g.reader, big.NewInt(int64(len(charPool))))
		if err != nil {
			return "", fmt.Errorf("error selecting character: %w", err)
		}
		password[i] = charPool[charIndex.Int64()]
	}

	return string(password), nil
}

// getCharPool returns a string containing all characters that can be used to
// generate a password.
func (g *Generator) getCharPool(charsetExclusions []CharSetExclusion) string {
	var charsetExclusion CharSetExclusion
	for _, exclusion := range charsetExclusions {
		charsetExclusion |= exclusion
	}

	var charPool strings.Builder

	if charsetExclusion&ExcludeUppercaseLetters == 0 {
		charPool.WriteString(uppercaseLetters)
	}
	if charsetExclusion&ExcludeLowercaseLetters == 0 {
		charPool.WriteString(lowercaseLetters)
	}
	if charsetExclusion&ExcludeDigits == 0 {
		charPool.WriteString(digits)
	}
	if charsetExclusion&ExcludeSymbols == 0 {
		charPool.WriteString(symbols)
	}

	return charPool.String()
}
