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

// GenerateInput is the input to the Generate method.
type GenerateInput struct {
	Length              int
	UseUppercaseLetters bool
	UseLowercaseLetters bool
	UseDigits           bool
	UseSymbols          bool
}

var (
	ErrInvalidLength = errors.New("length must be greater than 0")
	ErrNoCategories  = errors.New("no character categories selected")
)

// Generate returns a randomly generated password.
func (g *Generator) Generate(input *GenerateInput) (string, error) {
	if input.Length < 1 {
		return "", ErrInvalidLength
	}

	charPool := g.getCharPool(input)
	if len(charPool) == 0 {
		return "", ErrNoCategories
	}

	password := make([]byte, input.Length)
	for i := 0; i < input.Length; i++ {
		charIndex, err := rand.Int(g.reader, big.NewInt(int64(len(charPool))))
		if err != nil {
			return "", fmt.Errorf("error selecting character: %w", err)
		}
		password[i] = charPool[charIndex.Int64()]
	}

	return string(password), nil
}

// Generate returns a randomly generated password.
func Generate(input *GenerateInput) (string, error) {
	g, err := NewGenerator()
	if err != nil {
		return "", fmt.Errorf("error creating generator: %w", err)
	}
	return g.Generate(input)
}

// getCharPool returns a string containing all characters that can be used to
// generate a password.
func (g *Generator) getCharPool(input *GenerateInput) string {
	var charPool strings.Builder

	if input.UseUppercaseLetters {
		charPool.WriteString(uppercaseLetters)
	}
	if input.UseLowercaseLetters {
		charPool.WriteString(lowercaseLetters)
	}
	if input.UseDigits {
		charPool.WriteString(digits)
	}
	if input.UseSymbols {
		charPool.WriteString(symbols)
	}

	return charPool.String()
}
