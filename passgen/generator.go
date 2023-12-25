package passgen

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
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

	charCategories := g.getCharCategories(input)
	numCategories := len(charCategories)

	if numCategories == 0 {
		return "", ErrNoCategories
	}

	password := make([]byte, input.Length)
	for i := 0; i < input.Length; i++ {
		categoryIndex, err := rand.Int(g.reader, big.NewInt(int64(numCategories)))
		if err != nil {
			return "", fmt.Errorf("error selecting character category: %w", err)
		}
		charCategory := charCategories[categoryIndex.Int64()]

		charIndex, err := rand.Int(g.reader, big.NewInt(int64(len(charCategory))))
		if err != nil {
			return "", fmt.Errorf("error selecting character: %w", err)
		}

		password[i] = charCategory[charIndex.Int64()]
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

// getCharCategories returns a slice of allowed character categories.
func (g *Generator) getCharCategories(input *GenerateInput) []string {
	charCategories := make([]string, 0, 4)

	if input.UseUppercaseLetters {
		charCategories = append(charCategories, uppercaseLetters)
	}
	if input.UseLowercaseLetters {
		charCategories = append(charCategories, lowercaseLetters)
	}
	if input.UseDigits {
		charCategories = append(charCategories, digits)
	}
	if input.UseSymbols {
		charCategories = append(charCategories, symbols)
	}

	return charCategories
}
