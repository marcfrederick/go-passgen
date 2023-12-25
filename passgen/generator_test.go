package passgen_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/marcfrederick/go-passgen/passgen"
)

// randomString is a string of 64 characters that is used to mock the
// random number generator. It is used to ensure that the generated
// password is always the same for a given input.
const randomString = "zUJfcYXQhe7luxOhEeJPZ8LIkKBzsnSqWALSpD78BbbgLtn6Da"

func TestGenerator_Generate(t *testing.T) {
	type args struct {
		input *passgen.GenerateInput
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr error
	}{
		{
			name: "only uppercase letters",
			args: args{
				input: &passgen.GenerateInput{
					Length:                  16,
					ExcludeLowercaseLetters: true,
					ExcludeDigits:           true,
					ExcludeSymbols:          true,
				},
			},
			want: "VKGDZYRIFXMVYPIF",
		},
		{
			name: "only lowercase letters",
			args: args{
				input: &passgen.GenerateInput{
					Length:                  16,
					ExcludeUppercaseLetters: true,
					ExcludeDigits:           true,
					ExcludeSymbols:          true,
				},
			},
			want: "vkgdzyrifxmvypif",
		},
		{
			name: "only digits",
			args: args{
				input: &passgen.GenerateInput{
					Length:                  16,
					ExcludeUppercaseLetters: true,
					ExcludeLowercaseLetters: true,
					ExcludeSymbols:          true,
				},
			},
			want: "5639818575885508",
		},
		{
			name: "only symbols",
			args: args{
				input: &passgen.GenerateInput{
					Length:                  16,
					ExcludeUppercaseLetters: true,
					ExcludeLowercaseLetters: true,
					ExcludeDigits:           true,
				},
			},
			want: `_@+'$^]<)&\-@]:)`,
		},
		{
			name: "no categories",
			args: args{
				input: &passgen.GenerateInput{
					Length:                  16,
					ExcludeUppercaseLetters: true,
					ExcludeLowercaseLetters: true,
					ExcludeDigits:           true,
					ExcludeSymbols:          true,
				},
			},
			wantErr: passgen.ErrNoCategories,
		},
		{
			name: "invalid length",
			args: args{
				input: &passgen.GenerateInput{
					Length: 0,
				},
			},
			wantErr: passgen.ErrInvalidLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator, err := passgen.NewGenerator(passgen.WithReader(strings.NewReader(randomString)))
			if err != nil {
				t.Fatalf("NewGenerator() error = %v", err)
			}

			got, err := generator.Generate(tt.args.input)
			if (err != nil) && !errors.Is(err, tt.wantErr) {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Generate() got = %v, want %v", got, tt.want)
			}
		})
	}
}
