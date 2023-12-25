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
		length            int
		charsetExclusions []passgen.CharSetExclusion
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
				length: 16,
				charsetExclusions: []passgen.CharSetExclusion{
					passgen.ExcludeLowercaseLetters,
					passgen.ExcludeDigits,
					passgen.ExcludeSymbols,
				},
			},
			want: "VKGDZYRIFXMVYPIF",
		},
		{
			name: "only lowercase letters",
			args: args{
				length: 16,
				charsetExclusions: []passgen.CharSetExclusion{
					passgen.ExcludeUppercaseLetters,
					passgen.ExcludeDigits,
					passgen.ExcludeSymbols,
				},
			},
			want: "vkgdzyrifxmvypif",
		},
		{
			name: "only digits",
			args: args{
				length: 16,
				charsetExclusions: []passgen.CharSetExclusion{
					passgen.ExcludeUppercaseLetters,
					passgen.ExcludeLowercaseLetters,
					passgen.ExcludeSymbols,
				},
			},
			want: "5639818575885508",
		},
		{
			name: "only symbols",
			args: args{
				length: 16,
				charsetExclusions: []passgen.CharSetExclusion{
					passgen.ExcludeUppercaseLetters,
					passgen.ExcludeLowercaseLetters,
					passgen.ExcludeDigits,
				},
			},
			want: `_@+'$^]<)&\-@]:)`,
		},
		{
			name: "no categories",
			args: args{
				length: 16,
				charsetExclusions: []passgen.CharSetExclusion{
					passgen.ExcludeUppercaseLetters,
					passgen.ExcludeLowercaseLetters,
					passgen.ExcludeDigits,
					passgen.ExcludeSymbols,
				},
			},
			wantErr: passgen.ErrNoCategories,
		},
		{
			name: "invalid length",
			args: args{
				length: 0,
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

			got, err := generator.Generate(tt.args.length, tt.args.charsetExclusions...)
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
