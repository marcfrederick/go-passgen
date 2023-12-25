# go-passgen

[![CI](https://github.com/marcfrederick/go-passgen/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/marcfrederick/go-passgen/actions/workflows/ci.yml)

> :warning: This library is not suitable for generating passwords in high-security or critical systems. 
> Its intended use is primarily for testing and low-risk scenarios.
> 
> For more robust password generation in critical environments, consider [1Password/spg](https://github.com/1Password/spg).

go-passgen is a simple, dependency-free password generator written in Go.

## Installation

Ensure that your Go version is 1.13 or later and supports modules. 
To add go-passgen to your project, execute the following command:

```bash
go get github.com/marcfrederick/go-passgen
```

Alternatively, you can import it directly into your Go source files and run `go get`:

```go
import "github.com/marcfrederick/go-passgen/passgen"
```

## Usage

Below is a basic example demonstrating how to generate a password:

```go
package main

import (
	"log"

	"github.com/marcfrederick/go-passgen/passgen"
)

func main() {
	generator, err := passgen.NewGenerator()
	if err != nil {
		log.Fatalf("failed to create generator: %v", err)
	}

	password, err := generator.Generate(16, passgen.ExcludeSymbols, passgen.ExcludeDigits)
	if err != nil {
		log.Fatalf("failed to generate password: %v", err)
	}

	log.Printf("password: %s", password)
}
```

The above example will generate a password with a length of 16 characters, excluding symbols and digits.

### Options

By default, go-passgen utilizes the `crypto/rand` package for randomness. 
However, you can specify a different source of randomness by providing an `io.Reader` implementation to `passgen.NewGenerator`. 
This can be particularly useful for generating deterministic passwords in testing scenarios:

```go
generator, err := passgen.NewGenerator(passgen.WithReader(rand.Reader))
```

## Alternatives

- [1Password/spg](https://github.com/1Password/spg) - 1Password's Strong Password Generator
- [sethvargo/go-password](https://github.com/sethvargo/go-password) - Library for generating high-entropy random passwords
