# go-passgen

[![CI](https://github.com/marcfrederick/go-passgen/actions/workflows/ci.yml/badge.svg)](https://github.com/marcfrederick/go-passgen/actions/workflows/test.yml)

go-passgen is a simple, dependency-free password generator written in Go.

## Installation

go-passgen requires Go 1.13 or later and is compatible with modules.
To add go-passgen to your project, run the following command in your project:

```bash
go get github.com/marcfrederick/go-passgen
```

Alternatively, add the following import to your Go source files and run `go get`:

```go
import "github.com/marcfrederick/go-passgen/passgen"
```

## Usage

```go
package main

import (
	"log"

	"github.com/marcfrederick/go-passgen/passgen"
)

func main() {
	password, err := passgen.Generate(&passgen.GenerateInput{
		Length:              16,
		UseUppercaseLetters: true,
		UseLowercaseLetters: true,
		UseNumbers:          true,
		UseSymbols:          true,
	})
	if err != nil {
		log.Fatalf("failed to generate password: %v", err)
	}
	println(password)
}

```
