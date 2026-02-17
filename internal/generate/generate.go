package main

import (
	"context"

	"github.com/rs/zerolog/log"
)

func main() {
	err := run(context.Background())
	if err != nil {
		log.Fatal().Err(err).Send()
	}
}

func run(ctx context.Context) error {
	return generateEnums(ctx)
}
