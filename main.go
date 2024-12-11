package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/grpclog"
)

var version = "dev"

func main() {
	logger := zerolog.New(os.Stderr).
		With().
		Timestamp().
		Logger().
		Level(zerolog.InfoLevel)
	grpclog.SetLoggerV2(grpcLogger{logger})

	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		// TODO: Update this string with the published name of your provider.
		// Also update the tfplugindocs generate command to either remove the
		// -provider-name flag or set its value to the updated provider name.
		Address: "registry.terraform.io/pomerium/enterprise",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}
