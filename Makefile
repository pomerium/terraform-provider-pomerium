.PHONY: all
all: generate build test lint

.PHONY: lint
lint:
	@echo "==> $@"
	@go run ./internal/tools/get-tools.go && \
	./bin/golangci-lint run --fix --timeout=10m ./...

.PHONY: build
build:
	@echo "@==> $@"
	@go build -o bin/terraform-provider-pomerium

.PHONY: docs
docs:
	@echo "@==> $@"
	go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@latest generate --provider-dir . -provider-name pomerium

.PHONY: generate
generate: docs
	@echo "@==> $@"
	go run ./internal/generate


.PHONY: test
test:
	@echo "@==> $@"
	@go test ./internal/provider/...

.PHONY: update-pomerium
update-pomerium:
	@echo "@==> $@"
	go get -u github.com/pomerium/enterprise-client-go@main
	go get -u github.com/pomerium/pomerium@main
	go mod tidy
