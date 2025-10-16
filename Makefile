.PHONY: all
all: generate build test lint

.PHONY: lint
lint:
	@echo "@==> $@"
	@VERSION=$$(go run github.com/mikefarah/yq/v4@v4.34.1 '.jobs.lint.steps[] | select(.uses == "golangci/golangci-lint-action*") | .with.version' .github/workflows/reusable-build.yaml) && \
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@$$VERSION run --fix --timeout=20m ./...

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
