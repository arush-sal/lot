default: binary

.PHONY: clean show-fmt fmt binary static-binary install release-test release

BUILD_DIR := $(shell echo `pwd`/build)
BUILD_FLAGS := -ldflags "-linkmode external -extldflags -static"
GO_ENVIRONMENT := GOBIN=$(BUILD_DIR) GOCACHE=$(BUILD_DIR)/.cache GOGC=200

export GO111MODULE=on

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/bin
	mkdir -p $(BUILD_DIR)/pkg
	mkdir -p $(BUILD_DIR)/src
	chmod a+rwx $(BUILD_DIR)

install: 
	go install `go list -f '{{.Dir}}' `

binary: 
	$(GO_ENVIRONMENT) go build `go list -f '{{.Dir}}' `

static-binary: 
	$(GO_ENVIRONMENT) go build $(BUILD_FLAGS) `go list -f '{{.Dir}}' `

vet:
	$(GO_ENVIRONMENT) go vet `go list -f '{{.Dir}}' `

lint: vet
	golint ./...

fmt: lint
	$(GO_ENVIRONMENT) gofmt -w -s `go list -f '{{.Dir}}' `


show-fmt:
	$(GO_ENVIRONMENT) gofmt -d `go list -f '{{.Dir}}' `

check-fmt:
	$(GO_ENVIRONMENT) gofmt -d `go list -f '{{.Dir}}'` 2>&1 | read foo ; [ $$? -eq 1 ]

release-test:
	goreleaser release --skip-publish --snapshot --rm-dist

release:
	goreleaser release --snapshot --rm-dist

clean:
	rm -rf $(BUILD_DIR)
