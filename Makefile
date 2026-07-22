BINARY  := bin/s3-access-check
GO      := go
PKG     := ./...
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) \
           -X main.commit=$(COMMIT) \
           -X main.date=$(DATE)

.PHONY: all fmt vet test build install clean run tidy lint help

all: fmt vet test build install

fmt:
	$(GO) fmt $(PKG)

vet:
	$(GO) vet $(PKG)

test:
	$(GO) test -race -count=1 $(PKG)

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) .

# install copies the binary to a bin directory (override with PREFIX=...):
#   1) ~/.local/bin, if it is on $PATH
#   2) /usr/local/bin, if it exists
install: build
	@dest="$(PREFIX)"; \
	if [ -z "$$dest" ]; then \
		case ":$$PATH:" in *":$$HOME/.local/bin:"*) dest="$$HOME/.local/bin" ;; esac; \
	fi; \
	if [ -z "$$dest" ] && [ -d /usr/local/bin ]; then dest="/usr/local/bin"; fi; \
	if [ -z "$$dest" ]; then \
		echo "install: no suitable bin dir found; rerun with PREFIX=/path/to/bin"; exit 1; \
	fi; \
	mkdir -p "$$dest" && install -m 0755 $(BINARY) "$$dest/$(notdir $(BINARY))" && \
		echo "installed -> $$dest/$(notdir $(BINARY))"

clean:
	rm -f $(BINARY)
	rm -rf bin

# run builds then runs the CLI; pass a target via ARGS, e.g.
#   make run ARGS="s3://noaa-goes16"
#   make run ARGS="--scan --keys-from keys.txt s3://my-bucket"
# The leading '-' ignores the CLI's exit status: this tool uses exit codes
# 1 (public) and 2 (inconclusive/partial) as meaningful signals, not build
# failures, so `make run` should not abort on them.
run: build
	-./$(BINARY) $(ARGS)

tidy:
	$(GO) mod tidy

lint:
ifeq (, $(shell which golangci-lint))
	@echo "golangci-lint not installed, skipping"
else
	golangci-lint run
endif

help:
	@echo "Targets:"
	@echo "  fmt      - Format source code"
	@echo "  vet      - Run go vet"
	@echo "  test     - Run tests (race detector)"
	@echo "  build    - Build binary into $(BINARY) (version/commit/date injected)"
	@echo "  install  - Build and install the binary to a bin dir (PREFIX= to override)"
	@echo "  clean    - Remove the binary and bin/ directory"
	@echo "  run      - Build and run the CLI; pass a target with ARGS=\"...\""
	@echo "  tidy     - Tidy go modules"
	@echo "  lint     - Run golangci-lint (if installed)"
	@echo "  all      - fmt + vet + test + build + install"
