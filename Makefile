.PHONY: all build clean pxehost test

APP        ?= pxehost
BINDIR     ?= dist
OSARCHES    = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      = $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        = $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS     = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(DATE)


all: pxehost

build: pxehost

pxehost:
	go build -trimpath -ldflags="-s -w" -o pxehost ./cmd/pxehost

clean:
	rm -f pxehost

format:
	./scripts/format.sh

lint:
	./scripts/lint.sh

test:
	go test ./...

cross: $(OSARCHES:%=build/%)

build/%:
	@os=$(word 1,$(subst /, ,$*)) ; arch=$(word 2,$(subst /, ,$*)); \
	ext=$$( [ $$os = windows ] && echo .exe ); \
	echo "-> $$os/$$arch"; \
	GO111MODULE=on CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(APP)-$$os-$$arch$$ext ./cmd/pxehost
