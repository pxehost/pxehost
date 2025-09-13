.PHONY: all build clean pxehost

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
