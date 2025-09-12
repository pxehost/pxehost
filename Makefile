.PHONY: all build clean macos-pxe-boot

all: macos-pxe-boot

build: macos-pxe-boot

macos-pxe-boot:
	go build -trimpath -ldflags="-s -w" -o macos-pxe-boot ./cmd/pxehost

clean:
	rm -f macos-pxe-boot
