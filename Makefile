BINARY     := tether
MODULE     := github.com/FlashyFlash3011/tether
LDFLAGS    := -trimpath -ldflags="-s -w"
DIST       := dist

.PHONY: all build-linux build-mac build-mac-native test clean

all: build-linux build-mac

## Build for the PC (Linux/WSL2 amd64)
build-linux:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build $(LDFLAGS) -o $(DIST)/$(BINARY)-linux-amd64 ./cmd/$(BINARY)
	@echo "Built $(DIST)/$(BINARY)-linux-amd64"

## Build for M4 Mac (darwin arm64) — cross-compiled, no Keychain (uses encrypted file)
build-mac:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
		go build $(LDFLAGS) -o $(DIST)/$(BINARY)-darwin-arm64 ./cmd/$(BINARY)
	@echo "Built $(DIST)/$(BINARY)-darwin-arm64"
	@echo "NOTE: run 'make build-mac-native' ON the Mac for Keychain support"

## Build natively on Mac (run this on the Mac itself for Keychain support)
build-mac-native:
	@mkdir -p $(DIST)
	GOOS=darwin GOARCH=arm64 \
		go build $(LDFLAGS) -o $(DIST)/$(BINARY)-darwin-arm64 ./cmd/$(BINARY)
	@echo "Built $(DIST)/$(BINARY)-darwin-arm64 (with Keychain)"

## Run all tests
test:
	go test ./...

## Remove build artifacts
clean:
	rm -rf $(DIST)

## Install on this Linux machine (run as user with sudo for setcap)
install-linux: build-linux
	sudo install -m 755 $(DIST)/$(BINARY)-linux-amd64 /usr/local/bin/$(BINARY)
	sudo setcap cap_net_admin+ep /usr/local/bin/$(BINARY)
	@echo "Installed. Now run: tether setup && tether keygen"
