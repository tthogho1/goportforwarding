APP     := goportforwarding
DIST    := dist
LDFLAGS := -s -w
# Fyne needs cgo, so every target needs a C toolchain for that platform.
export CGO_ENABLED := 1

GO_IMAGE   := golang:1.25-bookworm
LINUX_DEPS := apt-get update -qq && apt-get install -y -qq gcc pkg-config libgl1-mesa-dev xorg-dev libwayland-dev libxkbcommon-dev >/dev/null

.PHONY: all test darwin windows linux linux-amd64 linux-arm64 clean

all: darwin windows linux

test:
	go test -race ./tunnel ./profile

# macOS universal binary (arm64 + amd64). Build on a Mac with Xcode CLT.
darwin:
	mkdir -p $(DIST)
	GOOS=darwin GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(DIST)/$(APP)-darwin-arm64 .
	GOOS=darwin GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(DIST)/$(APP)-darwin-amd64 .
	lipo -create -output $(DIST)/$(APP)-darwin-universal $(DIST)/$(APP)-darwin-arm64 $(DIST)/$(APP)-darwin-amd64

# Windows amd64. From macOS/Linux needs mingw-w64 (brew install mingw-w64).
# -H windowsgui hides the console window.
windows:
	mkdir -p $(DIST)
	GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
		go build -ldflags '$(LDFLAGS) -H windowsgui' -o $(DIST)/$(APP)-windows-amd64.exe .

# Linux builds run in Docker so they work from any host.
linux: linux-amd64 linux-arm64

linux-amd64 linux-arm64: linux-%:
	mkdir -p $(DIST)
	docker run --rm --platform linux/$* -v "$(CURDIR)":/src -w /src \
		-v $(APP)-gomod:/go/pkg/mod -e GOFLAGS=-buildvcs=false $(GO_IMAGE) \
		sh -c '$(LINUX_DEPS) && go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)-linux-$* .'

clean:
	rm -rf $(DIST)
