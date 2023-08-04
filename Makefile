GO=go
GOARCH=$(shell uname -m)

LINUX=linux
MACOS=darwin
VAULT_DIR=vault
SRC=cmd/main.go
TARGET=$(VAULT_DIR)/plugins/vault-plugin-secrets-kms

all: build

build-linux:
	GOOS=$(LINUX) GOARCH=amd64 $(GO) build -o $(TARGET)-$(LINUX) $(SRC)

build-macos:
	GOOS=$(MACOS) GOARCH=$(GOARCH) $(GO) build -o $(TARGET)-$(MACOS) $(SRC)

build: build-linux build-macos

test:
	go test -v

clean:
	@rm -rf $(VAULT_DIR)
