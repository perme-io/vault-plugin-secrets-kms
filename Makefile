GO=go
GOARCH=amd64

LINUX=linux
MACOS=darwin
VAULT_DIR=vault
SRC=cmd/main.go
TARGET=$(VAULT_DIR)/plugins/vault-plugin-secrets-kms

BUILD_TARGETS = build-$(LINUX)
ifeq (Darwin, $(shell uname -s))
    BUILD_TARGETS += build-$(MACOS)
endif

all: build

build-$(LINUX):
	GOOS=$(LINUX) GOARCH=$(GOARCH) $(GO) build -o $(TARGET)-$(LINUX) $(SRC)

build-$(MACOS):
	GOOS=$(MACOS) $(GO) build -o $(TARGET)-$(MACOS) $(SRC)

build: $(BUILD_TARGETS)

test:
	go test -v ./...

clean:
	@rm -rf $(VAULT_DIR)
