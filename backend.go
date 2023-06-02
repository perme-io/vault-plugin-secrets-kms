package secretsengine

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// kmsBackend defines an object that
// extends the Vault backend and stores the
// user wallet.
type kmsBackend struct {
	*framework.Backend
}

// backend defines the target API backend
// for Vault. It must include each path
// and the secrets it will store.
func backend() *kmsBackend {
	var b = kmsBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths:       framework.PathAppend(),
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

// invalidate clears an existing configuration in the backend
func (b *kmsBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		// b.reset()
	}
}

// backendHelp should contain help information for the backend
const backendHelp = `
The KMS secrets backend generates user wallet.
After mounting this backend, request data to generate signed transaction
must be transfered with the "wallet/" endpoints.
`
