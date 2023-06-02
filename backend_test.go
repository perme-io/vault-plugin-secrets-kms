package secretsengine

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	envVarRunAccTests = "VAULT_ACC"
)

// getTestBackend will help you construct a test backend object.
// Update this function with your target backend.
func getTestBackend(tb testing.TB) (*kmsBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*kmsBackend), config.StorageView
}

// runAcceptanceTests will separate unit tests from
// acceptance tests, which will make active requests
// to your target API.
var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

// testEnv creates an object to store and track testing environment
// resources
type testEnv struct {
	Username string
	Password string
	URL      string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	// SecretAddress tracks the wallet address, for checking rotations
	SecretAddress string

	// Address tracks the generated wallet address, to make sure we clean up
	Address []string
}

// AddConfig adds the configuration to the test backend.
// Make sure data includes all of the configuration
// attributes you need and the `config` path!
func (e *testEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"username": e.Username,
			"password": e.Password,
			"url":      e.URL,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

// AddUserWallet adds a wallet for the Parameta W user.
func (e *testEnv) AddUserWallet(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "wallet/test-user-wallet",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"username": e.Username,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

// ReadUserAddress retrieves the user address
// based on a Vault wallet.
func (e *testEnv) ReadUserAddress(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "wallet/test-user-wallet",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)

	if t, ok := resp.Data["address"]; ok {
		e.Address = append(e.Address, t.(string))
	}
	require.NotEmpty(t, resp.Data["address"])

	if e.SecretAddress != "" {
		require.NotEqual(t, e.SecretAddress, resp.Data["adress"])
	}

	// collect secret IDs to revoke at end of test
	require.NotNil(t, resp.Secret)
	if t, ok := resp.Secret.InternalData["address"]; ok {
		e.SecretAddress = t.(string)
	}
}
