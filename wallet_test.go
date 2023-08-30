package kms

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

type testWalletEnv struct {
	PrivateKey       *secp256k1.PrivateKey
	PublicKey        *secp256k1.PublicKey
	PrivateKeyString string
	PublicKeyString  string
	PrivAddress      string
	PubAddress       string
}

func TestSecp256k1(t *testing.T) {
	walletEnv := testWalletEnv{}

	if privateKey, err := secp256k1.GeneratePrivateKey(); err == nil {
		walletEnv.PrivateKey = privateKey
		walletEnv.PublicKey = privateKey.PubKey()
		walletEnv.PrivAddress = privateKey.Key.String()
	} else if err != nil {
		t.Errorf("failed to generate privateKey with secp256k1: err=%v", err)
	}

	pubKeyHash := sha3.Sum256(walletEnv.PublicKey.SerializeCompressed())
	walletEnv.PubAddress = hex.EncodeToString(pubKeyHash[len(pubKeyHash)-20:])

	walletEnv.PrivateKeyString = hex.EncodeToString(walletEnv.PrivateKey.Serialize())
	walletEnv.PublicKeyString = hex.EncodeToString(walletEnv.PublicKey.SerializeCompressed())

	t.Logf("privateKey : %v", walletEnv.PrivateKey)
	t.Logf("privateKey string : %v", walletEnv.PrivateKeyString)
	t.Logf("PrivateKey Address : %v", walletEnv.PrivAddress)
	t.Logf("publicKey : %v", walletEnv.PublicKey)
	t.Logf("publicKey string : %v", walletEnv.PublicKeyString)
	t.Logf("publicKey address : %v", walletEnv.PubAddress)

	pkBytes := walletEnv.PrivateKey.Key.Bytes()
	privKey := secp256k1.PrivKeyFromBytes(pkBytes[:])
	privKeyString := hex.EncodeToString(privKey.Serialize())
	require.Equalf(t, walletEnv.PrivateKeyString, privKeyString, "expected=%v, actual=%v", walletEnv.PrivateKeyString, privKeyString)

	address := privKey.Key.String()
	require.Equalf(t, walletEnv.PrivAddress, address, "expected=%v, actual=%v", walletEnv.PrivAddress, address)

	pubKey, err := secp256k1.ParsePubKey(walletEnv.PublicKey.SerializeCompressed())
	pubKeyString := hex.EncodeToString(pubKey.SerializeCompressed())
	if err != nil {
		t.Errorf("failed to parse publicKey: err=%v", err)
	}
	require.Equalf(t, walletEnv.PublicKeyString, pubKeyString, "expected=%v, actual=%v", walletEnv.PublicKeyString, pubKeyString)
}

func TestPubKeyAddress(t *testing.T) {
	walletEnv := testWalletEnv{}

	privKeyString := "1a5e70bfd427ec9ec3decf8d6e3461dfb4dbbde4351e071d9728d96e711e1b9c"
	expectedAddress := "hx5443d0db003fd7202046bbf31eaeade60af20c41"

	privKeyBytes, err := hex.DecodeString(privKeyString)
	if err != nil {
		t.Errorf("error=%v", err)
	}

	privateKey := secp256k1.PrivKeyFromBytes(privKeyBytes)

	walletEnv.PrivateKey = privateKey
	walletEnv.PrivateKeyString = hex.EncodeToString(walletEnv.PrivateKey.Serialize())
	walletEnv.PublicKey = privateKey.PubKey()

	pubKeyCompressed := walletEnv.PublicKey.SerializeUncompressed()
	pubKeyHash := sha3.Sum256(pubKeyCompressed[1:])
	pubAddress := hex.EncodeToString(pubKeyHash[len(pubKeyHash)-20:])

	walletEnv.PubAddress = "hx" + pubAddress

	t.Logf("privateKey : %v", walletEnv.PrivateKey)
	t.Logf("privateKey string : %v", walletEnv.PrivateKeyString)
	t.Logf("publicKey uncompressed : %v", hex.EncodeToString(walletEnv.PublicKey.SerializeUncompressed()))
	t.Logf("publicKey address : %v", walletEnv.PubAddress)

	require.Equalf(t, expectedAddress, walletEnv.PubAddress, "expected=%v, actual=%v", expectedAddress, walletEnv.PubAddress)
}

func TestCreateWallet(t *testing.T) {
	wallet, err := createWallet()

	require.Nilf(t, err, "createWallet err: expected nil, actual=%v", err)
	require.NotNilf(t, wallet, "createWallet wallet: expected not nil, actual=%v", wallet)
}

const (
	username = "tesuser@email.com"
	token    = "test-token"
)

// TestWallet mocks the creation, read, update, and delete
// of the backend wallet for kms.
func TestWallet(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test Wallet", func(t *testing.T) {
		resp, err := testWalletCreate(t, b, reqStorage, map[string]interface{}{
			"username": username,
		})

		assert.NoError(t, err)

		var walletAddress string
		if addr, ok := resp.Data["address"]; ok {
			walletAddress = addr.(string)
		}
		t.Logf("wallet address : %v", walletAddress)

		err = testWalletCreateWithEmptyUsername(t, b, reqStorage, map[string]interface{}{
			"username": "",
		})

		assert.Error(t, err)

		reqData := map[string]interface{}{
			"username": username,
			"address":  walletAddress,
		}
		expectedData := map[string]interface{}{
			"address": walletAddress,
		}
		err = testWalletRead(t, b, reqStorage, reqData, expectedData)

		assert.NoError(t, err)

		resp, err = testWalletUpdate(t, b, reqStorage, map[string]interface{}{
			"username": username,
		})

		assert.NoError(t, err)

		if addr, ok := resp.Data["address"]; ok {
			walletAddress = addr.(string)
		}
		t.Logf("updated wallet address : %v", walletAddress)

		reqData["address"] = walletAddress
		expectedData["address"] = walletAddress
		err = testWalletRead(t, b, reqStorage, reqData, expectedData)

		assert.NoError(t, err)

		err = testWalletDelete(t, b, reqStorage, map[string]interface{}{
			"username": username,
			"address":  walletAddress,
		})

		assert.NoError(t, err)
	})
}

func testWalletCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) (*logical.Response, error) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.CreateOperation,
		ClientToken: token,
		Path:        walletStoragePath,
		Data:        d,
		Storage:     s,
	})

	if err != nil {
		return nil, err
	}

	if resp != nil && resp.IsError() {
		return nil, resp.Error()
	}
	return resp, nil
}

func testWalletCreateWithEmptyUsername(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.CreateOperation,
		ClientToken: token,
		Path:        walletStoragePath,
		Data:        d,
		Storage:     s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testWalletUpdate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) (*logical.Response, error) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.UpdateOperation,
		ClientToken: token,
		Path:        walletStoragePath,
		Data:        d,
		Storage:     s,
	})

	if err != nil {
		return nil, err
	}

	if resp != nil && resp.IsError() {
		return nil, resp.Error()
	}
	return resp, nil
}

func testWalletRead(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, expected map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.ReadOperation,
		ClientToken: token,
		Path:        walletStoragePath,
		Data:        d,
		Storage:     s,
	})

	if err != nil {
		return err
	}

	if resp == nil && expected == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	if len(resp.Data) != 2 {
		return fmt.Errorf("read data mismatch (expected %d values, got %d)", len(expected), len(resp.Data))
	}

	for k, expectedV := range expected {
		actualV, ok := resp.Data[k]

		if !ok {
			return fmt.Errorf(`expected data["%s"] = %v but was not included in read output"`, k, expectedV)
		} else if expectedV != actualV {
			return fmt.Errorf(`expected data["%s"] = %v, instead got %v"`, k, expectedV, actualV)
		}
	}

	return nil
}

func testWalletDelete(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.DeleteOperation,
		ClientToken: token,
		Path:        walletStoragePath,
		Data:        d,
		Storage:     s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}
