package kms

import (
	"context"
	b64 "encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestTxSign(t *testing.T) {
	wallet, _ := createWallet("icon")

	// privateKeyString := "2f1f6284e96d217bca90c0d7e4b6971b83dd7a04e1f5cef9cb65e26451046368"
	privKeyBytes, err := hex.DecodeString(wallet.PrivateKey)
	if err != nil {
		t.Errorf("error=%v", err)
	}

	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)

	// Sign a tx using the private key.
	txMessage := "test message"

	messageHash := sha3.Sum256([]byte(txMessage))
	signature := ecdsa.Sign(privKey, messageHash[:])

	t.Logf("signature: %x", signature.Serialize())

	pubKey := privKey.PubKey()
	verified := signature.Verify(messageHash[:], pubKey)

	require.Truef(t, verified, "Signature verify: expected %v, actual=%v", true, verified)
}

func TestTxSignSerialized(t *testing.T) {
	serializedString := "icx_sendTransaction" +
		".from.hx5443d0db003fd7202046bbf31eaeade60af20c41" +
		".nid.0x7.nonce.0x1.stepLimit.0x11b340.timestamp.0x5fdaf54c5ed34" +
		".to.cxcb952e97e554800a1da099e5102079ceda03b277.value.0x8ac7230489e80000" +
		".version.0x3"

	// wallet, _ := createWallet()

	privateKeyString := "1a5e70bfd427ec9ec3decf8d6e3461dfb4dbbde4351e071d9728d96e711e1b9c"
	publicKeyString := "0215526d990ed57973c2722b9c772b76e9d4ef0fcf4cea95b76844ffa925050ee6"

	// privKeyBytes, err := hex.DecodeString(wallet.PrivateKey)
	privKeyBytes, err := hex.DecodeString(privateKeyString)
	if err != nil {
		t.Errorf("error=%v", err)
	}

	pubKeyBytes, err := hex.DecodeString(publicKeyString)
	if err != nil {
		t.Errorf("error=%v", err)
	}

	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	publicKey, _ := secp256k1.ParsePubKey(pubKeyBytes)

	// Sign a tx using the private key.
	serializedBytes := []byte(serializedString)
	messageHash := sha3.Sum256(serializedBytes)
	signature := ecdsa.Sign(privKey, messageHash[:])

	t.Logf("signature: %x", signature.Serialize())
	t.Logf("signature_base64: %v", b64.StdEncoding.EncodeToString(signature.Serialize()))

	verified := signature.Verify(messageHash[:], publicKey)

	require.Truef(t, verified, "Signature verify: expected true, actual=%v", verified)
}

// TestSign mocks the creation of the backend sign for kms.
func TestSign(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test Sign", func(t *testing.T) {
		resp, err := testWalletCreate(t, b, reqStorage, map[string]interface{}{
			"username":  username,
			"chainName": "icon",
		})

		assert.NoError(t, err)

		var walletAddress string
		if addr, ok := resp.Data["address"]; ok {
			walletAddress = addr.(string)
		}

		t.Logf("wallet address : %v", walletAddress)

		serializedString := "icx_sendTransaction" +
			".from." + walletAddress +
			".nid.0x7.nonce.0x1.stepLimit.0x11b340.timestamp.0x5fdaf54c5ed34" +
			".to.cxcb952e97e554800a1da099e5102079ceda03b277.value.0x8ac7230489e80000" +
			".version.0x3"

		reqData := map[string]interface{}{
			"username":     username,
			"address":      walletAddress,
			"chainName":    "icon",
			"txSerialized": serializedString,
		}
		resp, err = testSignCreate(t, b, reqStorage, reqData)

		assert.NoError(t, err)

		sign, ok := resp.Data["signature"]

		assert.True(t, ok)
		assert.NotNil(t, sign)

		t.Logf("signature : %v", sign.(string))
	})
}

func testSignCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) (*logical.Response, error) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.CreateOperation,
		ClientToken: token,
		Path:        walletStoragePath + "/sign",
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
