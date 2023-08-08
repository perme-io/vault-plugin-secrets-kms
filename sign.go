package kms

import (
	"context"
	b64 "encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/sha3"
)

const (
	// https://github.com/decred/dcrd/blob/dcrec/secp256k1/v4.2.0/dcrec/secp256k1/ecdsa/signature.go#L738
	compactMagicOffset = 27
)

// rearrangeSignature
//
// reverse true: <32-byte R><32-byte S><1-byte compact sig recovery code>
//
// reverse false: <1-byte compact sig recovery code><32-byte R><32-byte S>
func rearrangeSignature(signature []byte, reverse bool) []byte {
	var newSignature []byte

	if reverse {
		recid := signature[0] - compactMagicOffset
		newSignature = append(newSignature, signature[1:]...)
		newSignature = append(newSignature, recid)
	} else {
		recid := signature[len(signature)-1] + compactMagicOffset
		newSignature = append(newSignature, recid)
		newSignature = append(newSignature, signature[:len(signature)-1]...)
	}

	return newSignature
}

func signCompact(privKeyString string, serializedString string) (string, error) {
	privKeyBytes, err := hex.DecodeString(privKeyString)
	if err != nil {
		return "", err
	}

	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)

	// Sign a tx using the private key.
	serializedBytes := []byte(serializedString)
	messageHash := sha3.Sum256(serializedBytes)

	// Compact signature format:
	// <1-byte compact sig recovery code><32-byte R><32-byte S>
	signature := ecdsa.SignCompact(privKey, messageHash[:], false)

	compactSig := rearrangeSignature(signature, true)

	base64Sign := b64.StdEncoding.EncodeToString(compactSig)
	return base64Sign, nil
}

func pathSign(b *kmsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallet/sign",
			Fields: map[string]*framework.FieldSchema{
				"username": {
					Type:        framework.TypeString,
					Description: "username of wallet",
					Required:    true,
				},
				"txSerialized": {
					Type:        framework.TypeString,
					Description: "serialized transaction data",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathSignCreate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathSignCreate,
				},
			},
			HelpSynopsis:    pathSignHelpSynopsis,
			HelpDescription: pathSignHelpDescription,
		},
	}
}

func (b *kmsBackend) pathSignCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	var username string
	if un, ok := d.GetOk("username"); ok {
		username = un.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing username in sign")
	}

	var txSerialized string
	if ts, ok := d.GetOk("txSerialized"); ok {
		txSerialized = ts.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing txSerialized in sign")
	}

	walletPath := WalletStoragePath + "/" + username

	wallet, err := getWallet(ctx, req, walletPath)
	if err != nil {
		return nil, err
	}

	signature, err := signCompact(wallet.PrivateKey, txSerialized)
	if err != nil {
		return nil, fmt.Errorf("faild to sign: err=%v", err)
	}

	response := &logical.Response{
		Data: map[string]interface{}{
			"signature": signature,
		},
	}

	return response, nil
}

const (
	pathSignHelpSynopsis    = `Manages the Vault signature for send transaction.`
	pathSignHelpDescription = `
This path allows you to create signature used to send transaction.
You can get a signature to send transaction using user wallet by setting the username and txSeriailzed field.
`
)
