package kms

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/perme-io/vault-plugin-secrets-kms/chains"
	"golang.org/x/crypto/sha3"
)

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
				"address": {
					Type:        framework.TypeString,
					Description: "address of wallet",
					Required:    true,
				},
				"chainName": {
					Type:        framework.TypeString,
					Description: "name of blockchain",
					Required:    true,
				},
				"txSerialized": {
					Type:        framework.TypeString,
					Description: "serialized transaction data",
					Required:    false,
				},
				"msgHash": {
					Type:        framework.TypeString,
					Description: "an arbitrary 32-byte message hash to sign, expressed as a hex string",
					Required:    false,
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
	var username string
	if un, ok := d.GetOk("username"); ok {
		username = un.(string)
	} else {
		return nil, fmt.Errorf("missing username in sign")
	}

	var address string
	if addr, ok := d.GetOk("address"); ok {
		address = addr.(string)
	} else {
		return nil, fmt.Errorf("missing address in sign")
	}

	var chainName chains.ChainName
	if wtype, ok := d.GetOk("chainName"); ok {
		chainName = chains.ChainName(wtype.(string))
	} else {
		return nil, fmt.Errorf("missing chainName in sign")
	}

	var hashBytes []byte
	if ts, ok := d.GetOk("txSerialized"); ok {
		txSerialized := ts.(string)
		digest := sha3.Sum256([]byte(txSerialized))
		hashBytes = digest[:]
	} else if mh, ok := d.GetOk("msgHash"); ok {
		hexString := mh.(string)
		hashBytes, _ = hex.DecodeString(hexString)
	} else {
		return nil, fmt.Errorf("missing txSerialized or msgHash in sign")
	}
	if len(hashBytes) != 32 {
		return nil, fmt.Errorf("invalid hash length")
	}

	walletPath := getWalletPath(username, address)
	wallet, err := getWallet(ctx, req, walletPath)
	if err != nil {
		return nil, err
	}

	if privKeyBytes, err := hex.DecodeString(wallet.PrivateKey); err == nil {
		privateKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
		chain, err := chains.NewChain(chainName, privateKey)
		if err != nil {
			return nil, err
		}

		if signature, err := chain.SignCompact(hashBytes); err == nil {
			return &logical.Response{
				Data: map[string]interface{}{
					"signature": signature,
				},
			}, nil
		}
	}

	return nil, fmt.Errorf("faild to sign: err=%v", err)
}

const (
	pathSignHelpSynopsis    = `Manages the Vault signature for send transaction.`
	pathSignHelpDescription = `
This path lets you create a signature for sending a transaction.
You can get a signature from the user's wallet by providing the username and txSerialized (or msgHash) fields.
`
)
