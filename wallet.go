package kms

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/perme-io/vault-plugin-secrets-kms/chains"
)

const (
	walletStoragePath   = "wallet"
	publicKeyHashOffset = 20
)

type kmsWallet struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Address    string `json:"address"`
}

func pathWallet(b *kmsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallet",
			Fields: map[string]*framework.FieldSchema{
				"username": {
					Type:        framework.TypeString,
					Description: "username of wallet",
					Required:    true,
				},
				"address": {
					Type:        framework.TypeString,
					Description: "address of wallet",
					Required:    false,
				},
				"chainName": {
					Type:        framework.TypeString,
					Description: "name of blockchain",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathWalletRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathWalletCreate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathWalletCreate,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathWalletDelete,
				},
			},
			HelpSynopsis:    pathWalletHelpSynopsis,
			HelpDescription: pathWalletHelpDescription,
		},
	}
}

func getWalletPath(username string, address string) string {
	userPath := username + "/" + address
	return walletStoragePath + "/" + userPath
}

func getWallet(ctx context.Context, req *logical.Request, walletPath string) (*kmsWallet, error) {
	// Decode the data
	entry, err := req.Storage.Get(ctx, walletPath)
	if err != nil {
		return nil, fmt.Errorf("error reading wallet: %w", err)
	}

	if entry == nil {
		return nil, fmt.Errorf("error not found wallet")
	}

	wallet := new(kmsWallet)
	if err := entry.DecodeJSON(&wallet); err != nil {
		return nil, fmt.Errorf("error decode wallet: %w", err)
	}

	return wallet, nil
}

func (b *kmsBackend) pathWalletRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var username string
	if un, ok := d.GetOk("username"); ok {
		username = un.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing username in wallet")
	}

	var address string
	if addr, ok := d.GetOk("address"); ok {
		address = addr.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing address in wallet")
	}

	walletPath := getWalletPath(username, address)

	wallet, err := getWallet(ctx, req, walletPath)
	if err != nil {
		return nil, err
	}

	// Generate the response
	resp := &logical.Response{
		Data: map[string]interface{}{
			"address":    wallet.Address,
			"public_key": wallet.PublicKey,
		},
	}

	return resp, nil
}

func createWallet(chainName chains.ChainName) (*kmsWallet, error) {
	wallet := &kmsWallet{}
	var chain chains.Chain

	if privateKey, err := secp256k1.GeneratePrivateKey(); err == nil {

		switch chainName {
		case chains.ICON:
			chain = chains.IconChain{PrivateKey: privateKey}
		case chains.AERGO:
			chain = chains.AergoChain{PrivateKey: privateKey}
		default:
			return nil, fmt.Errorf("unknown chain name: %v", chainName)
		}
	} else {
		return nil, err
	}

	pubKeySerialized := chain.GetPublicKeySerialized()
	wallet.PrivateKey = hex.EncodeToString(chain.GetPrivateKeySerialized())
	wallet.PublicKey = hex.EncodeToString(pubKeySerialized)
	wallet.Address = chain.GetPublicKeyAddress(pubKeySerialized)

	return wallet, nil
}

func (b *kmsBackend) pathWalletCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var username string
	if un, ok := d.GetOk("username"); ok {
		if username = un.(string); username == "" {
			return nil, fmt.Errorf("empty username in wallet")
		}
	} else if !ok {
		return nil, fmt.Errorf("missing username in wallet")
	}

	var chainName chains.ChainName
	if wtype, ok := d.GetOk("chainName"); ok {
		chainName = chains.ChainName(wtype.(string))
	} else {
		return nil, fmt.Errorf("missing chainName in wallet")
	}
	b.Logger().Debug("chainName:", chainName)

	wallet, err := createWallet(chainName)
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet. err=%v", err)
	}

	walletPath := getWalletPath(username, wallet.Address)
	entry, err := logical.StorageEntryJSON(walletPath, wallet)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"address": wallet.Address,
		},
	}

	return resp, nil
}

func (b *kmsBackend) pathWalletDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var username string
	if un, ok := d.GetOk("username"); ok {
		if username = un.(string); username == "" {
			return nil, fmt.Errorf("empty username in wallet")
		}
	} else if !ok {
		return nil, fmt.Errorf("missing username in wallet")
	}

	var address string
	if addr, ok := d.GetOk("address"); ok {
		address = addr.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing address in wallet")
	}

	walletPath := getWalletPath(username, address)

	err := req.Storage.Delete(ctx, walletPath)
	if err != nil {
		return nil, fmt.Errorf("error deleting wallet: %w", err)
	}

	return nil, nil
}

const (
	pathWalletHelpSynopsis    = `Manages the Vault wallet for generating transaction signature.`
	pathWalletHelpDescription = `
This path allows you to read and write wallet used to generate transaction signature.
You can create wallet to generate a user's transaction signature by setting the username field.
`
)
