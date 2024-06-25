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

func sign(privKeyString string, chainName chains.ChainName, serializedString string) (string, error) {
	privKeyBytes, err := hex.DecodeString(privKeyString)
	if err != nil {
		return "", err
	}

	var chain chains.Chain
	privateKey := secp256k1.PrivKeyFromBytes(privKeyBytes)

	switch chainName {
	case chains.ICON:
		chain = chains.IconChain{PrivateKey: privateKey}
	case chains.AERGO:
		chain = chains.AergoChain{PrivateKey: privateKey}
	default:
		return "", fmt.Errorf("unknown chain name: %v", chainName)
	}

	if base64Sign, signErr := chain.SignCompact(serializedString); signErr != nil {
		return "", signErr
	} else {
		return base64Sign, nil
	}
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
	var username string
	if un, ok := d.GetOk("username"); ok {
		username = un.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing username in sign")
	}

	var address string
	if addr, ok := d.GetOk("address"); ok {
		address = addr.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing address in sign")
	}

	var chainName chains.ChainName
	if wtype, ok := d.GetOk("chainName"); ok {
		chainName = chains.ChainName(wtype.(string))
	} else if !ok {
		return nil, fmt.Errorf("missing chainName in sign")
	}
	b.Logger().Debug("chainName:", chainName)

	var txSerialized string
	if ts, ok := d.GetOk("txSerialized"); ok {
		txSerialized = ts.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing txSerialized in sign")
	}

	walletPath := getWalletPath(username, address)

	wallet, err := getWallet(ctx, req, walletPath)
	if err != nil {
		return nil, err
	}

	signature, err := sign(wallet.PrivateKey, chainName, txSerialized)
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
