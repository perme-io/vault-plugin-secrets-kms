package kms

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

type testWalletEnv struct {
	PrivateKey       *secp256k1.PrivateKey
	PublicKey        *secp256k1.PublicKey
	PrivateKeyString string
	PublicKeyString  string
	Address          string
}

func TestSecp256k1(t *testing.T) {
	walletEnv := testWalletEnv{}

	if privateKey, err := secp256k1.GeneratePrivateKey(); err == nil {
		walletEnv.PrivateKey = privateKey
		walletEnv.PublicKey = privateKey.PubKey()
		walletEnv.Address = privateKey.Key.String()
	} else if err != nil {
		t.Errorf("failed to generate privateKey with secp256k1: err=%v", err)
	}

	walletEnv.PrivateKeyString = hex.EncodeToString(walletEnv.PrivateKey.Serialize())
	walletEnv.PublicKeyString = hex.EncodeToString(walletEnv.PublicKey.SerializeCompressed())

	t.Logf("privateKey : %v", walletEnv.PrivateKey)
	t.Logf("privateKey string : %v", walletEnv.PrivateKeyString)
	t.Logf("Address : %v", walletEnv.Address)
	t.Logf("publicKey : %v", walletEnv.PublicKey)
	t.Logf("publicKey string : %v", walletEnv.PublicKeyString)

	pkBytes := walletEnv.PrivateKey.Key.Bytes()
	privKey := secp256k1.PrivKeyFromBytes(pkBytes[:])
	privKeyString := hex.EncodeToString(privKey.Serialize())
	require.Equalf(t, walletEnv.PrivateKeyString, privKeyString, "expected=%v, actual=%v", walletEnv.PrivateKeyString, privKeyString)

	address := privKey.Key.String()
	require.Equalf(t, walletEnv.Address, address, "expected=%v, actual=%v", walletEnv.Address, address)

	pubKey, err := secp256k1.ParsePubKey(walletEnv.PublicKey.SerializeCompressed())
	pubKeyString := hex.EncodeToString(pubKey.SerializeCompressed())
	if err != nil {
		t.Errorf("failed to parse publicKey: err=%v", err)
	}
	require.Equalf(t, walletEnv.PublicKeyString, pubKeyString, "expected=%v, actual=%v", walletEnv.PublicKeyString, pubKeyString)
}

func TestCreateWallet(t *testing.T) {
	wallet, err := createWallet()

	require.Nilf(t, err, "createWallet err: expected nil, actual=%v", err)
	require.NotNilf(t, wallet, "createWallet wallet: expected not nil, actual=%v", wallet)
}
