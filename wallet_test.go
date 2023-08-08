package kms

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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
