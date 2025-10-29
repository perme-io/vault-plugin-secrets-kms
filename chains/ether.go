package chains

import (
	b64 "encoding/base64"
	"encoding/hex"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

const (
	ethPublicKeyHashOffset = 20
)

type EtherChain BaseChain

func (c EtherChain) GetPrivateKeySerialized() []byte {
	return c.PrivateKey.Serialize()
}

func (c EtherChain) GetPublicKeySerialized() []byte {
	return c.PrivateKey.PubKey().SerializeUncompressed()
}

func (c EtherChain) GetPublicKeyAddress(pubKeySerialized []byte) string {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(pubKeySerialized[1:])
	pubKeyHash := hasher.Sum(nil)

	beginIndex := len(pubKeyHash) - ethPublicKeyHashOffset
	address := "0x" + hex.EncodeToString(pubKeyHash[beginIndex:])

	return address
}

func (c EtherChain) SignCompact(msgHash []byte) (string, error) {
	// Compact signature format:
	// <1-byte compact sig recovery code><32-byte R><32-byte S>
	signature := ecdsa.SignCompact(c.PrivateKey, msgHash, false)

	compactSig := rearrangeSignature(signature, true)

	base64Sign := b64.StdEncoding.EncodeToString(compactSig)
	return base64Sign, nil
}
