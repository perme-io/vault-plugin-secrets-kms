package chains

import (
	"encoding/hex"

	"golang.org/x/crypto/sha3"
)

const (
	publicKeyHashOffset = 20
)

type IconChain BaseChain

func (c IconChain) GetPrivateKeySerialized() []byte {
	return c.PrivateKey.Serialize()
}

func (c IconChain) GetPublicKeySerialized() []byte {
	return c.PrivateKey.PubKey().SerializeUncompressed()
}

func (c IconChain) GetPublicKeyAddress(pubKeySerialized []byte) string {
	pubKeyHash := sha3.Sum256(pubKeySerialized[1:])

	beginIndex := len(pubKeyHash) - publicKeyHashOffset
	address := "hx" + hex.EncodeToString(pubKeyHash[beginIndex:])

	return address
}
