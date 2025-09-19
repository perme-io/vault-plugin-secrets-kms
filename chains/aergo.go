package chains

import (
	"fmt"

	"github.com/btcsuite/btcutil/base58"
)

const (
	AergoAddressVersion = 0x42
)

type AergoChain BaseChain

func (c AergoChain) GetPrivateKeySerialized() []byte {
	return c.PrivateKey.Serialize()
}

func (c AergoChain) GetPublicKeySerialized() []byte {
	return c.PrivateKey.PubKey().SerializeCompressed()
}

func (c AergoChain) GetPublicKeyAddress(pubKeySerialized []byte) string {
	return base58.CheckEncode(pubKeySerialized, AergoAddressVersion)
}

func (c AergoChain) SignCompact(msgHash []byte) (string, error) {
	return "", fmt.Errorf("aergo sign not supported")
}
