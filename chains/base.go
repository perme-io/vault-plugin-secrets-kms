package chains

import (
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type ChainName string

const (
	AERGO ChainName = "aergo"
	ICON  ChainName = "icon"
	ETHER ChainName = "ether"
)

type Chain interface {
	GetPrivateKeySerialized() []byte
	GetPublicKeySerialized() []byte
	GetPublicKeyAddress(b []byte) string
	SignCompact(msgHash []byte) (string, error)
}

type BaseChain struct {
	PrivateKey *secp256k1.PrivateKey
}

func NewChain(chainName ChainName, privateKey *secp256k1.PrivateKey) (Chain, error) {
	switch chainName {
	case ICON:
		return IconChain{PrivateKey: privateKey}, nil
	case AERGO:
		return AergoChain{PrivateKey: privateKey}, nil
	case ETHER:
		return EtherChain{PrivateKey: privateKey}, nil
	}
	return nil, fmt.Errorf("unknown chain name: %v", chainName)
}
