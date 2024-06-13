package chains

import "github.com/decred/dcrd/dcrec/secp256k1/v4"

type ChainName string

const (
	AERGO ChainName = "aergo"
	ICON  ChainName = "icon"
)

type Chain interface {
	GetPrivateKeySerialized() []byte
	GetPublicKeySerialized() []byte
	GetPublicKeyAddress(b []byte) string
}

type BaseChain struct {
	PrivateKey *secp256k1.PrivateKey
}
