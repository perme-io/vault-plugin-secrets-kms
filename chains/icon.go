package chains

import (
	b64 "encoding/base64"
	"encoding/hex"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

const (
	publicKeyHashOffset = 20
	// https://github.com/decred/dcrd/blob/dcrec/secp256k1/v4.2.0/dcrec/secp256k1/ecdsa/signature.go#L738
	compactMagicOffset = 27
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

func (c IconChain) SignCompact(serializedString string) (string, error) {
	// privKeyBytes, err := hex.DecodeString(c.privKeyString)
	// if err != nil {
	// 	return "", err
	// }

	// privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	privKey := c.PrivateKey

	// Sign a tx using the private key.
	serializedBytes := []byte(serializedString)
	messageHash := sha3.Sum256(serializedBytes)

	// Compact signature format:
	// <1-byte compact sig recovery code><32-byte R><32-byte S>
	signature := ecdsa.SignCompact(privKey, messageHash[:], false)

	compactSig := rearrangeSignature(signature, true)

	base64Sign := b64.StdEncoding.EncodeToString(compactSig)
	return base64Sign, nil
}

// rearrangeSignature
//
// reverse true: <32-byte R><32-byte S><1-byte compact sig recovery code>
//
// reverse false: <1-byte compact sig recovery code><32-byte R><32-byte S>
func rearrangeSignature(signature []byte, reverse bool) []byte {
	var newSignature []byte

	if reverse {
		recid := signature[0] - compactMagicOffset
		newSignature = append(newSignature, signature[1:]...)
		newSignature = append(newSignature, recid)
	} else {
		recid := signature[len(signature)-1] + compactMagicOffset
		newSignature = append(newSignature, recid)
		newSignature = append(newSignature, signature[:len(signature)-1]...)
	}

	return newSignature
}
