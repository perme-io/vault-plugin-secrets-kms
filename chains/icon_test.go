package chains

import (
	b64 "encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestIconTxSignCompactSerialized(t *testing.T) {
	serializedString := "icx_sendTransaction" +
		".from.hx5443d0db003fd7202046bbf31eaeade60af20c41" +
		".nid.0x7.nonce.0x1.stepLimit.0x11b340.timestamp.0x5fdaf54c5ed34" +
		".to.cxcb952e97e554800a1da099e5102079ceda03b277.value.0x8ac7230489e80000" +
		".version.0x3"

	expectedSignature := "r+bGnNA1RBcw5SVAinoSDo4plG8/X5HzZ6cJxlfTv/REyg0bgErn/oZIj43OhN/Xquwx0oNwQ27UBVWkT4ByXQE="

	// wallet, _ := createWallet()

	// privateKeyString := "2f1f6284e96d217bca90c0d7e4b6971b83dd7a04e1f5cef9cb65e26451046368"
	privateKeyString := "1a5e70bfd427ec9ec3decf8d6e3461dfb4dbbde4351e071d9728d96e711e1b9c"
	publicKeyString := "0215526d990ed57973c2722b9c772b76e9d4ef0fcf4cea95b76844ffa925050ee6"

	// privKeyBytes, err := hex.DecodeString(wallet.PrivateKey)

	pubKeyBytes, err := hex.DecodeString(publicKeyString)
	if err != nil {
		t.Errorf("error=%v", err)
	}

	publicKey, _ := secp256k1.ParsePubKey(pubKeyBytes)

	// Sign a tx using the private key.
	serializedBytes := []byte(serializedString)
	messageHash := sha3.Sum256(serializedBytes)

	privKeyBytes, err := hex.DecodeString(privateKeyString)
	if err != nil {
		t.Errorf("error=%v", err)
	}

	chain := IconChain{PrivateKey: secp256k1.PrivKeyFromBytes(privKeyBytes)}
	signature, err := chain.SignCompact(serializedString)
	if err != nil {
		t.Errorf("error=%v", err)
	}

	t.Logf("signature_base64: %v", signature)

	require.Equalf(t, expectedSignature, signature, "icon Signature Base64: expected %x, actual=%x", expectedSignature, signature)

	decodedSignature, err := b64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Errorf("error=%v", err)
	}
	t.Logf("decoded signature: %x", decodedSignature)

	compactSignature := rearrangeSignature(decodedSignature, false)
	t.Logf("compact signature: %x", compactSignature)

	require.Equalf(t, 65, len(compactSignature), "signature length: expected=65, actual=%v", len(compactSignature))

	pubKey, compressed, _ := ecdsa.RecoverCompact(compactSignature, messageHash[:])
	t.Logf("recovered pubKey=%x, compressed=%v", pubKey.SerializeCompressed(), compressed)

	require.Equalf(t, publicKey, pubKey, "recovered publicKey: expected %x, actual=%x", publicKey.SerializeCompressed(), pubKey.SerializeCompressed())
}
