package kms

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTxSerialize(t *testing.T) {
	t.Skip()

	txData := map[string]interface{}{
		"version":   "0x3",
		"from":      "hxbe258ceb872e08851f1f59694dac2558708ece11",
		"to":        "hx5bfdb090f43a808005ffc27c25b213145e80b7cd",
		"value":     "0xde0b6b3a7640000",
		"stepLimit": "0x12345",
		"timestamp": "0x563a6cf330136",
		"nid":       "0x1",
		"nonce":     "0x1",
	}
	t.Logf("txData=%v", txData)

	serialized := Serialize(txData)
	t.Logf("txData serialized=%v", serialized)

	expected := "icx_sendTransaction" +
		".from.hxbe258ceb872e08851f1f59694dac2558708ece11" +
		".nid.0x1.nonce.0x1.stepLimit.0x12345.timestamp.0x563a6cf330136" +
		".to.hx5bfdb090f43a808005ffc27c25b213145e80b7cd.value.0xde0b6b3a7640000" +
		".version.0x3"

	t.Logf("serialized expected=%v", expected)
	require.Equalf(t, expected, serialized, "TxSerialize: expected=%v actual=%v", expected, serialized)
}
