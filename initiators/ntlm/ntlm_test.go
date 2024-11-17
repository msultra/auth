package ntlm_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/msultra/spnego/initiators/ntlm"
)

func TestInitSecContext(t *testing.T) {
	provider := ntlm.NtlmProvider{
		NegotiateFlags: 0xe21882b7,
	}

	bs, err := provider.InitSecContext()
	if err != nil {
		t.Fatalf("InitSecContext() failed: %v", err)
	}

	// https://wiki.wireshark.org/samplecaptures#ntlmssp
	expected, err := hex.DecodeString("4e544c4d5353500001000000b78218e2000000000000000000000000000000000a0000000000000f")
	if err != nil {
		t.Fatalf("Failed to decode expected hex string: %v", err)
	}

	if !bytes.Equal(bs, expected) {
		t.Fatalf("bytes different from expected")
	}
}
