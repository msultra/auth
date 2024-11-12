package auth_test

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"testing"

	"github.com/msultra/auth"
	"github.com/msultra/auth/initiators/ntlm"
)

func TestEncodeNegTokenInit(t *testing.T) {
	var testEncodeNegTokenInit = []struct {
		Types    []asn1.ObjectIdentifier
		Token    string
		Expected string
	}{
		{
			[]asn1.ObjectIdentifier{ntlm.NtlmOID},
			"4e544c4d5353500001000000978208e2000000000000000000000000000000000a005a290000000f",
			"604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000978208e2000000000000000000000000000000000a005a290000000f",
		},
	}
	for i, e := range testEncodeNegTokenInit {
		tok, err := hex.DecodeString(e.Token)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := hex.DecodeString(e.Expected)
		if err != nil {
			t.Fatal(err)
		}
		ret, err := auth.EncodeNegTokenInit(e.Types, tok)
		if err != nil {
			t.Errorf("%d: %v\n", i, err)
		}
		if !bytes.Equal(ret, expected) {
			t.Errorf("%d: fail\n", i)
		}
	}
}
