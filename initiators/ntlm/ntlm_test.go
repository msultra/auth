package ntlm_test

import (
	"bytes"
	"encoding/binary"
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

func TestAcceptSecContext(t *testing.T) {
	provider := ntlm.NtlmProvider{}

	challenge, err := hex.DecodeString("4e544c4d53535000020000000600060038000000358299e2212ba239356b3d8200000000000000005e005e003e0000000a0063450000000f4c0041004200020006004c0041004200010004004400430004000e006c00610062002e006c0061006e0003001400440043002e006c00610062002e006c0061006e0005000e006c00610062002e006c0061006e0007000800f364eebe92ecd80100000000")
	if err != nil {
		t.Fatalf("Failed to decode challenge hex string: %v", err)
	}

	if err := provider.ValidateChallengeMessage(challenge); err != nil {
		t.Fatalf("ValidateChallengeMessage() failed: %v", err)
	}

	t.Logf("TargetName: %s", ntlm.ToString(provider.TargetName))
	if ntlm.ToString(provider.TargetName) != "LAB" {
		t.Fatalf("TargetName is incorrect")
	}

	// Test AvPairs
	targetInfo := provider.TargetInfo
	t.Logf("NetBIOS Domain Name: %s", targetInfo.NbDomainName)
	if targetInfo.NbDomainName != "LAB" {
		t.Fatalf("NetBIOS Domain Name is incorrect")
	}

	t.Logf("NetBIOS Computer Name: %s", targetInfo.NbComputerName)
	if targetInfo.NbComputerName != "DC" {
		t.Fatalf("NetBIOS Computer Name is incorrect")
	}

	t.Logf("DNS Domain Name: %s", targetInfo.DNSDomainName)
	if targetInfo.DNSDomainName != "lab.lan" {
		t.Fatalf("DNS Domain Name is incorrect")
	}

	t.Logf("DNS Computer Name: %s", targetInfo.DNSComputerName)
	if targetInfo.DNSComputerName != "DC.lab.lan" {
		t.Fatalf("DNS Computer Name is incorrect")
	}

	t.Logf("DNS Tree Name: %s", targetInfo.DNSTreeName)
	if targetInfo.DNSTreeName != "lab.lan" {
		t.Fatalf("DNS Tree Name is incorrect")
	}

	t.Logf("Timestamp: %d", targetInfo.Timestamp)
	ts, err := hex.DecodeString("f364eebe92ecd801")
	if err != nil {
		t.Fatalf("Failed to decode timestamp hex string: %v", err)
	}
	if targetInfo.Timestamp != binary.LittleEndian.Uint64(ts) {
		t.Fatalf("Timestamp is incorrect")
	}
}
