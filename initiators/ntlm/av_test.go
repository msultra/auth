package ntlm_test

import (
	"testing"

	"github.com/msultra/spnego/initiators/ntlm"
)

func TestAvPairs(t *testing.T) {
	p := make(ntlm.AvPairs)
	p[ntlm.AvIDMsvAvNbComputerName] = ntlm.ToUnicode("DC01")
	p[ntlm.AvIDMsvAvNbDomainName] = ntlm.ToUnicode("CONTOSO")
	bytes := p.Bytes()
	t.Logf("Bytes: %x", bytes)
	t.Logf("Encoded successfully")

	pairs, err := ntlm.NewAvPairs(bytes)
	if err != nil {
		t.Fatalf("failed to create av pairs: %v", err)
	}
	t.Logf("Pairs: %v", pairs)
	t.Logf("Decoded successfully")

	tinfo, err := ntlm.NewTargetInformation(pairs)
	if err != nil {
		t.Fatalf("failed to create target information: %v", err)
	}
	t.Logf("Reconstructed successfully into ntlm.TargetInformation")

	if tinfo.NbComputerName != "DC01" || tinfo.NbDomainName != "CONTOSO" {
		t.Fatalf("target info is incorrect: %v", tinfo)
	}
	t.Logf("(NbComputerName) %v == DC01", tinfo.NbComputerName)
	t.Logf("(NbDomainName)   %v == CONTOSO", tinfo.NbDomainName)
	t.Logf("Verified successfully")
}

func TestChannelBindings(t *testing.T) {
	// TODO: Gather channel bindings from a real NTLM authentication
}
