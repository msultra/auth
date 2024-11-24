package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/msultra/encoder"
)

var (
	NtlmOID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
	Signature = []byte("NTLMSSP\x00")
)

var ClientVersion = []byte{
	0: 0x0a, // Windows Major Version
	1: 0x00, // Windows Minor Version
	7: 0x0f, // Build Number
}

const DefaultNegotiateFlags = Negotiate56 | Negotiate128 | NegotiateKeyExch | NegotiateTargetInfo | NegotiateExtendedSecurity | NegotiateAlwaysSign | NegotiateNTLM | NegotiateSign | RequestTarget | NegotiateUnicode | NegotiateVersion

const (
	NegotiateUnicode = 1 << iota
	NegotiateOEM
	RequestTarget
	_ // Reserved
	NegotiateSign
	NegotiateSeal
	NegotiateDatagram
	NegotiateLMKey
	_ // Reserved
	NegotiateNTLM
	_ // Reserved
	NegotiateAnonymous
	NegotiateOEMDomainSupplied
	NegotiateOEMWorkstationSupplied
	_ // Reserved
	NegotiateAlwaysSign
	TargetTypeDomain
	TargetTypeServer
	_ // Reserved
	NegotiateExtendedSecurity
	NegotiateIdentify
	_ // Reserved
	RequestNonNTSessionKey
	NegotiateTargetInfo
	_ // Reserved
	NegotiateVersion
	_ // Reserved
	_ // Reserved
	_ // Reserved
	Negotiate128
	NegotiateKeyExch
	Negotiate56
)

const (
	MessageTypeNtLmNegotiate    = 0x00000001
	MessageTypeNtLmChallenge    = 0x00000002
	MessageTypeNtLmAuthenticate = 0x00000003
)

func (n *NtlmProvider) NewNegotiateMessage() ([]byte, error) {
	//        NegotiateMessage
	//   0-8: Signature
	//  8-12: MessageType
	// 12-16: NegotiateFlags
	// 16-24: DomainNameFields
	// 24-32: WorkstationFields
	// 32-40: Version
	//   40-: Payload
	if n.NegotiateFlags == 0 {
		n.NegotiateFlags = DefaultNegotiateFlags
	}

	// NegotiateMessage
	payload := make([]byte, 40)

	// 0-8: Signature
	copy(payload, Signature)

	// 8-12: MessageType
	binary.LittleEndian.PutUint32(payload[8:12], MessageTypeNtLmNegotiate)

	// 12-16: NegotiateFlags
	if n.IsOEM {
		n.NegotiateFlags |= NegotiateOEM
		if n.Domain != "" {
			n.NegotiateFlags |= NegotiateOEMDomainSupplied
		}
		if n.Workstation != "" {
			n.NegotiateFlags |= NegotiateOEMWorkstationSupplied
		}
	}
	binary.LittleEndian.PutUint32(payload[12:16], uint32(n.NegotiateFlags))

	// 16-24: DomainNameFields
	expectedLen := 40
	toAppend := []byte{}
	if n.Domain != "" && n.IsOEM {
		uniStr := encoder.StrToUTF16(n.Domain)
		toAppend = append(toAppend, uniStr...)

		binary.LittleEndian.PutUint16(payload[16:18], uint16(len(uniStr)))
		binary.LittleEndian.PutUint16(payload[18:20], uint16(len(uniStr)))
		binary.LittleEndian.PutUint32(payload[20:24], uint32(expectedLen))
		expectedLen += len(uniStr)
	}

	// 24-32: WorkstationFields
	if n.Workstation != "" && n.IsOEM {
		uniStr := encoder.StrToUTF16(n.Workstation)
		toAppend = append(toAppend, uniStr...)

		binary.LittleEndian.PutUint16(payload[24:26], uint16(len(uniStr)))
		binary.LittleEndian.PutUint16(payload[26:28], uint16(len(uniStr)))
		binary.LittleEndian.PutUint32(payload[28:32], uint32(expectedLen))
		expectedLen += len(uniStr)
	}

	// 32-40: Version
	copy(payload[32:], ClientVersion)

	// 40-: Payload
	n.NegotiateMessage = append(payload, toAppend...)
	return n.NegotiateMessage, nil
}

func (n *NtlmProvider) ValidateChallengeMessage(sc []byte) (err error) {
	//        ChallengeMessage
	//   0-8: Signature
	//  8-12: MessageType
	// 12-20: TargetNameFields
	// 20-24: NegotiateFlags
	// 24-32: ServerChallenge
	// 32-40: _
	// 40-48: TargetInfoFields
	// 48-56: Version
	//   56-: Payload

	if len(sc) < 48 {
		return errors.New("invalid challenge message length")
	}

	//        ChallengeMessage
	//        Note that sc is the ChallengeMessage

	//   0-8: Signature
	if !bytes.Equal(sc[:8], Signature) {
		return errors.New("invalid signature")
	}

	//  8-12: MessageType
	if binary.LittleEndian.Uint32(sc[8:12]) != MessageTypeNtLmChallenge {
		return errors.New("invalid message type")
	}

	// 12-20: TargetNameFields
	if n.TargetName, err = extractFields(sc[12:20], sc); err != nil {
		return err
	}

	// 20-24: NegotiateFlags
	challengeFlags := binary.LittleEndian.Uint32(sc[20:24])
	if challengeFlags&RequestTarget == 0 || challengeFlags&NegotiateTargetInfo == 0 {
		return errors.New("invalid negotiate flags")
	}

	// 24-32: ServerChallenge
	n.ServerChallenge = sc[24:32]

	// 32-40: _

	// 40-48: TargetInfoFields
	targetInfo, err := extractFields(sc[40:48], sc)
	if err != nil {
		return err
	}

	avpairs, err := NewAvPairs(targetInfo)
	if err != nil {
		return err
	}

	if n.TargetInfo, err = NewTargetInformation(avpairs); err != nil {
		return err
	}

	// 48-56: Version
	// version := sc[48:56]
	return nil
}

func (n *NtlmProvider) GenerateAuthenticateMessage() ([]byte, error) {
	//        AuthenticateMessage
	//   0-8: Signature
	//  8-12: MessageType
	// 12-20: LmChallengeResponseFields
	// 20-28: NtChallengeResponseFields
	// 28-36: DomainNameFields
	// 36-44: UserNameFields
	// 44-52: WorkstationFields
	// 52-60: EncryptedRandomSessionKeyFields
	// 60-64: NegotiateFlags
	// 64-72: Version
	// 72-88: MIC
	//   88-: Payload
	var payload []byte

	offset := 88

	//        AuthenticateMessage
	authenticateMessage := make([]byte, offset)

	//   0-8: Signature
	copy(authenticateMessage[0:8], Signature)

	//  8-12: MessageType
	binary.LittleEndian.PutUint32(authenticateMessage[8:12], MessageTypeNtLmAuthenticate)

	// 12-20: LmChallengeResponseFields
	//        0-2: len
	//        2-4: maxlen
	//        4-8: offset
	lm := n.NewLMChallengeResponse()
	binary.LittleEndian.PutUint16(authenticateMessage[12:14], uint16(len(lm)))
	binary.LittleEndian.PutUint16(authenticateMessage[14:16], uint16(len(lm)))
	binary.LittleEndian.PutUint32(authenticateMessage[16:20], uint32(offset))
	payload = append(payload, lm...)
	offset += len(lm)

	// 20-28: NtChallengeResponseFields
	nt, err := n.NewNtChallengeResponse(n.TargetName)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint16(authenticateMessage[20:22], uint16(len(nt)))
	binary.LittleEndian.PutUint16(authenticateMessage[22:24], uint16(len(nt)))
	binary.LittleEndian.PutUint32(authenticateMessage[24:28], uint32(offset))
	payload = append(payload, nt...)
	offset += len(nt)

	// 28-36: DomainNameFields
	domain := encoder.StrToUTF16(strings.ToUpper(n.Domain))
	binary.LittleEndian.PutUint16(authenticateMessage[28:30], uint16(len(domain)))
	binary.LittleEndian.PutUint16(authenticateMessage[30:32], uint16(len(domain)))
	binary.LittleEndian.PutUint32(authenticateMessage[32:36], uint32(offset))
	payload = append(payload, domain...)
	offset += len(domain)

	// 36-44: UserNameFields
	user := encoder.StrToUTF16(strings.ToUpper(n.User))
	binary.LittleEndian.PutUint16(authenticateMessage[36:38], uint16(len(user)))
	binary.LittleEndian.PutUint16(authenticateMessage[38:40], uint16(len(user)))
	binary.LittleEndian.PutUint32(authenticateMessage[40:44], uint32(offset))
	payload = append(payload, user...)
	offset += len(user)

	// 44-52: WorkstationFields
	workstation := encoder.StrToUTF16(strings.ToUpper(n.Workstation))
	binary.LittleEndian.PutUint16(authenticateMessage[44:46], uint16(len(workstation)))
	binary.LittleEndian.PutUint16(authenticateMessage[46:48], uint16(len(workstation)))
	binary.LittleEndian.PutUint32(authenticateMessage[48:52], uint32(offset))
	payload = append(payload, workstation...)
	offset += len(workstation)

	// 52-60: EncryptedRandomSessionKeyFields
	binary.LittleEndian.PutUint16(authenticateMessage[52:54], uint16(len(n.RandomSessionKey)))
	binary.LittleEndian.PutUint16(authenticateMessage[54:56], uint16(len(n.RandomSessionKey)))
	binary.LittleEndian.PutUint32(authenticateMessage[56:60], uint32(offset))
	payload = append(payload, n.RandomSessionKey...)
	offset += len(n.RandomSessionKey)

	// 60-64: NegotiateFlags
	binary.LittleEndian.PutUint32(authenticateMessage[60:64], uint32(n.NegotiateFlags))

	// 64-72: Version
	copy(authenticateMessage[64:72], ClientVersion)

	// 72-88: MIC
	// to overwrite later
	copy(authenticateMessage[72:88], make([]byte, 16))

	// 88-: Payload
	n.AuthenticateMessage = append(authenticateMessage, payload...)

	hash := hmac.New(md5.New, n.ExportedSessionKey)
	if _, err := hash.Write(n.NegotiateMessage); err != nil {
		return nil, err
	}

	if _, err = hash.Write(n.AuthenticateMessage); err != nil {
		return nil, err
	}
	copy(n.AuthenticateMessage[72:88], hash.Sum(authenticateMessage[72:88]))

	// Before returning, we need to generate the session keys
	n.ServerSigningKey, err = signKey(
		n.ExportedSessionKey,
		[]byte("session key to server-to-client signing key magic constant\x00"),
		n.NegotiateFlags,
	)
	if err != nil {
		return nil, err
	}

	n.ClientSigningKey, err = signKey(
		n.ExportedSessionKey,
		[]byte("session key to client-to-server signing key magic constant\x00"),
		n.NegotiateFlags,
	)
	if err != nil {
		return nil, err
	}

	var sealedClientKey, sealedServerKey []byte

	sealedClientKey, err = sealKey(
		n.ExportedSessionKey,
		[]byte("session key to client-to-server sealing key magic constant\x00"),
		n.NegotiateFlags,
	)
	if err != nil {
		return nil, err
	}

	sealedServerKey, err = sealKey(
		n.ExportedSessionKey,
		[]byte("session key to server-to-client sealing key magic constant\x00"),
		n.NegotiateFlags,
	)
	if err != nil {
		return nil, err
	}

	if n.ClientHandle, err = rc4.NewCipher(sealedClientKey); err != nil {
		return nil, err
	}

	if n.ServerHandle, err = rc4.NewCipher(sealedServerKey); err != nil {
		return nil, err
	}

	return n.AuthenticateMessage, nil
}
