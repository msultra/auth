package ntlm

import (
	"crypto/rc4"
	"encoding/asn1"
	"encoding/binary"
)

type NtlmProvider struct {
	// User (username for authentication)
	// Can be empty (anonymous login)
	User string

	// Password (password for authentication)
	// Can be empty
	Password string

	// Hash (NTLM hash of the password)
	// Can be nil if the password is not known or not provided
	Hash []byte

	// Domain (domain for authentication)
	Domain string

	// Workstation (workstation for authentication)
	Workstation string

	// TargetName (target name)
	// Don't touch unless you know what you're doing
	TargetName []byte

	// Negotiate Flags
	// Don't touch unless you know what you're doing
	NegotiateFlags uint32

	// SessionBaseKey (used to derive session keys)
	// Don't touch unless you know what you're doing
	SessionBaseKey []byte

	// KeyExchangeKey (used to derive session keys)
	// Don't touch unless you know what you're doing
	KeyExchangeKey []byte

	// RandomSessionKey (used to derive session keys)
	// Don't touch unless you know what you're doing
	RandomSessionKey []byte

	// ExportedSessionKey (session key)
	// Don't touch unless you know what you're doing
	ExportedSessionKey []byte

	// ClientSigningKey (used to sign messages)
	// Don't touch unless you know what you're doing
	ClientSigningKey []byte

	// ServerSigningKey (used to verify messages)
	// Don't touch unless you know what you're doing
	ServerSigningKey []byte

	// ServerHandle (used to decrypt messages)
	// Don't touch unless you know what you're doing
	ServerHandle *rc4.Cipher

	// ClientHandle (used to encrypt messages)
	// Don't touch unless you know what you're doing
	ClientHandle *rc4.Cipher

	// SequenceNumber (used to sequence messages)
	// Don't touch unless you know what you're doing
	SequenceNumber uint32

	// ServerChallenge
	// Don't touch unless you know what you're doing
	ServerChallenge []byte

	// ClientChallenge
	// Don't touch unless you know what you're doing
	ClientChallenge []byte

	// NegotiateMessage (Type 1)
	// Don't touch unless you know what you're doing
	NegotiateMessage []byte

	// AuthenticateMessage (Type 3)
	// Don't touch unless you know what you're doing
	AuthenticateMessage []byte

	// Target Information (avpairs)
	// Don't touch unless you know what you're doing
	TargetInfo *TargetInformation
}

// GetOID returns the NTLM mechanism OID
func (n *NtlmProvider) GetOID() asn1.ObjectIdentifier {
	return NtlmOID
}

// InitSecContext generates the initial NTLM Type 1 message
func (n *NtlmProvider) InitSecContext() ([]byte, error) {
	//        NegotiateMessage
	//   0-8: Signature
	//  8-12: MessageType
	// 12-16: NegotiateFlags
	// 16-24: DomainNameFields
	// 24-32: WorkstationFields
	// 32-40: Version
	//   40-: Payload
	var flags uint32
	if n.NegotiateFlags == 0 {
		flags = Negotiate56 | Negotiate128 | NegotiateKeyExch | NegotiateTargetInfo |
			NegotiateExtendedSecurity | NegotiateAlwaysSign | NegotiateNTLM | NegotiateSign |
			RequestTarget | NegotiateUnicode | NegotiateVersion
	} else {
		flags = n.NegotiateFlags
	}

	// NegotiateMessage
	payload := make([]byte, 40)

	// 0-8: Signature
	copy(payload, Signature)

	// 8-12: MessageType
	binary.LittleEndian.PutUint32(payload[8:12], MessageTypeNtLmNegotiate)

	// 12-16: NegotiateFlags
	if n.Domain != "" {
		flags |= NegotiateDomainSupplied
	}
	if n.Workstation != "" {
		flags |= NegotiateWorkstationSupplied
	}
	n.NegotiateFlags = flags
	binary.LittleEndian.PutUint32(payload[12:16], uint32(flags))

	// 16-24: DomainNameFields
	expectedLen := 40
	toAppend := []byte{}
	if n.Domain != "" {
		uniStr := ToUnicode(n.Domain)
		toAppend = append(toAppend, uniStr...)

		binary.LittleEndian.PutUint16(payload[16:18], uint16(len(uniStr)))
		binary.LittleEndian.PutUint16(payload[18:20], uint16(len(uniStr)))
		binary.LittleEndian.PutUint32(payload[20:24], uint32(expectedLen))
		expectedLen += len(uniStr)
	}

	// 24-32: WorkstationFields
	if n.Workstation != "" {
		uniStr := ToUnicode(n.Workstation)
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

// AcceptSecContext processes the NTLM Type 2 message and generates Type 3 response
func (n *NtlmProvider) AcceptSecContext(sc []byte) ([]byte, error) {
	if err := n.ValidateChallengeMessage(sc); err != nil {
		return nil, err
	}
	return n.GenerateAuthenticateMessage()
}

// GetMIC generates a Message Integrity Code for the given bytes
func (n *NtlmProvider) GetMIC(bs []byte) (mic []byte) {
	if n.NegotiateFlags&NegotiateSign == 0 {
		return []byte{}
	}

	mic, n.SequenceNumber = sign(
		nil,
		n.NegotiateFlags,
		n.ClientHandle,
		n.ClientSigningKey,
		n.SequenceNumber,
		bs,
	)
	return mic
}

// SessionKey returns the established session key
func (n *NtlmProvider) SessionKey() []byte {
	return n.ExportedSessionKey
}
