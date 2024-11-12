package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

func toUnicode(s string) []byte {
	// https://github.com/Azure/go-ntlmssp/blob/master/unicode.go
	uints := utf16.Encode([]rune(s))
	b := bytes.Buffer{}
	_ = binary.Write(&b, binary.LittleEndian, &uints)
	return b.Bytes()
}

func toString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	ws := make([]uint16, len(b)/2)
	for i := range ws {
		ws[i] = binary.LittleEndian.Uint16(b[2*i : 2*i+2])
	}
	if len(ws) > 0 && ws[len(ws)-1] == 0 {
		ws = ws[:len(ws)-1]
	}
	return string(utf16.Decode(ws))
}

func extractFields(field []byte, full []byte) (data []byte, err error) {
	length := binary.LittleEndian.Uint16(field[0:2])
	maxlen := binary.LittleEndian.Uint16(field[2:4])
	offset := binary.LittleEndian.Uint16(field[4:8])
	if offset+length > uint16(len(full)) {
		return nil, errors.New("invalid offset")
	}
	if maxlen < length {
		return nil, errors.New("invalid length")
	}
	return full[offset : offset+length], nil
}

func (n *NtlmInitiator) NewLMChallengeResponse() []byte {
	//        LMv2Response
	//  0-16: Response
	// 16-24: ChallengeFromClient
	// Empty LMv2ChallengeResponse => unsupported
	return make([]byte, 24)
}

func (n *NtlmInitiator) NewNtChallengeResponse(target []byte) ([]byte, error) {
	//        NTLMv2Response
	//  0-16: Response
	//   16-: NTLMv2ClientChallenge

	// Generate Random Client Challenge
	var challenge [8]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, err
	}

	// Generate Hash Function
	domain := toUnicode(n.Domain)
	if domain == nil {
		domain = target
	}

	user := toUnicode(strings.ToUpper(n.User))
	if user == nil {
		// Should be valid for anonymous login
		// TODO: check if this is correct
		user = toUnicode("ANONYMOUS")
	}

	if n.Hash == nil {
		// Use password
		password := toUnicode(n.Password)
		m4 := md4.New()
		_, err := m4.Write(password)
		if err != nil {
			return nil, err
		}
		hash := m4.Sum(nil)
		n.Hash = hash
	}

	hm := hmac.New(md5.New, n.Hash)
	_, err := hm.Write(user)
	if err != nil {
		return nil, err
	}
	_, err = hm.Write(domain)
	if err != nil {
		return nil, err
	}

	hashfunction := hmac.New(md5.New, hm.Sum(nil))
	_, err = hashfunction.Write(n.ServerChallenge)
	if err != nil {
		return nil, err
	}
	_, err = hashfunction.Write(challenge[:])
	if err != nil {
		return nil, err
	}

	//  0-16: Response
	response := make([]byte, 16)
	_ = hashfunction.Sum(response[:])

	//   16-: NTLMv2ClientChallenge

	//	      NTLMv2ClientChallenge
	//	 0-1: RespType
	//	 1-2: HiRespType
	//	 2-4: _
	//	 4-8: _
	//	8-16: TimeStamp
	//
	// 16-24: ChallengeFromClient
	// 24-28: _
	//
	//	 28-: AvPairs

	//	      NTLMv2ClientChallenge
	clientChallenge := make([]byte, 28)

	//	 0-1: RespType
	clientChallenge[0] = 0x01

	//	 1-2: HiRespType
	clientChallenge[1] = 0x01

	//	 2-4: _

	//	 4-8: _

	//	8-16: TimeStamp

	// if no timestamp provided in AvPairs, provide our own
	if n.TargetInfo.Timestamp == 0 {
		n.TargetInfo.Timestamp = uint64((time.Now().UnixNano() / 100) + 116444736000000000)
	}
	binary.LittleEndian.PutUint64(clientChallenge[8:16], n.TargetInfo.Timestamp)

	// 16-24: ChallengeFromClient
	copy(clientChallenge[16:24], challenge[:])

	// 24-28: _

	// 28-: AvPairs
	clientChallenge = append(clientChallenge, n.TargetInfo.AvPairsBytes...)

	ntlmv2Response := append(response, clientChallenge...)

	// Before returning, we need to generate the session keys
	hashfunction.Reset()
	hashfunction.Write(response[:])
	n.SessionBaseKey = hashfunction.Sum(nil)
	n.KeyExchangeKey = n.SessionBaseKey
	n.ExportedSessionKey = make([]byte, 16)

	if n.NegotiateFlags&NegotiateKeyExch == 0 {
		n.ExportedSessionKey = n.KeyExchangeKey
		return ntlmv2Response, nil
	}

	if _, err := rand.Read(n.RandomSessionKey[:]); err != nil {
		return nil, err
	}

	cipher, err := rc4.NewCipher(n.KeyExchangeKey)
	if err != nil {
		return nil, err
	}
	n.RandomSessionKey = make([]byte, 16)
	cipher.XORKeyStream(n.RandomSessionKey, n.ExportedSessionKey)

	// Return the NTLMv2Response
	return ntlmv2Response, nil
}
