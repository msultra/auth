package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"strings"
	"time"

	"github.com/msultra/encoder"
	"golang.org/x/crypto/md4"
)

func signKey(key []byte, magicConstant []byte, negotiateFlags uint32) ([]byte, error) {
	if negotiateFlags&NegotiateExtendedSecurity == 0 {
		return []byte{}, nil
	}

	h := md5.New()
	if _, err := h.Write(key); err != nil {
		return nil, err
	}
	if _, err := h.Write(magicConstant); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func sealKey(key []byte, magicConstant []byte, negotiateFlags uint32) ([]byte, error) {
	switch {
	case negotiateFlags&NegotiateExtendedSecurity != 0:
		hSeal := md5.New()
		switch {
		case negotiateFlags&Negotiate128 != 0:
			hSeal.Write(key[:16])
		case negotiateFlags&Negotiate56 != 0:
			hSeal.Write(key[:7])
		default:
			hSeal.Write(key[:5])
		}

		if _, err := hSeal.Write(magicConstant); err != nil {
			return nil, err
		}
		return hSeal.Sum(nil), nil
	case negotiateFlags&NegotiateLMKey != 0:
		sealingKey := make([]byte, 8)
		if negotiateFlags&Negotiate56 != 0 {
			copy(sealingKey, key[:7])
			sealingKey[7] = 0xa0
		} else {
			copy(sealingKey, key[:5])
			sealingKey[5] = 0xe5
			sealingKey[6] = 0x38
			sealingKey[7] = 0xb0
		}
		return sealingKey, nil
	}
	return key, nil
}

func sign(dst []byte, negotiateFlags uint32, handle *rc4.Cipher, signingKey []byte, seqNum uint32, msg []byte) ([]byte, uint32) {
	ret, tag := sliceForAppend(dst, 16)
	if negotiateFlags&NegotiateExtendedSecurity == 0 {
		//        NtlmsspMessageSignature
		//   0-4: Version
		//   4-8: RandomPad
		//  8-12: Checksum
		// 12-16: SeqNum
		binary.LittleEndian.PutUint32(tag[:4], 1)
		binary.LittleEndian.PutUint32(tag[8:12], crc32.ChecksumIEEE(msg))
		handle.XORKeyStream(tag[4:8], tag[4:8])
		handle.XORKeyStream(tag[8:12], tag[8:12])
		handle.XORKeyStream(tag[12:16], tag[12:16])
		tag[12] ^= byte(seqNum)
		tag[13] ^= byte(seqNum >> 8)
		tag[14] ^= byte(seqNum >> 16)
		tag[15] ^= byte(seqNum >> 24)
		if negotiateFlags&NegotiateDatagram == 0 {
			seqNum++
		}
		tag[4] = 0
		tag[5] = 0
		tag[6] = 0
		tag[7] = 0
	} else {
		//        NtlmsspMessageSignatureExt
		//   0-4: Version
		//  4-12: Checksum
		// 12-16: SeqNum

		//   0-4: Version
		binary.LittleEndian.PutUint32(tag[:4], 1)

		// 12-16: SeqNum
		binary.LittleEndian.PutUint32(tag[12:16], seqNum)

		h := hmac.New(md5.New, signingKey)
		h.Write(tag[12:16])
		h.Write(msg)
		copy(tag[4:12], h.Sum(nil))
		if negotiateFlags&NegotiateKeyExch != 0 {
			handle.XORKeyStream(tag[4:12], tag[4:12])
		}
		seqNum++
	}
	return ret, seqNum
}

func (n *NtlmProvider) VerifyMIC(mic, msg []byte, seqNum uint32) (bool, uint32) {
	expectedMIC, seqNum := sign(nil, n.NegotiateFlags, n.ServerHandle, n.ServerSigningKey, seqNum, msg)
	return bytes.Equal(mic, expectedMIC), seqNum
}

func (n *NtlmProvider) SealMessage(msg []byte) ([]byte, uint32) {
	ret, ciphertext := sliceForAppend(nil, len(msg))
	switch {
	case n.NegotiateFlags&NegotiateSeal != 0:
		n.ClientHandle.XORKeyStream(ciphertext[16:], msg)
		_, n.SequenceNumber = sign(ciphertext[:0], n.NegotiateFlags, n.ClientHandle, n.ClientSigningKey, n.SequenceNumber, msg)
	case n.NegotiateFlags&NegotiateSign != 0:
		copy(ciphertext[16:], msg)
		_, n.SequenceNumber = sign(ciphertext[:0], n.NegotiateFlags, n.ClientHandle, n.ClientSigningKey, n.SequenceNumber, msg)
	}
	return ret, n.SequenceNumber
}

func (n *NtlmProvider) UnsealMessage(msg []byte) ([]byte, uint32, error) {
	ret, plaintext := sliceForAppend(nil, len(msg))
	switch {
	case n.NegotiateFlags&NegotiateSeal != 0:
		n.ServerHandle.XORKeyStream(plaintext[16:], msg)
		_, n.SequenceNumber = sign(plaintext[:0], n.NegotiateFlags, n.ServerHandle, n.ServerSigningKey, n.SequenceNumber, msg)
	case n.NegotiateFlags&NegotiateSign != 0:
		copy(plaintext[16:], msg)
		_, n.SequenceNumber = sign(plaintext[:0], n.NegotiateFlags, n.ServerHandle, n.ServerSigningKey, n.SequenceNumber, msg)
	default:
		copy(plaintext, msg[16:])
		for _, s := range msg[:16] {
			if s != 0x0 {
				return nil, 0, errors.New("signature mismatch")
			}
		}
	}
	return ret, n.SequenceNumber, nil
}

func (n *NtlmProvider) NewLMChallengeResponse() []byte {
	//        LMv2Response
	//  0-16: Response
	// 16-24: ChallengeFromClient
	// Empty LMv2ChallengeResponse => unsupported
	return make([]byte, 24)
}

func (n *NtlmProvider) NewNtChallengeResponse(target []byte) ([]byte, error) {
	//        NTLMv2Response
	//  0-16: Response
	//   16-: NTLMv2ClientChallenge

	// Generate Random Client Challenge
	var challenge [8]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, err
	}

	// Generate Hash Function
	domain := encoder.StrToUTF16(n.Domain)
	if domain == nil {
		domain = target
	}

	user := encoder.StrToUTF16(strings.ToUpper(n.User))
	if user == nil {
		// Should be valid for anonymous login
		// TODO: check if this is correct
		user = encoder.StrToUTF16("ANONYMOUS")
	}

	if n.Hash == nil {
		// Use password
		password := encoder.StrToUTF16(n.Password)
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
