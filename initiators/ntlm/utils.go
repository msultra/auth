package ntlm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

func ToUnicode(s string) []byte {
	// https://github.com/Azure/go-ntlmssp/blob/master/unicode.go
	uints := utf16.Encode([]rune(s))
	b := bytes.Buffer{}
	_ = binary.Write(&b, binary.LittleEndian, &uints)
	return b.Bytes()
}

func ToString(b []byte) string {
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

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
