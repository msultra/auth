package ntlm

import (
	"encoding/binary"
	"errors"
)

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
