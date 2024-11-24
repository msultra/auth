package ntlm

import (
	"encoding/binary"
	"errors"
)

type VarField struct {
	Length uint16
	MaxLen uint16
	Offset uint32
}

func (v *VarField) Extract(baseOffset int, payload []byte) (data []byte, err error) {
	if baseOffset > int(v.Offset) {
		return []byte{}, nil
	}
	if v.Offset+uint32(v.Length) > uint32(len(payload)) {
		return nil, errors.New("invalid offset")
	}
	return payload[v.Offset-uint32(baseOffset) : v.Offset-uint32(baseOffset)+uint32(v.Length)], nil
}

func NewVarField(dst *[]byte, src []byte, offset *int) VarField {
	f := VarField{
		Length: uint16(len(src)),
		MaxLen: uint16(len(src)),
		Offset: uint32(*offset),
	}

	head, tail := growSlice(*dst, len(src))
	copy(tail, src)
	*dst = head

	*offset += int(f.Length)
	return f
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

func growSlice(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
