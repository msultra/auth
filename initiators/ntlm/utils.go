package ntlm

import (
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

	start := int(v.Offset) - baseOffset
	if start+int(v.Length) > len(payload) {
		return nil, errors.New("invalid offset")
	}
	return payload[start : start+int(v.Length)], nil
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
