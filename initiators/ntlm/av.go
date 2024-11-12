package ntlm

import (
	"encoding/binary"
	"fmt"
)

type AvID uint16

const (
	AvIDMsvAvEOL AvID = iota
	AvIDMsvAvNbComputerName
	AvIDMsvAvNbDomainName
	AvIDMsvAvDNSComputerName
	AvIDMsvAvDNSDomainName
	AvIDMsvAvDNSTreeName
	AvIDMsvAvFlags
	AvIDMsvAvTimestamp
	AvIDMsvAvSingleHost
	AvIDMsvAvTargetName
	AvIDMsvChannelBindings
)

type AvPairs map[AvID][]byte

func NewAvPairs(b []byte) (AvPairs, error) {
	//        AvPair
	//   0-2: AvId
	//   2-4: AvLen
	//    4-: Value
	if len(b) < 4 {
		return nil, fmt.Errorf("no av pair to parse")
	}

	m := make(AvPairs)
	for i := 0; i < len(b); {
		// Read AvID
		id := AvID(binary.LittleEndian.Uint16(b[i : i+2]))

		// If EOL return
		if id == AvIDMsvAvEOL {
			// Checking if the standard is followed as some fields MUST be present in the AV pairs
			// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
			_, ok1 := m[AvIDMsvAvNbComputerName]
			_, ok2 := m[AvIDMsvAvNbDomainName]
			if !ok1 || !ok2 {
				return m, fmt.Errorf("target info received is corrupted, this should not happen")
			}
			return m, nil
		}

		// Read value size and check that it is not OOB
		sz := binary.LittleEndian.Uint16(b[i+2 : i+4])
		if len(b) < i+4+int(sz) {
			return nil, fmt.Errorf("corrupted data - refusing to go out of bounds")
		}

		m[id] = b[i+4 : i+4+int(sz)]
		i = i + 4 + int(sz)
	}
	return nil, fmt.Errorf("never reached AvId == AvIDMsvAvEOL")
}

func (a AvPairs) Bytes() []byte {
	var buf []byte
	for k, v := range a {
		if k == AvIDMsvAvEOL {
			continue
		}
		binary.LittleEndian.PutUint16(buf[0:2], uint16(k))
		binary.LittleEndian.PutUint16(buf[2:4], uint16(len(v)))
		buf = append(buf, v...)
	}
	binary.LittleEndian.PutUint16(buf[0:2], uint16(AvIDMsvAvEOL))
	binary.LittleEndian.PutUint16(buf[2:4], 0)
	return buf
}

type SingleHost struct {
	Size       uint32
	Z4         uint32
	CustomData uint8
	MachineID  [32]byte
}

func NewSingleHost(v []byte) SingleHost {
	var sh SingleHost
	sh.Size = binary.LittleEndian.Uint32(v[0:4])
	sh.Z4 = binary.LittleEndian.Uint32(v[4:8])
	sh.CustomData = v[8]
	copy(sh.MachineID[:], v[9:])
	return sh
}

// ChannelBindings represents the NTLM Channel Binding structure
// as defined in [MS-NLMP]. Either MD5Hash or gss_channel_bindings_struct
type ChannelBindings struct {
	MD5Hash [16]byte

	InitiatorAddrType uint32
	InitiatorAddr     []byte
	AcceptorAddrType  uint32
	AcceptorAddr      []byte
	ApplicationData   []byte
}

func NewChannelBindings(v []byte) (ChannelBindings, error) {
	var cb ChannelBindings

	if len(v) < 12 { // Minimum size for addr types and empty addresses
		return cb, fmt.Errorf("channel bindings data too short")
	}

	if len(v) == 16 {
		copy(cb.MD5Hash[:], v)
		return cb, nil
	}

	offset := 0

	// Read initiator address info
	cb.InitiatorAddrType = binary.LittleEndian.Uint32(v[offset:])
	offset += 4
	initAddrLen := binary.LittleEndian.Uint32(v[offset:])
	offset += 4
	if initAddrLen > 0 {
		cb.InitiatorAddr = make([]byte, initAddrLen)
		copy(cb.InitiatorAddr, v[offset:offset+int(initAddrLen)])
		offset += int(initAddrLen)
	}

	// Read acceptor address info
	cb.AcceptorAddrType = binary.LittleEndian.Uint32(v[offset:])
	offset += 4
	acceptAddrLen := binary.LittleEndian.Uint32(v[offset:])
	offset += 4
	if acceptAddrLen > 0 {
		cb.AcceptorAddr = make([]byte, acceptAddrLen)
		copy(cb.AcceptorAddr, v[offset:offset+int(acceptAddrLen)])
		offset += int(acceptAddrLen)
	}

	// Read application data
	if offset < len(v) {
		cb.ApplicationData = make([]byte, len(v)-offset)
		copy(cb.ApplicationData, v[offset:])
	}

	return cb, nil
}

type TargetInformation struct {
	NbComputerName  string
	NbDomainName    string
	DNSComputerName string
	DNSDomainName   string
	DNSTreeName     string
	Flags           uint32
	Timestamp       uint64
	Host            SingleHost
	TargetName      string
	ChBindings      ChannelBindings

	// Metadata
	AvPairsSize  int
	AvPairs      AvPairs
	AvPairsBytes []byte
}

func NewTargetInformation(pairs AvPairs) (*TargetInformation, error) {
	var info TargetInformation
	for k, v := range pairs {
		if err := info.Set(k, v); err != nil {
			return nil, err
		}
	}
	info.AvPairsSize = len(info.AvPairsBytes)
	info.AvPairs = pairs
	info.AvPairsBytes = pairs.Bytes()
	return &info, nil
}

func (t *TargetInformation) Set(k AvID, v []byte) (err error) {
	switch k {
	case AvIDMsvAvNbComputerName:
		t.NbComputerName = toString(v)
	case AvIDMsvAvNbDomainName:
		t.NbDomainName = toString(v)
	case AvIDMsvAvDNSComputerName:
		t.DNSComputerName = toString(v)
	case AvIDMsvAvDNSDomainName:
		t.DNSDomainName = toString(v)
	case AvIDMsvAvDNSTreeName:
		t.DNSTreeName = toString(v)
	case AvIDMsvAvFlags:
		t.Flags = binary.LittleEndian.Uint32(v)
	case AvIDMsvAvTimestamp:
		t.Timestamp = binary.LittleEndian.Uint64(v)
	case AvIDMsvAvSingleHost:
		t.Host = NewSingleHost(v)
	case AvIDMsvAvTargetName:
		t.TargetName = toString(v)
	case AvIDMsvChannelBindings:
		t.ChBindings, err = NewChannelBindings(v)
	}
	return err
}
