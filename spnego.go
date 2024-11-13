package spnego

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"strconv"
)

// SPNEGO OID as defined in RFC 4178 and MS-SPNG
var SpnegoOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}

// Built-in authentication mechanism OIDs
var (
	MsKerberosOid = asn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}
	KerberosOID   = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
	NegotiateOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 30}
)

// "not_defined_in_RFC4178@please_ignore"
var NegHints = asn1.RawValue{
	FullBytes: []byte{
		0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x64, 0x5f,
		0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38, 0x40, 0x70, 0x6c, 0x65, 0x61, 0x73,
		0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65,
	},
}

type Initiator interface {
	GetOID() asn1.ObjectIdentifier
	InitSecContext() ([]byte, error)            // GSS_Init_sec_context
	AcceptSecContext(sc []byte) ([]byte, error) // GSS_Accept_sec_context
	GetMIC(bs []byte) []byte                    // GSS_getMIC
	SessionKey() []byte                         // QueryContextAttributes(ctx, SECPKG_ATTR_SESSION_KEY, &out)
}

// NegTokenInit represents the initial negotiation token
type NegTokenInit struct {
	MechTypes   []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags    asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechToken   []byte                  `asn1:"explicit,optional,tag:2"`
	MechListMIC []byte                  `asn1:"explicit,optional,tag:3"`
}

// NegTokenInit2 is the useless extension to the NegTokenInit made by MS
type NegTokenInit2 struct {
	MechTypes   []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags    asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechToken   []byte                  `asn1:"explicit,optional,tag:2"`
	NegHints    asn1.RawValue           `asn1:"explicit,optional,tag:3"` // will always be NegHints
	MechListMIC []byte                  `asn1:"explicit,optional,tag:4"`
}

func EncodeNegTokenInitGeneric(token interface{}) ([]byte, error) {
	type initialCtxToken struct { // `asn1:"application,tag:0"`
		ThisMech asn1.ObjectIdentifier `asn1:"optional"`
		Init     []interface{}         `asn1:"optional,explict,tag:0"`
		Resp     []NegTokenResp        `asn1:"optional,explict,tag:1"`
	}

	bs, err := asn1.Marshal(initialCtxToken{
		ThisMech: SpnegoOID,
		Init:     []interface{}{token},
	})
	if err != nil {
		return nil, err
	}

	bs[0] = 0x60 // `asn1:"application,tag:0"`
	return bs, nil
}

func EncodeNegTokenInit(types []asn1.ObjectIdentifier, token []byte) ([]byte, error) {
	return EncodeNegTokenInitGeneric(NegTokenInit{
		MechTypes: types,
		MechToken: token,
	})
}

func EncodeNegTokenInit2(types []asn1.ObjectIdentifier) ([]byte, error) {
	return EncodeNegTokenInitGeneric(NegTokenInit2{
		MechTypes: types,
		NegHints:  NegHints, // Include the predefined NegHints
	})
}

// NegTokenResp represents all subsequent negotiation messages
type NegTokenResp struct {
	NegState      asn1.Enumerated       `asn1:"explicit,optional,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,tag:1"`
	ResponseToken []byte                `asn1:"explicit,optional,tag:2"`
	MechListMIC   []byte                `asn1:"explicit,optional,tag:3"`
}

func EncodeNegTokenResp(token NegTokenResp) ([]byte, error) {
	data, err := asn1.Marshal(token)
	if err != nil {
		return nil, errors.New("failed to marshal NegTokenResp: " + err.Error())
	}

	// Skip GSS-API framing
	skip := 1
	if data[skip] > 128 {
		skip += int(data[skip]) - 128
	}
	return data[skip+1:], nil
}

func DecodeNegTokenResp(data []byte) (*NegTokenResp, error) {
	var resp *NegTokenResp
	if _, err := asn1.Unmarshal(data, &resp); err != nil {
		// MS-SPNG 3.1: Handle potential raw token without ASN.1 wrapper
		if len(data) > 0 {
			return resp, nil
		}
		return nil, err
	}
	return resp, nil
}

// NegotiationState values as defined in RFC 4178
const (
	AcceptCompleted  = 0
	AcceptIncomplete = 1
	Reject           = 2
	RequestMIC       = 3
)

// SPNEGOClient handles SPNEGO negotiation
type SPNEGOClient struct {
	Mechanisms   []Initiator
	MechTypes    []asn1.ObjectIdentifier
	SelectedMech Initiator
}

// NewSPNEGOClient creates a new SPNEGO client with the given mechanisms
func NewSPNEGOClient(mechs []Initiator) *SPNEGOClient {
	mechTypes := make([]asn1.ObjectIdentifier, len(mechs))
	for i, mech := range mechs {
		mechTypes[i] = mech.GetOID()
	}
	return &SPNEGOClient{
		Mechanisms: mechs,
		MechTypes:  mechTypes,
	}
}

func (c *SPNEGOClient) GetOID() asn1.ObjectIdentifier {
	return SpnegoOID
}

// InitSecContext generates the initial negotiation token
func (c *SPNEGOClient) InitSecContext() ([]byte, error) {
	if len(c.Mechanisms) == 0 {
		return nil, errors.New("no mechanisms available")
	}

	mechToken, err := c.Mechanisms[0].InitSecContext()
	if err != nil {
		return nil, errors.New("failed to initialize security context: " + err.Error())
	}

	return EncodeNegTokenInit(c.MechTypes, mechToken)
}

// AcceptSecContext handles the response token from the acceptor
func (c *SPNEGOClient) AcceptSecContext(responseToken []byte) ([]byte, error) {
	resp, err := DecodeNegTokenResp(responseToken)
	if err != nil {
		return nil, err
	}

	switch resp.NegState {
	case AcceptCompleted:
		// MS-SPNG 3.1: Handle both wrapped and unwrapped tokens
		if len(resp.ResponseToken) > 0 {
			return resp.ResponseToken, nil
		}
		return nil, nil
	case Reject:
		// MS-SPNG 2.2.1: Include more specific error info if available
		if len(resp.ResponseToken) > 0 {
			return nil, errors.New("negotiation rejected with token: " + hex.EncodeToString(resp.ResponseToken))
		}
		return nil, errors.New("negotiation rejected by acceptor")

	case AcceptIncomplete, RequestMIC:
		// Continue negotiation (if received AcceptIncomplete, we need to send another response token)
		// As stated in RFC 4178 Section 3.1, the initiator, upon receiving an AcceptIncomplete
		// state from the acceptor, can OPTIONALLY send a MIC in the next response token.
		// So, to generalize, we always send a MIC in the response token

	default:
		return nil, errors.New("unknown negState: " + strconv.Itoa(int(resp.NegState)))
	}

	for i, mechType := range c.MechTypes {
		if mechType.Equal(resp.SupportedMech) {
			c.SelectedMech = c.Mechanisms[i]
			break
		}
	}

	initiatorResponse, err := c.SelectedMech.AcceptSecContext(resp.ResponseToken)
	if err != nil {
		return nil, errors.New("failed to accept security context: " + err.Error())
	}

	supportedMICs, err := asn1.Marshal(c.MechTypes)
	if err != nil {
		return nil, errors.New("failed to marshal supported mechanisms: " + err.Error())
	}
	mechListMIC := c.SelectedMech.GetMIC(supportedMICs)

	return EncodeNegTokenResp(NegTokenResp{
		NegState:      resp.NegState,
		SupportedMech: resp.SupportedMech,
		ResponseToken: initiatorResponse,
		MechListMIC:   mechListMIC,
	})
}
