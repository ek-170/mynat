package stun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

type Attributes []Attribute

type AttributeType uint16

const (
	// Comprehension-required range (0x0000-0x7FFF):
	// 0x0000: AttrReserved
	AttrReserved AttributeType = 0x0000
	// 0x0001: MAPPED-ADDRESS
	AttrMappedAddress AttributeType = 0x0001
	// 0x0002: Reserved; was RESPONSE-ADDRESS prior to [RFC5389]
	AttrResponseAddress AttributeType = 0x002
	// 0x0003: Reserved; was CHANGE-REQUEST prior to [RFC5389]
	AttrCahngeRequest AttributeType = 0x0003
	// 0x0004: Reserved; was SOURCE-ADDRESS prior to [RFC5389]
	AttrSourceAddress AttributeType = 0x0004
	// 0x0005: Reserved; was CHANGED-ADDRESS prior to [RFC5389]
	AttrChangedAddress AttributeType = 0x0005
	// 0x0006: USERNAME
	AttrUsername AttributeType = 0x0006
	// 0x0007: Reserved; was PASSWORD prior to [RFC5389]
	AttrPassword AttributeType = 0x0007
	// 0x0008: MESSAGE-INTEGRITY
	AttrMessageIntegrity AttributeType = 0x0008
	// 0x0009: ERROR-CODE
	AttrErrorCode AttributeType = 0x0009
	// 0x000A: UNKNOWN-ATTRIBUTES
	AttrUnknownAttributes AttributeType = 0x000A
	// 0x000B: Reserved; was REFLECTED-FROM prior to [RFC5389]
	AttrReflectedFrom AttributeType = 0x000B
	// 0x0014: REALM
	AttrRealm AttributeType = 0x0014
	// 0x0015: NONCE
	AttrNonce AttributeType = 0x0015
	// 0x0020: XOR-MAPPED-ADDRESS
	AttrXorMappedAddress AttributeType = 0x0020
)

var attrTypes map[AttributeType]string = map[AttributeType]string{
	AttrReserved:          "Reserved",
	AttrMappedAddress:     "MAPPED-ADDRESS",
	AttrResponseAddress:   "RESPONSE-ADDRESS",
	AttrCahngeRequest:     "CHANGE-REQUEST",
	AttrSourceAddress:     "SOURCE-ADDRESS",
	AttrChangedAddress:    "CHANGED-ADDRESS",
	AttrUsername:          "USERNAME",
	AttrPassword:          "PASSWORD",
	AttrMessageIntegrity:  "MESSAGE-INTEGRITY",
	AttrErrorCode:         "ERROR-CODE",
	AttrUnknownAttributes: "UNKNOWN-ATTRIBUTES",
	AttrReflectedFrom:     "REFLECTED-FROM",
	AttrRealm:             "REALM",
	AttrNonce:             "NONCE",
	AttrXorMappedAddress:  "XOR-MAPPED-ADDRESS",
}

type TypedValue interface {
	Parse(attr Attribute) error
}

// MUST end on a 32-bit boundary
type Attribute struct {

	// 	0                   1                   2                   3
	// 	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |         Type                  |            Length             |
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |                         Value (variable)                ....
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	Type   AttributeType
	Length uint16 // except padding bytes
	Value  []byte
}

func (atts Attributes) Add(t AttributeType, v []byte) {
	a := Attribute{
		Type:   t,
		Length: uint16(len(v)),
		Value:  v,
	}
	atts = append(atts, a)
}

func (atts Attributes) Extract(attrType AttributeType) (attr Attribute, exist bool) {
	if len(atts) > 0 {
		for _, v := range atts {
			if attrType == v.Type {
				return v, true
			}
		}
	}
	return Attribute{}, false
}

const (
	ipv4 = 0x01
	ipv6 = 0x02
)

type MappedAddress struct {

	// 	0                   1                   2                   3
	// 	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |0 0 0 0 0 0 0 0|    Family     |           Port                |
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |                                                               |
	//  |                 Address (32 bits or 128 bits)                 |
	//  |                                                               |
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	Family  uint8
	Address netip.Addr
	Port    uint16
}

func (ma MappedAddress) Parse(attr Attribute) error {
	if attr.Type != AttrMappedAddress {
		return errors.New("type is not MAPPED-ADDRESS")
	}
	index := 1 // except Reserved area
	ma.Family = attr.Value[index]
	fmt.Printf("MAPPED-ADDRESS Family: %X\n", ma.Family)
	index++

	xport := binary.BigEndian.Uint16(attr.Value[index : index+2])
	mc16 := uint16(MagicCookie >> 16)
	ma.Port = xport ^ mc16
	fmt.Printf("MAPPED-ADDRESS Port: %d\n", ma.Port)
	index += 2

	if ma.Family == ipv4 {
		ma.Address = netip.AddrFrom4(([4]byte)(attr.Value[index : index+4]))
		fmt.Printf("MAPPED-ADDRESS Address(ipv4): %s\n", ma.Address.String())
	} else {
		// ipv6
		ma.Address = netip.AddrFrom16(([16]byte)(attr.Value[index : index+16]))
		fmt.Printf("MAPPED-ADDRESS Address(ipv6): %s\n", ma.Address.String())
	}

	return nil
}

type XORMappedAddress struct {

	// 	0                   1                   2                   3
	// 	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |0 0 0 0 0 0 0 0|    Family     |         X-Port                |
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |                X-Address (Variable)
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	Family  uint8
	Address net.IP
	Port    uint16
}

func (xa *XORMappedAddress) Parse(attr Attribute, tid TransactionID) error {
	if attr.Type != AttrXorMappedAddress {
		return errors.New("type is not XOR-MAPPED-ADDRESS")
	}
	index := 1 // except Reserved area
	xa.Family = attr.Value[index]
	fmt.Printf("XOR-MAPPED-ADDRESS Family: %X\n", xa.Family)
	index++

	xport := binary.BigEndian.Uint16(attr.Value[index : index+2])
	mc16 := uint16(MagicCookie >> 16)
	xa.Port = xport ^ mc16
	fmt.Printf("XOR-MAPPED-ADDRESS Port: %d\n", xa.Port)
	index += 2

	if xa.Family == ipv4 {
		xaddr := binary.BigEndian.Uint32(attr.Value[index : index+4])
		xaddr ^= MagicCookie
		var addr [4]byte
		binary.BigEndian.PutUint32(addr[:], xaddr)
		xa.Address = net.IP(addr[:])
		fmt.Printf("XOR-MAPPED-ADDRESS Address(ipv4): %s\n", xa.Address.String())
	} else {
		// ipv6
		var comparison [16]byte
		binary.BigEndian.PutUint32(comparison[:4], MagicCookie)
		copy(comparison[4:], tid[:])

		xaddr := ([16]byte)(attr.Value[index : index+16])
		addr := xor128(xaddr, comparison)
		xa.Address = net.IP(addr[:])
		fmt.Printf("XOR-MAPPED-ADDRESS Address(ipv6): %s\n", xa.Address.String())
	}

	return nil
}

// xor128 performs XOR operation on two 128-bit values represented as [16]byte
func xor128(a, b [16]byte) [16]byte {
	var result [16]byte
	for i := 0; i < 16; i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}
