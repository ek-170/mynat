package stun

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
)

const (
	HeaderByte               = 20
	TransactionIDByte        = 12
	AttrBoundaryByte         = 4
	MagicCookie       uint32 = 0x2112A442
)

const (

	// STUN Message type
	//
	// 	0                 1
	// 	2  3  4 5 6 7 8 9 0 1 2 3 4 5
	//  +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
	//  |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
	//  +--+--+-+-+-+-+-+-+-+-+-+-+-+-+

	BindingReq uint16 = 0x0001
	BindingRes uint16 = 0x0101
)

// RFC8489
type Message struct {

	// 	0                   1                   2                   3
	// 	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |0 0|     STUN Message Type     |         Message Length        |
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |                         Magic Cookie                          |
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |                                                               |
	//  |                     Transaction ID (96 bits)                  |
	//  |                                                               |
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	Type          uint16                  // 2bit: 00, 14bit: Type
	Length        uint16                  // Message Lengh except Header
	Cookie        uint32                  // must be fixed value: 0x2112A442
	TransactionID [TransactionIDByte]byte // created by crypto/rand
	Attributes    Attributes
}

type Attributes []Attribute

// MUST end on a 32-bit boundary
type Attribute struct {

	// 	0                   1                   2                   3
	// 	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |         Type                  |            Length             |
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |                         Value (variable)                ....
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	Type   uint16
	Length uint16 // except padding bytes
	Value  []byte
}

const (
	// Comprehension-required range (0x0000-0x7FFF):
	// 0x0000: Reserved
	reserved uint16 = 0x0000
	// 0x0001: MAPPED-ADDRESS
	mappedAddress uint16 = 0x0001
	// 0x0002: Reserved; was RESPONSE-ADDRESS prior to [RFC5389]
	responseAddress uint16 = 0x002
	// 0x0003: Reserved; was CHANGE-REQUEST prior to [RFC5389]
	cahngeRequest uint16 = 0x0003
	// 0x0004: Reserved; was SOURCE-ADDRESS prior to [RFC5389]
	sourceAddress uint16 = 0x0004
	// 0x0005: Reserved; was CHANGED-ADDRESS prior to [RFC5389]
	changedAddress uint16 = 0x0005
	// 0x0006: USERNAME
	username uint16 = 0x0006
	// 0x0007: Reserved; was PASSWORD prior to [RFC5389]
	password uint16 = 0x0007
	// 0x0008: MESSAGE-INTEGRITY
	messageIntegrity uint16 = 0x0008
	// 0x0009: ERROR-CODE
	errorCode uint16 = 0x0009
	// 0x000A: UNKNOWN-ATTRIBUTES
	unknownAttributes uint16 = 0x000A
	// 0x000B: Reserved; was REFLECTED-FROM prior to [RFC5389]
	reflectedFrom uint16 = 0x000B
	// 0x0014: REALM
	realm uint16 = 0x0014
	// 0x0015: NONCE
	nonce uint16 = 0x0015
	// 0x0020: XOR-MAPPED-ADDRESS
	xorMappedAddress uint16 = 0x0020
)

var attrTypes map[uint16]string = map[uint16]string{
	reserved:          "Reserved",
	mappedAddress:     "MAPPED-ADDRESS",
	responseAddress:   "RESPONSE-ADDRESS",
	cahngeRequest:     "CHANGE-REQUEST",
	sourceAddress:     "SOURCE-ADDRESS",
	changedAddress:    "CHANGED-ADDRESS",
	username:          "USERNAME",
	password:          "PASSWORD",
	messageIntegrity:  "MESSAGE-INTEGRITY",
	errorCode:         "ERROR-CODE",
	unknownAttributes: "UNKNOWN-ATTRIBUTES",
	reflectedFrom:     "REFLECTED-FROM",
	realm:             "REALM",
	nonce:             "NONCE",
	xorMappedAddress:  "XOR-MAPPED-ADDRESS",
}

func extractAttr(a Attributes, attrType uint16) (Attribute, bool) {
	if len(a) > 0 {
		for _, v := range a {
			if attrType == v.Type {
				return v, true
			}
		}
	}
	return Attribute{}, false
}

// Encode encodes a STUN message into binary format.
func (m *Message) Encode() ([]byte, error) {
	fmt.Println("-- encode --")
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, m.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, m.Length); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, m.Cookie); err != nil {
		return nil, err
	}
	if _, err := buf.Write(m.TransactionID[:]); err != nil {
		return nil, err
	}

	for _, attr := range m.Attributes {
		if err := binary.Write(buf, binary.BigEndian, attr.Type); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, attr.Length); err != nil {
			return nil, err
		}
		if _, err := buf.Write(attr.Value); err != nil {
			return nil, err
		}
	}
	fmt.Println(hex.Dump(buf.Bytes()))

	return buf.Bytes(), nil
}

func (m *Message) Decode(data []byte) error {
	fmt.Println("-- decode --")
	if len(data) < HeaderByte {
		return errors.New("header size is too short")
	}
	fmt.Println(hex.Dump(data[:HeaderByte]))

	mtype := data[:2]
	fmt.Println("message type")
	fmt.Println(hex.Dump(mtype))
	m.Type = binary.BigEndian.Uint16(mtype)

	mlen := data[2:4]
	m.Length = binary.BigEndian.Uint16(mlen)
	fmt.Printf("Message length: %d\n", m.Length)
	fmt.Println(hex.Dump(mlen))

	cookie := data[4:8]
	fmt.Println("magic cookie")
	fmt.Println(hex.Dump(cookie))
	m.Cookie = binary.BigEndian.Uint32(cookie)

	tid := [TransactionIDByte]byte{}
	for i := 0; i < TransactionIDByte; i++ {
		tid[i] = data[i+8]
	}
	fmt.Println("transaction id")
	fmt.Println(hex.Dump(tid[:]))
	m.TransactionID = tid

	// Attribnutesのデコード
	// 重複して属性タイプが表示された場合は最初の値のみ有効
	if m.Length > 0 {
		attrs := make(Attributes, 1)
		index := 0
		attrsByte := data[HeaderByte:]
		dup := make(map[uint16]bool, 1)
		for index < int(m.Length) {
			attr := Attribute{}

			aType := binary.BigEndian.Uint16(attrsByte[index : index+2])
			attr.Type = aType
			fmt.Printf("Attribute type: %s\n", attrTypes[attr.Type])
			fmt.Println(hex.Dump(attrsByte[index : index+2]))
			index += 2
			// TODO
			// type values between 0x0000 and 0x7FFF are comprehension-required
			// type values between 0x8000 and 0xFFFF are comprehension-optional

			aLen := binary.BigEndian.Uint16(attrsByte[index : index+2])
			attr.Length = aLen
			fmt.Printf("Attribute len: %d\n", attr.Length)
			fmt.Println(hex.Dump(attrsByte[index : index+2]))
			pad := 0
			if aLen%AttrBoundaryByte != 0 {
				pad = int(AttrBoundaryByte - (aLen % AttrBoundaryByte))
				fmt.Printf("Attribute padding: %d\n", pad)
			}
			index += 2

			val := attrsByte[index : index+int(aLen)]
			attr.Value = val
			fmt.Println("Attribute value")
			fmt.Println(hex.Dump(val))
			index += (int(aLen) + pad)

			if _, ok := dup[attr.Type]; ok {
				fmt.Printf("Attribute type %s has already parsed", attrTypes[attr.Type])
				continue
			}

			dup[aType] = true

			attrs = append(attrs, attr)
		}

		m.Attributes = attrs
	} else {
		m.Attributes = make(Attributes, 0)
	}

	return nil
}

func (m *Message) ExtractXORMappedAddress() (XORMappedAddress, bool) {
	xadd := XORMappedAddress{}
	attr, ok := extractAttr(m.Attributes, xorMappedAddress)
	if !ok {
		return xadd, false
	}
	if err := xadd.parse(attr); err != nil {
		return xadd, false
	}
	return xadd, true
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
	Address netip.Addr
	Port    uint16
}

const (
	ipv4 = 0x01
	ipv6 = 0x02
)

func (xa XORMappedAddress) parse(attr Attribute) error {
	if attr.Type != xorMappedAddress {
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
		var bytes [4]byte
		binary.BigEndian.PutUint32(bytes[:], xaddr)
		xa.Address = netip.AddrFrom4(bytes)
		fmt.Printf("XOR-MAPPED-ADDRESS Address(ipv4): %s\n", xa.Address.String())
	} else {
		// TODO ipv6
	}

	return nil
}
