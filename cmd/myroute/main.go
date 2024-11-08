package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
)

var (
	magicCookie uint32 = 0x2112A442

	// STUN msg type
	//
	// 	0                 1
	// 	2  3  4 5 6 7 8 9 0 1 2 3 4 5
	//  +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
	//  |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
	//  +--+--+-+-+-+-+-+-+-+-+-+-+-+-+

	bindingReq uint16 = 0x0001
	bindingRes uint16 = 0x0101
)

const (
	headerSize        = 20 // byte
	transactionIdSize = 12 // byte
	dest              = "stun:stun.l.google.com"
	destIPv4          = "74.125.250.129:19302"
	destIPv6          = "240f:7f:106e:1:c807:9559:46aa:3d10:19302"
)

func main() {
	slog.Info("start")
	tid := [transactionIdSize]byte{}
	rand.Read(tid[:])

	reqMsg := Message{
		Type:          bindingReq,
		Length:        0,
		Cookie:        magicCookie,
		TransactionID: tid,
	}

	conn, err := net.Dial("udp", destIPv4)
	if err != nil {
		panic(fmt.Sprintf("udp dial for %s failed", destIPv4))
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			panic("closing udp conn failed")
		}
	}()

	req, err := reqMsg.Encode()
	if err != nil {
		fmt.Println(err)
		panic("binary encoding failed")
	}

	_, err = conn.Write(req)
	if err != nil {
		panic("STUN request failed")
	}

	res := make([]byte, 1500)
	_, err = conn.Read(res)
	if err != nil {
		panic("STUN response reading failed")
	}
	resMsg := Message{}
	// binary.Decode(b2, binary.BigEndian, &resMsg)
	err = resMsg.Decode(res)
	if err != nil {
		panic(err)
	}
	fmt.Println(resMsg)
}

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
	TransactionID [transactionIDByte]byte // created by crypto/rand
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

const (
	headerByte        = 20
	transactionIDByte = 12
	attrBoundaryByte  = 4
)

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
	if len(data) < headerByte {
		return errors.New("header size is too short")
	}
	fmt.Println(hex.Dump(data))

	mtype := data[:2]
	fmt.Println("message type")
	fmt.Println(hex.Dump(mtype))
	m.Type = binary.BigEndian.Uint16(mtype)

	mlen := data[2:4]
	fmt.Println("message length")
	fmt.Println(hex.Dump(mlen))
	m.Length = binary.BigEndian.Uint16(mlen)

	cookie := data[4:8]
	fmt.Println("magic cookie")
	fmt.Println(hex.Dump(cookie))
	m.Cookie = binary.BigEndian.Uint32(cookie)

	tid := [transactionIDByte]byte{}
	for i := 0; i < transactionIDByte; i++ {
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
		attrsByte := data[headerByte:]
		for index < int(m.Length) {
			attr := Attribute{}

			aType := binary.BigEndian.Uint16(attrsByte[index : index+2])
			index += 2
			attr.Type = aType
			fmt.Println("attr type")
			fmt.Println(hex.Dump(attrsByte[index : index+2]))
			// TODO
			// type values between 0x0000 and 0x7FFF are comprehension-required
			// type values between 0x8000 and 0xFFFF are comprehension-optional

			aLen := binary.BigEndian.Uint16(attrsByte[index : index+2])
			index += 2
			attr.Length = aLen
			fmt.Println("attr len")
			fmt.Printf("aLen: %d\n", aLen)
			fmt.Println(hex.Dump(attrsByte[index : index+2]))
			pad := 0
			if aLen%attrBoundaryByte != 0 {
				pad = int(attrBoundaryByte - (aLen % attrBoundaryByte))
				fmt.Printf("attr padding: %d\n", pad)
			}

			val := attrsByte[index : index+int(aLen)]
			index += (int(aLen) + pad)
			attr.Value = val
			fmt.Println("attr value")
			fmt.Println(hex.Dump(val))

			attrs = append(attrs, attr)
		}

		m.Attributes = attrs
	}

	return nil
}

func (m *Message) getAttr() {

}

func (attrs *Attributes) includeTypes(types ...uint16) error {

}
