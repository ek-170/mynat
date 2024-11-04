package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
)

var (
	cookie uint32 = 0x2112A442

	// STUN msg type
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
		Cookie:        cookie,
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
	fmt.Println(hex.Dump(req))

	_, err = conn.Write(req)
	if err != nil {
		panic("STUN request failed")
	}

	res := make([]byte, 74)
	_, err = conn.Read(res)
	if err != nil {
		panic("STUN response reading failed")
	}
	fmt.Println(hex.Dump(res))
	resMsg := Message{}
	// binary.Decode(b2, binary.BigEndian, &resMsg)
	err = resMsg.Decode(res)
	if err != nil {
		panic("STUN response decoding failed")
	}
	fmt.Println(resMsg)
}

// RFC8489
type Message struct {
	Type          uint16   // 2bit: 00, 14bit: Type
	Length        uint16   // Message Lengh except Header
	Cookie        uint32   // must be fixed value: 0x2112A442
	TransactionID [12]byte // created by crypto/rand
	Attributes    Attributes
}

type Attributes []Attribute

// MUST end on a 32-bit boundary
type Attribute struct {
	Type   uint16
	Length uint16 // except padding bytes
	Value  []byte
}

// Encode encodes a STUN message into binary format.
func (m *Message) Encode() ([]byte, error) {
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

	return buf.Bytes(), nil
}

func (m *Message) Decode(data []byte) error {
	// ヘッダのデコード

	// Attribnutesのデコード

	return nil
}
