package stun

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/ek-170/myroute/pkg/logger"
)

var (
	errInvalidPortRange error = errors.New("invalid port range")
	errNotSTUNURIScheme error = errors.New("not STUN URI scheme")
)

const (
	DefaultPort = "3478"

	HeaderByte               = 20
	TransactionIDByte        = 12
	AttrBoundaryByte         = 4
	MagicCookie       uint32 = 0x2112A442
)

type (
	STUNRequest   uint16
	TransactionID [TransactionIDByte]byte
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

	BindingReq STUNRequest = 0x0001
	BindingRes STUNRequest = 0x0101
)

// Message represents STUN message
// see more detail: https://tex2e.github.io/rfc-translater/html/rfc8489.html#5--STUN-Message-Structure
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

	Type          STUNRequest   // 2bit: 00, 14bit: Type
	Length        uint16        // Message Lengh except Header
	Cookie        uint32        // must be fixed value: 0x2112A442
	TransactionID TransactionID // created by crypto/rand
	Attributes    Attributes
}

func NewMessage(req STUNRequest) *Message {
	tid := TransactionID{}
	rand.Read(tid[:])
	return &Message{
		Type:          req,
		Length:        0,
		Cookie:        MagicCookie,
		TransactionID: tid,
		Attributes:    make(Attributes, 0),
	}
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
		if attr.Length%AttrBoundaryByte != 0 {
			// add padding for align 4 bytes order
			padBytes := int(AttrBoundaryByte - (attr.Length % AttrBoundaryByte))
			pad := make([]byte, padBytes)
			attr.Value = append(attr.Value, pad...)
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
	m.Type = STUNRequest(binary.BigEndian.Uint16(mtype))

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
	fmt.Println("Transaction ID")
	fmt.Println(hex.Dump(tid[:]))
	m.TransactionID = tid

	// decode Attribnutes
	// if duplicate attribute types are displayed, only the first value is valid
	if m.Length > 0 {
		attrs := make(Attributes, 1)
		index := 0
		attrsByte := data[HeaderByte:]
		dup := make(map[AttributeType]bool, 1)
		for index < int(m.Length) {
			attr := Attribute{}

			aType := AttributeType(binary.BigEndian.Uint16(attrsByte[index : index+2]))
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

// ParseSTUNURL parses a string URL and returns a url.URL object
// If the scheme is not stun or stuns, it returns an error
// If no port is specified, it assigns the default STUN port 3478
// expected URL format is "stun(s):host:port", "stun(s):host", host:port, host
func ParseSTUNURL(rawURL string) (*url.URL, error) {
	url := new(url.URL)
	first := strings.Index(rawURL, ":")
	last := strings.LastIndex(rawURL, ":")

	if first == -1 {
		// treat as only including host
		url.Scheme = "stun"
		url.Host = fmt.Sprintf("%s:%s", rawURL, DefaultPort)
		return url, nil
	}

	if first == last {
		// treat as scheme:host or host:port
		maybePort := rawURL[first+1:]
		if err := validatePort(maybePort); err != nil {
			logger.Warn(err.Error())
			if errors.Is(err, errInvalidPortRange) {
				// host:port, but invalid port range
				return nil, err
			}
			// scheme:host
			scheme := rawURL[:first]
			if !isSTUNScheme(scheme) {
				return nil, errNotSTUNURIScheme
			}
			url.Scheme = scheme
			url.Host = rawURL[first+1:]
		} else {
			url.Scheme = "stun"
			url.Host = rawURL
		}
		return url, nil
	}

	if first < last {
		// treat as scheme:host:port
		scheme := rawURL[:first]
		if !isSTUNScheme(scheme) {
			return nil, errNotSTUNURIScheme
		}
		url.Scheme = scheme
		url.Host = rawURL[first+1:]
	}

	return url, nil
}

func validatePort(port string) error {
	p, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	if p < 1 || p > 65535 {
		return fmt.Errorf("validation failed: %w", errInvalidPortRange)
	}
	return nil
}

func isSTUNScheme(scheme string) bool {
	return scheme == "stun" || scheme == "stuns"
}
