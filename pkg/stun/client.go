package stun

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

const (
	defaultMaxRetry = 3
	defaultTimeout  = 5 * time.Second
)

type Client struct {
	conn     net.Conn
	maxRetry uint8
	timeout  time.Duration
}

func NewClient(addr string, port uint16, opts ...ClientOption) (Client, error) {
	const network = "udp"

	// TODO add DNS
	// if addr == domain {
	// 	translate addr to ip
	// }

	ipAddr, err := netip.ParseAddr(addr)
	if err != nil {
		return Client{}, err
	}
	conn, err := net.Dial(network, fmt.Sprintf("%s:%d", ipAddr, port))
	if err != nil {
		return Client{}, err
	}
	c := Client{
		conn:     conn,
		maxRetry: defaultMaxRetry,
		timeout:  defaultTimeout,
	}
	if len(opts) > 0 {
		for _, o := range opts {
			o(&c)
		}
	}
	return c, nil
}

type ClientOption func(c *Client)

func WithMaxRetry(maxRetry uint8) ClientOption {
	return func(c *Client) {
		c.maxRetry = maxRetry
	}
}

func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = timeout
	}
}

// Do send STUN request, and wait for recieving response
func (c Client) Do(msg Message) (Message, error) {
	req, err := msg.Encode()
	if err != nil {
		return Message{}, err
	}

	writeRetry := 0
	for {
		c.conn.SetWriteDeadline(time.Now().Add(time.Duration(c.timeout)))
		_, err = c.conn.Write(req)
		if err != nil {
			if writeRetry < int(c.maxRetry) {
				return Message{}, err
			}
			writeRetry++
			continue
		}
		break
	}

	packet := make([]byte, 1500)
	readRetry := 0
	for {
		c.conn.SetReadDeadline(time.Now().Add(time.Duration(c.timeout)))
		_, err = c.conn.Read(packet)
		if err != nil {
			if readRetry < int(c.maxRetry) {
				return Message{}, err
			}
			readRetry++
			continue
		}
		break
	}
	res := Message{}
	err = res.Decode(packet)
	if err != nil {
		return Message{}, err
	}
	return res, nil
}

func (c Client) Close() error {
	err := c.conn.Close()
	if err != nil {
		return err
	}
	return nil
}
