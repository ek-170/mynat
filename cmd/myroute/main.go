package main

import (
	"crypto/rand"

	"github.com/ek-170/myroute/pkg/logger"
	"github.com/ek-170/myroute/pkg/stun"
)

const (
	dest     = "stun:stun.l.google.com:19302"
	destIPv4 = "74.125.250.129"
	destIPv6 = "240f:7f:106e:1:c807:9559:46aa:3d10:19302"
)

func main() {
	logger.Info("start")

	client, err := stun.NewClient(destIPv4, 19302)
	if err != nil {
		panic(err)
	}

	tid := [stun.TransactionIDByte]byte{}
	rand.Read(tid[:])
	req := stun.Message{
		Type:          stun.BindingReq,
		Length:        0,
		Cookie:        stun.MagicCookie,
		TransactionID: tid,
	}

	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	if err := client.Close(); err != nil {
		panic(err)
	}

	res.ExtractXORMappedAddress()
}
