package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ek-170/myroute/pkg/logger"
	"github.com/ek-170/myroute/pkg/stun"
)

const (
	// default STUN server candidates
	// "stun.l.google.com:19302",
	// "stun1.l.google.com:19302",
	// "stun2.l.google.com:19302",
	// "stun3.l.google.com:19302",
	// "stun4.l.google.com:19302",
	// "global.stun.twilio.com:3478",

	DefaultXX = "stun.l.google.com:19302"
	DefaultYX = "stun1.l.google.com:19302"
)

func main() {
	var (
		urlxxStr = flag.String("xx", DefaultXX, "STUN server url, address is \"x\", port is \"X\"")
		// urlxyStr = flag.String("xy", "", "STUN server url, address is \"x\", port is \"Y\"")
		// urlyxStr = flag.String("yx", DefaultYX, "STUN server url, address is \"y\", port is \"X\"")
		// urlyyStr = flag.String("yy", "", "STUN server url, address is \"y\", port is \"Y\"")
		verbose = flag.Bool("v", false, "verbose")
		help    = flag.Bool("h", false, "command usage help")
	)

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *verbose {
		if err := logger.InitLogger(os.Stdout, logger.Text, logger.DebugStr); err != nil {
			panic(err)
		}
	}

	urlxx, err := stun.ParseSTUNURL(*urlxxStr)
	if err != nil {
		panic(err)
	}

	logger.Debug(fmt.Sprintf("target: %s:%s", urlxx.Scheme, urlxx.Host))

	client, err := stun.NewClient(*urlxx)
	if err != nil {
		panic(err)
	}

	res, err := client.Do(stun.NewMessage(stun.BindingReq))
	if err != nil {
		panic(err)
	}
	if err := client.Close(); err != nil {
		panic(err)
	}

	xadd := stun.XORMappedAddress{}
	attr, exist := res.Attributes.Extract(stun.AttrXorMappedAddress)
	if !exist {
		panic("not exists XOR-MAPPED-ADDRESS")
	}
	if err := xadd.Parse(attr, res.TransactionID); err != nil {
		panic(err)
	}
}
