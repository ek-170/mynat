package main

import (
	"flag"
	"fmt"
	"net"
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

	defaultXX = "stun.l.google.com:19302"
	defaultYX = "stun1.l.google.com:19302"

	defaultIface = "en0"
)

func main() {
	var (
		// server   = flag.String("s", defaultXX, "STUN server url. CHANGE-REQUEST Attribute must be implemented in server")
		urlxxStr = flag.String("xx", defaultXX, "STUN server url, address is \"x\", port is \"X\"")
		// urlxyStr = flag.String("xy", "", "STUN server url, address is \"x\", port is \"Y\"")
		// urlyxStr = flag.String("yx", DefaultYX, "STUN server url, address is \"y\", port is \"X\"")
		// urlyyStr = flag.String("yy", "", "STUN server url, address is \"y\", port is \"Y\"")
		targetIface = flag.String("i", defaultIface, "target network interface of inspection")
		verbose     = flag.Bool("v", false, "verbose")
		help        = flag.Bool("h", false, "command usage help")
	)

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	// TODO remove panic and display error massage

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

	// TODO add support ipv6
	ip4, _, err := getIPFromIface(*targetIface)
	if err != nil {
		panic(err)
	}

	if len(ip4) == 0 {
		panic("not found ipv4 in spcefied interface")
	}

	logger.Info(fmt.Sprintf("using local ip: %s", ip4[0].String()))
	// TODO fix case of multiple ip
	client, err := stun.NewClient(*urlxx, ip4[0])
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

func getIPFromIface(targetIface string) (ip4 []net.IP, ip6 []net.IP, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	var addrs []net.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if iface.Name != targetIface {
			continue
		}

		addrs, err = iface.Addrs()
		if err != nil {
			return nil, nil, err
		}
	}

	ip4 = []net.IP{}
	ip6 = []net.IP{}
	for _, addr := range addrs {
		var ip net.IP

		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		if ip == nil || ip.IsLoopback() {
			continue
		}

		if ip.To4() != nil {
			fmt.Printf("found ipv4 in interface %s: %s\n", targetIface, ip.String())
			ip4 = append(ip4, ip)
			continue
		}

		if ip.To16() != nil {
			fmt.Printf("found ipv6 in interface %s: %s\n", targetIface, ip.String())
			ip6 = append(ip6, ip)
		}
	}
	return ip4, ip6, nil
}
