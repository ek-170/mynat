package mynat

import (
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/ek-170/myroute/pkg/logger"
	"github.com/ek-170/myroute/pkg/stun"
)

// TODO for CHANGE-REQUEST implemented STUN server
// func DiagnoseWithSingleSTUN(server, targetIface string) {
// 	urlxx, err := stun.ParseSTUNURL(server)
// 	if err != nil {
// 		panic(err)
// 	}

// 	logger.Debug(fmt.Sprintf("target: %s:%s", urlxx.Scheme, urlxx.Host))

// 	// TODO add support ipv6
// 	ip4, _, err := GetIPFromIface(targetIface)
// 	if err != nil {
// 		panic(err)
// 	}

// 	if len(ip4) == 0 {
// 		panic("not found ipv4 in spcefied interface")
// 	}

// 	logger.Info(fmt.Sprintf("using local ip: %s", ip4[0].String()))
// 	// TODO fix case of multiple ip
// 	client, err := stun.NewClient(*urlxx, ip4[0])
// 	if err != nil {
// 		panic(err)
// 	}

// 	res, err := client.Do(stun.NewMessage(stun.BindingReq))
// 	if err != nil {
// 		panic(err)
// 	}
// 	if err := client.Close(); err != nil {
// 		panic(err)
// 	}

// 	xadd := stun.XORMappedAddress{}
// 	attr, exist := res.Attributes.Extract(stun.AttrXorMappedAddress)
// 	if !exist {
// 		panic("not exists XOR-MAPPED-ADDRESS")
// 	}
// 	if err := xadd.Parse(attr, res.TransactionID); err != nil {
// 		panic(err)
// 	}
// }

// default STUN server candidates
// "stun.l.google.com:19302",
// "stun1.l.google.com:19302",
// "stun2.l.google.com:19302",
// "stun3.l.google.com:19302",
// "stun4.l.google.com:19302",
// "global.stun.twilio.com:3478",
const (
	defaultX = "stun.l.google.com:19302"
	defaultY = "stun1.l.google.com:19302"
)

// DiagnoseWithPublicSTUN diagnose NAT with Google/Twillio public STUN server
// this only EIM NAT or other can be determined, and can not know fileter type
func DiagnoseWithPublicSTUN(targetIface string) error {
	urlxx, err := stun.ParseSTUNURL(defaultX)
	if err != nil {
		return err
	}

	logger.Debug(fmt.Sprintf("target: %s:%s", urlxx.Scheme, urlxx.Host))

	// TODO add support ipv6
	ip4, _, err := GetIPFromIface(targetIface)
	if err != nil {
		return err
	}

	if len(ip4) == 0 {
		return errors.New("not found ipv4 in spcefied interface")
	}
	logger.Info(fmt.Sprintf("using local ip: %s", ip4[0].String()))

	// STUN Bind-Request for Google Public STUN 1
	res1st, err := doSTUNRequest(*urlxx, ip4[0], stun.NewMessage(stun.BindingReq))
	if err != nil {
		return err
	}

	xadd1st := stun.XORMappedAddress{}
	attr, exist := res1st.Attributes.Extract(stun.AttrXorMappedAddress)
	if !exist {
		return errors.New("not exists XOR-MAPPED-ADDRESS")
	}
	if err := xadd1st.Parse(attr, res1st.TransactionID); err != nil {
		return err
	}

	// check whether server reflexive ip equals private ip
	contained := containIP(ip4, xadd1st.Address)
	if contained {
		fmt.Println("There is no NAT")
		return nil
	}

	// STUN Bind-Request for Google Public STUN 2
	res2nd, err := doSTUNRequest(*urlxx, ip4[0], stun.NewMessage(stun.BindingReq))
	if err != nil {
		return err
	}

	xadd2nd := stun.XORMappedAddress{}
	attr, exist = res2nd.Attributes.Extract(stun.AttrXorMappedAddress)
	if !exist {
		return errors.New("not exists XOR-MAPPED-ADDRESS")
	}
	if err := xadd2nd.Parse(attr, res2nd.TransactionID); err != nil {
		return err
	}

	if xadd1st.Address.Equal(xadd2nd.Address) {
		fmt.Println("NAT Mapping Type: Endpoint-Independent Mapping(EIM)")
		fmt.Println("NAT Filtering Type: could not determine")
	}
	return nil
}

func doSTUNRequest(url url.URL, lip net.IP, req *stun.Message) (*stun.Message, error) {
	client, err := stun.NewClient(url, lip)
	if err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if err := client.Close(); err != nil {
		return nil, err
	}
	return res, nil
}

func containIP(comparator []net.IP, target net.IP) bool {
	for _, ip := range comparator {
		if ip.Equal(target) {
			return true
		}
	}
	return false
}
