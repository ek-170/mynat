package mynat

import (
	"fmt"
	"net"
)

func GetIPFromIface(targetIface string) (ip4 []net.IP, ip6 []net.IP, err error) {
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
