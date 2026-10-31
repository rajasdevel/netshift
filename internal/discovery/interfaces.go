package discovery

import (
	"net"
	"slices"
	"strings"
)

// InterfaceSnapshot describes the addresses of active interfaces. IPv6
// addresses are reduced to their network prefix: temporary (privacy)
// addresses rotate within a prefix and are not a network change.
func InterfaceSnapshot() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var rows []string
	for _, item := range interfaces {
		if item.Flags&net.FlagLoopback != 0 || item.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := item.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			network, ok := addr.(*net.IPNet)
			if !ok || network.IP.IsLinkLocalUnicast() || network.IP.IsLoopback() {
				continue
			}
			if network.IP.To4() == nil {
				network = &net.IPNet{IP: network.IP.Mask(network.Mask), Mask: network.Mask}
			}
			rows = append(rows, item.Name+"="+network.String())
		}
	}
	slices.Sort(rows)
	return strings.Join(slices.Compact(rows), ","), nil
}
