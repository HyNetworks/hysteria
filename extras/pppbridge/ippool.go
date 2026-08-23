package pppbridge

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

// IPPool is a thread-safe IPv4 address pool for PPP sessions.
// The first usable IP (network+1) is reserved as the gateway.
// Client IPs are allocated from network+2 through broadcast-1.
type IPPool struct {
	mu      sync.Mutex
	network *net.IPNet
	gateway net.IP
	free    []net.IP
}

func NewIPPool(cidr string) (*IPPool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, errors.New("only IPv4 CIDRs are supported")
	}
	// Need at least /30 for network + gateway + 1 client + broadcast
	if ones > 30 {
		return nil, fmt.Errorf("CIDR /%d too small, need at least /30", ones)
	}

	netIP := ipToUint32(network.IP.To4())
	bcast := netIP | ^maskToUint32(network.Mask)

	gateway := uint32ToIP(netIP + 1)

	var free []net.IP
	for i := netIP + 2; i < bcast; i++ {
		free = append(free, uint32ToIP(i))
	}

	return &IPPool{
		network: network,
		gateway: gateway,
		free:    free,
	}, nil
}

func (p *IPPool) Gateway() string {
	return p.gateway.String()
}

func (p *IPPool) Allocate() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.free) == 0 {
		return "", errors.New("IP pool exhausted")
	}
	ip := p.free[0]
	p.free = p.free[1:]
	return ip.String(), nil
}

func (p *IPPool) Release(ipStr string) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.free = append(p.free, ip)
}

func ipToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip[:4])
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

func maskToUint32(mask net.IPMask) uint32 {
	return binary.BigEndian.Uint32(mask[:4])
}
