package outbounds

import (
	"errors"
	"net"
	"strings"

	"github.com/apernet/hysteria/extras/v2/outbounds/acl"
)

const (
	aclCacheSize = 1024
)

var errRejected = errors.New("rejected")

// aclEngine is a PluggableOutbound that dispatches connections to different
// outbounds based on ACL rules.
// There are 3 built-in outbounds:
// - direct: directOutbound, auto mode
// - reject: reject the connection
// - default: first outbound in the list, or if the list is empty, equal to direct
// If the user-defined outbounds contain any of the above names, they will
// override the built-in outbounds.
type aclEngine struct {
	RuleSet acl.CompiledRuleSet[PluggableOutbound]
	Default PluggableOutbound
}

type OutboundEntry struct {
	Name     string
	Outbound PluggableOutbound
}

// NewACLEngine creates an ACL engine from expr-based rules.
func NewACLEngine(rules []acl.Rule, outbounds []OutboundEntry, geoLoader acl.GeoLoader) (PluggableOutbound, error) {
	obMap := outboundsToMap(outbounds)
	rs, err := acl.Compile[PluggableOutbound](rules, obMap, aclCacheSize, geoLoader)
	if err != nil {
		return nil, err
	}
	return &aclEngine{rs, obMap["default"]}, nil
}

func outboundsToMap(outbounds []OutboundEntry) map[string]PluggableOutbound {
	obMap := make(map[string]PluggableOutbound)
	for _, ob := range outbounds {
		obMap[strings.ToLower(ob.Name)] = ob.Outbound
	}
	// Add built-in outbounds if not overridden
	if _, ok := obMap["direct"]; !ok {
		obMap["direct"] = NewDirectOutboundSimple(DirectOutboundModeAuto)
	}
	if _, ok := obMap["reject"]; !ok {
		obMap["reject"] = &aclRejectOutbound{}
	}
	if _, ok := obMap["default"]; !ok {
		if len(outbounds) > 0 {
			obMap["default"] = outbounds[0].Outbound
		} else {
			obMap["default"] = obMap["direct"]
		}
	}
	return obMap
}

func (a *aclEngine) handle(reqAddr *AddrEx, proto acl.Protocol) PluggableOutbound {
	req := acl.Request{
		Proto: proto,
		Host:  reqAddr.Host,
		Port:  reqAddr.Port,
	}
	if reqAddr.ResolveInfo != nil {
		req.IPv4 = reqAddr.ResolveInfo.IPv4
		req.IPv6 = reqAddr.ResolveInfo.IPv6
	}
	if reqAddr.Info != nil {
		req.AuthID = reqAddr.Info.AuthID
		req.ClientAddr = reqAddr.Info.ClientAddr
	}
	ob, hijackIP := a.RuleSet.Match(&req)
	if ob == nil {
		// No match, use default outbound
		return a.Default
	}
	if hijackIP != nil {
		// We must rewrite both Host & ResolveInfo,
		// as some outbounds only care about Host.
		reqAddr.Host = hijackIP.String()
		if ip4 := hijackIP.To4(); ip4 != nil {
			reqAddr.ResolveInfo = &ResolveInfo{IPv4: ip4}
		} else {
			reqAddr.ResolveInfo = &ResolveInfo{IPv6: hijackIP}
		}
	}
	return ob
}

func (a *aclEngine) TCP(reqAddr *AddrEx) (net.Conn, error) {
	ob := a.handle(reqAddr, acl.ProtocolTCP)
	return ob.TCP(reqAddr)
}

func (a *aclEngine) UDP(reqAddr *AddrEx) (UDPConn, error) {
	ob := a.handle(reqAddr, acl.ProtocolUDP)
	return ob.UDP(reqAddr)
}

func (a *aclEngine) CheckUDP(reqAddr *AddrEx) error {
	ob := a.handle(reqAddr, acl.ProtocolUDP)
	return ob.CheckUDP(reqAddr)
}

type aclRejectOutbound struct{}

func (a *aclRejectOutbound) TCP(reqAddr *AddrEx) (net.Conn, error) {
	return nil, errRejected
}

func (a *aclRejectOutbound) UDP(reqAddr *AddrEx) (UDPConn, error) {
	return nil, errRejected
}

func (a *aclRejectOutbound) CheckUDP(reqAddr *AddrEx) error {
	return errRejected
}
