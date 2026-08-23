package l2tp

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// A minimal PPP peer, for driving a real LNS to a verdict.
//
// The LAC under test relays PPP verbatim and understands none of it, which is
// the whole design -- so proving that design works end to end means someone has
// to be the subscriber. This is that someone: just enough LCP to bring the link
// up, just enough CHAP and PAP to answer an authenticator, and nothing else. It
// never runs outside an interop test.
//
// It is deliberately not a PPP implementation. It has no state machine, no
// restart timers and no retransmission: an interop test that needs those is a
// test of pppd, and pppd already exists.

const (
	pppProtoLCP    uint16 = 0xC021
	pppProtoPAP    uint16 = 0xC023
	pppProtoCHAP   uint16 = 0xC223
	pppProtoIPCP   uint16 = 0x8021
	pppProtoIPv6CP uint16 = 0x8057
	pppProtoIPv4   uint16 = 0x0021
)

// LCP and CHAP/PAP packets share a layout: code(1) id(1) length(2) data...
// (RFC 1661 s5, RFC 1994 s4, RFC 1334 s2.2).
const (
	lcpConfigureRequest byte = 1
	lcpConfigureAck     byte = 2
	lcpConfigureNak     byte = 3
	lcpConfigureReject  byte = 4
	lcpTerminateRequest byte = 5
	lcpTerminateAck     byte = 6
	lcpCodeReject       byte = 7
	lcpProtocolReject   byte = 8
	lcpEchoRequest      byte = 9
	lcpEchoReply        byte = 10
	lcpDiscardRequest   byte = 11
)

// RFC 1661 s6: configuration options.
const (
	lcpOptMRU          byte = 1
	lcpOptACCM         byte = 2
	lcpOptAuthProtocol byte = 3
	lcpOptQuality      byte = 4
	lcpOptMagicNumber  byte = 5
	lcpOptPFC          byte = 7
	lcpOptACFC         byte = 8
	// RFC 1990 s5.1: Multilink.
	lcpOptMRRU                  byte = 17
	lcpOptEndpointDiscriminator byte = 19
)

const (
	chapChallenge byte = 1
	chapResponse  byte = 2
	chapSuccess   byte = 3
	chapFailure   byte = 4
)

// RFC 1332 s3.3 and RFC 1877 s1.1: the options a subscriber actually needs.
const (
	ipcpOptIPAddress    byte = 3
	ipcpOptPrimaryDNS   byte = 129
	ipcpOptSecondaryDNS byte = 131
)

// RFC 5072 s4.1: IPv6CP has one option worth negotiating.
const ipv6cpOptInterfaceID byte = 1

const (
	papAuthenticateRequest byte = 1
	papAuthenticateAck     byte = 2
	papAuthenticateNak     byte = 3
)

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

// pppPacket builds the common code/id/length/data layout. The length field
// covers the whole packet including the four header octets.
func pppPacket(code, id byte, data []byte) []byte {
	pkt := make([]byte, 4+len(data))
	pkt[0], pkt[1] = code, id
	binary.BigEndian.PutUint16(pkt[2:4], uint16(4+len(data)))
	copy(pkt[4:], data)
	return pkt
}

type lcpOption struct {
	typ  byte
	data []byte
}

// RFC 1661 s6: type(1) length(1) data..., where length covers the two header
// octets.
func encodeLCPOptions(opts []lcpOption) []byte {
	var buf []byte
	for _, o := range opts {
		buf = append(buf, o.typ, byte(2+len(o.data)))
		buf = append(buf, o.data...)
	}
	return buf
}

func decodeLCPOptions(data []byte) []lcpOption {
	var opts []lcpOption
	for len(data) >= 2 {
		n := int(data[1])
		if n < 2 || n > len(data) {
			return opts // malformed; report what was readable
		}
		opts = append(opts, lcpOption{typ: data[0], data: append([]byte(nil), data[2:n]...)})
		data = data[n:]
	}
	return opts
}

func findOption(opts []lcpOption, typ byte) *lcpOption {
	for i := range opts {
		if opts[i].typ == typ {
			return &opts[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Describing what arrived
// ---------------------------------------------------------------------------

func lcpCodeName(code byte) string {
	switch code {
	case lcpConfigureRequest:
		return "Configure-Request"
	case lcpConfigureAck:
		return "Configure-Ack"
	case lcpConfigureNak:
		return "Configure-Nak"
	case lcpConfigureReject:
		return "Configure-Reject"
	case lcpTerminateRequest:
		return "Terminate-Request"
	case lcpTerminateAck:
		return "Terminate-Ack"
	case lcpCodeReject:
		return "Code-Reject"
	case lcpProtocolReject:
		return "Protocol-Reject"
	case lcpEchoRequest:
		return "Echo-Request"
	case lcpEchoReply:
		return "Echo-Reply"
	case lcpDiscardRequest:
		return "Discard-Request"
	default:
		return fmt.Sprintf("code %d", code)
	}
}

func authProtocolName(data []byte) string {
	if len(data) < 2 {
		return "malformed"
	}
	switch binary.BigEndian.Uint16(data[:2]) {
	case pppProtoPAP:
		return "PAP"
	case pppProtoCHAP:
		if len(data) >= 3 && data[2] == 5 {
			return "CHAP-MD5"
		}
		return fmt.Sprintf("CHAP algorithm %x", data[2:])
	default:
		return fmt.Sprintf("protocol %04x", binary.BigEndian.Uint16(data[:2]))
	}
}

// describeLCP renders an LCP packet for a test log. Interop failures are
// diagnosed from what the peer actually said, and a hex dump is not that.
func describeLCP(payload []byte) string {
	if len(payload) < 4 {
		return "truncated LCP packet " + hex.EncodeToString(payload)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s id=%d", lcpCodeName(payload[0]), payload[1])
	body := payload[4:]
	switch payload[0] {
	case lcpConfigureRequest, lcpConfigureAck, lcpConfigureNak, lcpConfigureReject:
		for _, o := range decodeLCPOptions(body) {
			switch o.typ {
			case lcpOptMRU:
				if len(o.data) >= 2 {
					fmt.Fprintf(&b, " MRU=%d", binary.BigEndian.Uint16(o.data))
				}
			case lcpOptACCM:
				fmt.Fprintf(&b, " ACCM=%x", o.data)
			case lcpOptAuthProtocol:
				fmt.Fprintf(&b, " Auth=%s", authProtocolName(o.data))
			case lcpOptQuality:
				fmt.Fprintf(&b, " Quality=%x", o.data)
			case lcpOptMagicNumber:
				fmt.Fprintf(&b, " Magic=%x", o.data)
			case lcpOptPFC:
				b.WriteString(" PFC")
			case lcpOptACFC:
				b.WriteString(" ACFC")
			default:
				fmt.Fprintf(&b, " opt%d=%x", o.typ, o.data)
			}
		}
	default:
		if len(body) > 0 {
			fmt.Fprintf(&b, " data=%s", hex.EncodeToString(body))
		}
	}
	return b.String()
}

// describeIPCP is describeLCP for the network layer. It needs its own option
// names because the numbers collide: option 3 is Authentication-Protocol in LCP
// and IP-Address in IPCP.
func describeIPCP(payload []byte) string {
	if len(payload) < 4 {
		return "truncated IPCP packet " + hex.EncodeToString(payload)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s id=%d", lcpCodeName(payload[0]), payload[1])
	for _, o := range decodeLCPOptions(payload[4:]) {
		name := map[byte]string{
			ipcpOptIPAddress:    "IP",
			ipcpOptPrimaryDNS:   "DNS1",
			ipcpOptSecondaryDNS: "DNS2",
		}[o.typ]
		if name == "" {
			fmt.Fprintf(&b, " opt%d=%x", o.typ, o.data)
			continue
		}
		if len(o.data) == 4 {
			fmt.Fprintf(&b, " %s=%d.%d.%d.%d", name, o.data[0], o.data[1], o.data[2], o.data[3])
		} else {
			fmt.Fprintf(&b, " %s=%x", name, o.data)
		}
	}
	return b.String()
}

// describeIPv6CP renders an IPv6CP packet: RFC 5072's Interface-Identifier is
// the only option that appears in practice.
func describeIPv6CP(payload []byte) string {
	if len(payload) < 4 {
		return "truncated IPv6CP packet " + hex.EncodeToString(payload)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s id=%d", lcpCodeName(payload[0]), payload[1])
	for _, o := range decodeLCPOptions(payload[4:]) {
		if o.typ == ipv6cpOptInterfaceID {
			fmt.Fprintf(&b, " InterfaceID=%s", hex.EncodeToString(o.data))
		} else {
			fmt.Fprintf(&b, " opt%d=%x", o.typ, o.data)
		}
	}
	return b.String()
}

func describePPP(proto uint16, payload []byte) string {
	switch proto {
	case pppProtoLCP:
		return "LCP " + describeLCP(payload)
	case pppProtoCHAP:
		if len(payload) < 4 {
			return "CHAP truncated"
		}
		name := map[byte]string{
			chapChallenge: "Challenge", chapResponse: "Response",
			chapSuccess: "Success", chapFailure: "Failure",
		}[payload[0]]
		if name == "" {
			name = fmt.Sprintf("code %d", payload[0])
		}
		// A Failure carries a human-readable message, which is usually the most
		// informative thing in the whole exchange.
		if payload[0] == chapSuccess || payload[0] == chapFailure {
			return fmt.Sprintf("CHAP %s id=%d %q", name, payload[1], string(payload[4:]))
		}
		return fmt.Sprintf("CHAP %s id=%d", name, payload[1])
	case pppProtoPAP:
		if len(payload) < 4 {
			return "PAP truncated"
		}
		name := map[byte]string{
			papAuthenticateRequest: "Authenticate-Request",
			papAuthenticateAck:     "Authenticate-Ack",
			papAuthenticateNak:     "Authenticate-Nak",
		}[payload[0]]
		if name == "" {
			name = fmt.Sprintf("code %d", payload[0])
		}
		msg := ""
		if len(payload) > 5 {
			n := int(payload[4])
			if 5+n <= len(payload) {
				msg = string(payload[5 : 5+n])
			}
		}
		return fmt.Sprintf("PAP %s id=%d %q", name, payload[1], msg)
	case pppProtoIPCP:
		return "IPCP " + describeIPCP(payload)
	case pppProtoIPv6CP:
		return "IPv6CP " + describeIPv6CP(payload)
	case pppProtoIPv4:
		return "IPv4 packet"
	default:
		return fmt.Sprintf("protocol %04x %s", proto, hex.EncodeToString(payload))
	}
}

// ---------------------------------------------------------------------------
// The peer
// ---------------------------------------------------------------------------

// authOutcome is what an authentication attempt ended as.
type authOutcome int

const (
	outcomeNone authOutcome = iota
	// outcomeDenied: the authenticator refused the credentials. This is the
	// expected result for a random username and password, and it is the whole
	// point of the exercise -- it proves the LNS is the authenticator.
	outcomeDenied
	// outcomeAccepted: the authenticator accepted them.
	outcomeAccepted
	// outcomeLinkTerminated: the far end closed the link without ever giving an
	// authentication verdict.
	outcomeLinkTerminated
	// outcomeNetworkUp: authentication succeeded and a network control protocol
	// reached Opened. Only reachable when the peer was told to carry on past the
	// verdict.
	outcomeNetworkUp
)

func (o authOutcome) String() string {
	switch o {
	case outcomeDenied:
		return "denied"
	case outcomeAccepted:
		return "accepted"
	case outcomeLinkTerminated:
		return "link terminated without a verdict"
	case outcomeNetworkUp:
		return "network up"
	default:
		return "no outcome"
	}
}

type pppPeer struct {
	t       *testing.T
	session *Session

	user     string
	password string

	// magic is our Magic-Number, offered so the peer's loopback detection has
	// something to compare against.
	magic [4]byte

	// authProto is what the peer's Configure-Request asked for, once seen.
	authProto uint16

	// allowPFC lets a test accept Protocol-Field-Compression, and
	// allowMultilink the MRRU and endpoint discriminator that turn the link into
	// a Multilink bundle. Both are off by default so the ordinary tests get the
	// simplest exchange; TestInteropWhatTheLNSPutsOnTheWire turns them on to
	// find out what a real LNS does with them.
	allowPFC       bool
	allowMultilink bool

	// transcript is every frame in both directions, for the failure message.
	transcript []string
	nextID     byte
	sentPAP    bool

	// carryOn keeps the peer running past the authentication verdict, through
	// the network control protocols, so a test with real credentials can prove
	// the whole session.
	carryOn bool

	// linger keeps reading after the network layer is up. Compression only ever
	// applies to data-phase protocols, so a peer that stops at the last
	// Configure-Ack has seen nothing that could have been compressed.
	linger time.Duration
	up     bool

	sentIPCP     bool
	ipcpRejected []byte
	ipcpUp       bool

	sentIPv6CP     bool
	ipv6cpRejected bool
	ipv6cpUp       bool
	interfaceID    []byte
	assigned       []byte // the IPv4 address the LNS handed out
	dns            [][]byte
	ipcpAcked      bool
}

func newPPPPeer(t *testing.T, s *Session, user, password string) *pppPeer {
	t.Helper()
	p := &pppPeer{t: t, session: s, user: user, password: password, nextID: 1}
	_, _ = rand.Read(p.magic[:])
	return p
}

// randomCredentials returns a username and password that no authentication
// backend can know. The username carries a realm because an LNS commonly routes
// on one, and an unroutable realm may produce a different rejection from a wrong
// password -- both are denials, and the transcript says which.
func randomCredentials(t *testing.T) (user, password string) {
	t.Helper()
	var b [12]byte
	_, err := rand.Read(b[:])
	if err != nil {
		t.Fatalf("no randomness available: %v", err)
	}
	return fmt.Sprintf("nosuchuser-%s@invalid", hex.EncodeToString(b[:6])),
		hex.EncodeToString(b[6:])
}

func (p *pppPeer) send(proto uint16, payload []byte) {
	p.t.Helper()
	p.note("->", proto, payload)
	// Uncompressed and without address/control, which this peer's own
	// Configure-Request never asks to change.
	if err := p.session.SendPPP(framePPP(proto, payload)); err != nil {
		p.t.Fatalf("could not send a PPP frame to the LNS: %v\n%s", err, p.dump())
	}
}

func (p *pppPeer) note(dir string, proto uint16, payload []byte) {
	p.transcript = append(p.transcript, fmt.Sprintf("  %s %s", dir, describePPP(proto, payload)))
}

func (p *pppPeer) dump() string {
	return "PPP transcript:\n" + strings.Join(p.transcript, "\n")
}

func (p *pppPeer) id() byte {
	p.nextID++
	return p.nextID
}

// ourConfigureRequest asks for almost nothing. A subscriber that requests no
// options is legal (RFC 1661 s6 makes every option optional) and gives the peer
// nothing to Nak, which keeps this peer free of a negotiation state machine.
// The Magic Number is the one exception: without it the peer cannot distinguish
// a looped-back link, and some implementations insist.
func (p *pppPeer) ourConfigureRequest() []byte {
	opts := []lcpOption{{typ: lcpOptMagicNumber, data: p.magic[:]}}
	if p.allowPFC {
		// Accepting PFC is not enough to see it: a peer may only compress toward
		// someone who asked it to, so observing whether one does means requesting
		// it here.
		opts = append(opts, lcpOption{typ: lcpOptPFC})
	}
	return pppPacket(lcpConfigureRequest, p.id(), encodeLCPOptions(opts))
}

// acceptableOption says whether this peer can honour a configuration option.
//
// The list is short on purpose. Anything not here is Configure-Rejected, which
// is both correct and useful: a real LNS's reaction to a refusal is part of what
// an interop test is for.
func (p *pppPeer) acceptableOption(o lcpOption) bool {
	switch o.typ {
	case lcpOptMRU, lcpOptACCM, lcpOptMagicNumber, lcpOptACFC:
		return true
	case lcpOptAuthProtocol:
		if len(o.data) < 2 {
			return false
		}
		switch binary.BigEndian.Uint16(o.data[:2]) {
		case pppProtoPAP:
			return true
		case pppProtoCHAP:
			return len(o.data) >= 3 && o.data[2] == 5 // MD5 only
		}
		return false
	case lcpOptPFC:
		// Protocol-Field-Compression lets the peer send a one-octet protocol
		// field for the protocols that carry user traffic.
		return p.allowPFC
	case lcpOptMRRU, lcpOptEndpointDiscriminator:
		// Accepting these makes the link one member of a Multilink bundle, after
		// which data arrives as MP fragments (protocol 0x003D).
		return p.allowMultilink
	default:
		return false
	}
}

// chapResponseValue is RFC 1994 s4.1: MD5 over the identifier octet, the secret
// and the challenge, in that order.
func chapResponseValue(id byte, password string, challenge []byte) []byte {
	h := md5.New()
	h.Write([]byte{id})
	h.Write([]byte(password))
	h.Write(challenge)
	return h.Sum(nil)
}

// run drives the link until the authenticator gives a verdict, the peer
// terminates the link, or the deadline expires.
func (p *pppPeer) run(deadline time.Duration) authOutcome {
	p.t.Helper()
	stop := time.After(deadline)
	type inbound struct {
		raw []byte
		err error
	}
	frames := make(chan inbound, 16)
	go func() {
		for {
			raw, err := p.session.RecvPPP()
			frames <- inbound{raw, err}
			if err != nil {
				return
			}
		}
	}()

	sentOurRequest := false
	var lingerUntil <-chan time.Time
	for {
		select {
		case <-lingerUntil:
			return outcomeNetworkUp
		case <-stop:
			if p.up {
				return outcomeNetworkUp
			}
			p.t.Fatalf("the LNS said nothing conclusive within %s\n%s", deadline, p.dump())
			return outcomeNone
		case f := <-frames:
			if f.err != nil {
				// The session ended. Whether that is a denial is for the caller to
				// decide from the L2TP Result Code.
				p.transcript = append(p.transcript, "  -- session ended: "+f.err.Error())
				return outcomeLinkTerminated
			}
			proto, payload := splitPPP(f.raw)
			p.note("<-", proto, payload)
			out := p.handle(proto, payload, &sentOurRequest)
			if out == outcomeNetworkUp && p.linger > 0 {
				// Stay on the link a while: what the far end sends once the
				// session is carrying traffic is the whole question.
				if !p.up {
					p.up = true
					lingerUntil = time.After(p.linger)
				}
				continue
			}
			if out != outcomeNone {
				return out
			}
		}
	}
}

func (p *pppPeer) handle(proto uint16, payload []byte, sentOurRequest *bool) authOutcome {
	if len(payload) < 4 {
		return outcomeNone
	}
	code, id, body := payload[0], payload[1], payload[4:]

	switch proto {
	case pppProtoLCP:
		switch code {
		case lcpConfigureRequest:
			opts := decodeLCPOptions(body)
			// RFC 1661 s5.3: options this peer does not implement are refused with
			// a Configure-Reject listing exactly those, and the peer then asks
			// again without them. Acking an option we cannot honour would be worse
			// than refusing it -- the far end would go on to use it.
			var reject []lcpOption
			for _, o := range opts {
				if !p.acceptableOption(o) {
					reject = append(reject, o)
				}
			}
			if len(reject) > 0 {
				p.send(pppProtoLCP, pppPacket(lcpConfigureReject, id, encodeLCPOptions(reject)))
				return outcomeNone // wait for the peer to ask again
			}

			if opt := findOption(opts, lcpOptAuthProtocol); opt != nil && len(opt.data) >= 2 {
				p.authProto = binary.BigEndian.Uint16(opt.data[:2])
			}
			p.send(pppProtoLCP, pppPacket(lcpConfigureAck, id, body))
			if !*sentOurRequest {
				*sentOurRequest = true
				p.send(pppProtoLCP, p.ourConfigureRequest())
			}
			// PAP is the authenticatee's move: nothing prompts it, so once the peer
			// has asked for PAP and acked our side, we have to speak first.
			if p.authProto == pppProtoPAP {
				p.sendPAPRequest()
			}

		case lcpConfigureAck:
			// Our side is up. Under PAP this is the earliest safe moment to
			// authenticate; under CHAP the peer challenges us.
			if p.authProto == pppProtoPAP {
				p.sendPAPRequest()
			}

		case lcpConfigureNak, lcpConfigureReject:
			// We asked for one option. If it is not wanted, ask for nothing.
			p.send(pppProtoLCP, pppPacket(lcpConfigureRequest, p.id(), nil))

		case lcpEchoRequest:
			// Echo-Reply carries our own Magic Number (RFC 1661 s5.8).
			p.send(pppProtoLCP, pppPacket(lcpEchoReply, id, append(append([]byte(nil), p.magic[:]...), body[min(4, len(body)):]...)))

		case lcpTerminateRequest:
			p.send(pppProtoLCP, pppPacket(lcpTerminateAck, id, nil))
			return outcomeLinkTerminated

		case lcpProtocolReject, lcpCodeReject:
			// Nothing to do: this peer has no fallback to offer.
		}

	case pppProtoCHAP:
		switch code {
		case chapChallenge:
			// RFC 1994 s4.1: value-size(1) value(n) name(...)
			if len(body) < 1 {
				return outcomeNone
			}
			n := int(body[0])
			if 1+n > len(body) {
				p.t.Fatalf("the LNS sent a CHAP Challenge whose value runs past the packet\n%s", p.dump())
			}
			challenge := body[1 : 1+n]
			value := chapResponseValue(id, p.password, challenge)
			resp := make([]byte, 0, 1+len(value)+len(p.user))
			resp = append(resp, byte(len(value)))
			resp = append(resp, value...)
			resp = append(resp, p.user...)
			p.send(pppProtoCHAP, pppPacket(chapResponse, id, resp))

		case chapFailure:
			return outcomeDenied
		case chapSuccess:
			if !p.carryOn {
				return outcomeAccepted
			}
		}

	case pppProtoPAP:
		switch code {
		case papAuthenticateNak:
			return outcomeDenied
		case papAuthenticateAck:
			if !p.carryOn {
				return outcomeAccepted
			}
		}

	case pppProtoIPCP:
		// Reaching IPCP means authentication succeeded. A peer that was only
		// asking for a verdict has its answer; one that was told to carry on
		// negotiates an address.
		if !p.carryOn {
			return outcomeAccepted
		}
		return p.handleIPCP(code, id, body)

	case pppProtoIPv6CP:
		if !p.carryOn {
			return outcomeAccepted
		}
		return p.handleIPv6CP(code, id, body)
	}
	return outcomeNone
}

// handleIPCP runs the address negotiation of RFC 1332.
//
// The subscriber asks for 0.0.0.0 and lets the LNS say what it should have: an
// LNS answers a request it does not like with a Configure-Nak carrying the
// values it will accept, so asking for nothing in particular is how a dial-in
// client is assigned an address. The DNS options (RFC 1877) go the same way.
func (p *pppPeer) handleIPCP(code, id byte, body []byte) authOutcome {
	switch code {
	case lcpConfigureRequest:
		// The LNS is telling us its own address. There is nothing to object to.
		p.send(pppProtoIPCP, pppPacket(lcpConfigureAck, id, body))
		if !p.sentIPCP {
			p.sentIPCP = true
			p.sendIPCPRequest()
		}

	case lcpConfigureNak:
		// What the LNS will accept, which is what we asked to be told.
		for _, o := range decodeLCPOptions(body) {
			if len(o.data) != 4 {
				continue
			}
			switch o.typ {
			case ipcpOptIPAddress:
				p.assigned = append([]byte(nil), o.data...)
			case ipcpOptPrimaryDNS, ipcpOptSecondaryDNS:
				p.dns = append(p.dns, append([]byte(nil), o.data...))
			}
		}
		p.sendIPCPRequest()

	case lcpConfigureReject:
		// RFC 1661 s5.4: a rejected option must not appear in the next request.
		// Leaving it in loops forever, and an LNS may Configure-Reject an option
		// another would Configure-Nak, so this is not a path a peer can skip.
		for _, o := range decodeLCPOptions(body) {
			p.ipcpRejected = append(p.ipcpRejected, o.typ)
		}
		p.sendIPCPRequest()

	case lcpConfigureAck:
		p.ipcpUp = true
		return p.networkOutcome()

	case lcpTerminateRequest:
		p.send(pppProtoIPCP, pppPacket(lcpTerminateAck, id, nil))
		return outcomeLinkTerminated
	}
	return outcomeNone
}

// sendIPCPRequest asks for the address the LNS last offered, or for 0.0.0.0 the
// first time round, minus anything the LNS has already refused to discuss.
func (p *pppPeer) sendIPCPRequest() {
	ip := p.assigned
	if len(ip) != 4 {
		ip = []byte{0, 0, 0, 0}
	}
	primary, secondary := []byte{0, 0, 0, 0}, []byte{0, 0, 0, 0}
	if len(p.dns) > 0 {
		primary = p.dns[0]
	}
	if len(p.dns) > 1 {
		secondary = p.dns[1]
	}
	var opts []lcpOption
	for _, o := range []lcpOption{
		{typ: ipcpOptIPAddress, data: ip},
		{typ: ipcpOptPrimaryDNS, data: primary},
		{typ: ipcpOptSecondaryDNS, data: secondary},
	} {
		if !slices.Contains(p.ipcpRejected, o.typ) {
			opts = append(opts, o)
		}
	}
	// An empty Configure-Request is legal (RFC 1661 s5.1) and is what is left
	// when the peer will not negotiate any of these options.
	p.send(pppProtoIPCP, pppPacket(lcpConfigureRequest, p.id(), encodeLCPOptions(opts)))
}

// handleIPv6CP is RFC 5072: one option, an 8-octet Interface-Identifier that
// each end picks for itself and the other end Naks if it collides.
func (p *pppPeer) handleIPv6CP(code, id byte, body []byte) authOutcome {
	switch code {
	case lcpConfigureRequest:
		p.send(pppProtoIPv6CP, pppPacket(lcpConfigureAck, id, body))
		if !p.sentIPv6CP {
			p.sentIPv6CP = true
			p.sendIPv6CPRequest()
		}

	case lcpConfigureNak:
		if o := findOption(decodeLCPOptions(body), ipv6cpOptInterfaceID); o != nil && len(o.data) == 8 {
			p.interfaceID = append([]byte(nil), o.data...)
		}
		p.sendIPv6CPRequest()

	case lcpConfigureReject:
		p.ipv6cpRejected = true
		p.send(pppProtoIPv6CP, pppPacket(lcpConfigureRequest, p.id(), nil))

	case lcpConfigureAck:
		p.ipv6cpUp = true
		return p.networkOutcome()

	case lcpTerminateRequest:
		p.send(pppProtoIPv6CP, pppPacket(lcpTerminateAck, id, nil))
	}
	return outcomeNone
}

func (p *pppPeer) sendIPv6CPRequest() {
	if p.ipv6cpRejected {
		p.send(pppProtoIPv6CP, pppPacket(lcpConfigureRequest, p.id(), nil))
		return
	}
	if len(p.interfaceID) != 8 {
		p.interfaceID = make([]byte, 8)
		_, _ = rand.Read(p.interfaceID)
		p.interfaceID[0] &^= 0x02 // not a globally unique identifier
	}
	p.send(pppProtoIPv6CP, pppPacket(lcpConfigureRequest, p.id(),
		encodeLCPOptions([]lcpOption{{typ: ipv6cpOptInterfaceID, data: p.interfaceID}})))
}

// networkOutcome reports the session up once either network layer has agreed.
//
// Either alone is a working session. Requiring both, or requiring IPv4
// specifically, would report a failure for a service that provisions only one of
// them -- which is a decision for the operator, not for this test.
func (p *pppPeer) networkOutcome() authOutcome {
	if p.ipcpUp || p.ipv6cpUp {
		return outcomeNetworkUp
	}
	return outcomeNone
}

// assignedIP renders the address the LNS handed out.
func (p *pppPeer) assignedIP() string {
	if len(p.assigned) != 4 {
		return ""
	}
	return net.IP(p.assigned).String()
}

// sendPAPRequest is RFC 1334 s2.2.1: peer-ID-length(1) peer-ID(n)
// passwd-length(1) passwd(n). It goes out at most once.
func (p *pppPeer) sendPAPRequest() {
	if p.sentPAP {
		return
	}
	p.sentPAP = true
	body := make([]byte, 0, 2+len(p.user)+len(p.password))
	body = append(body, byte(len(p.user)))
	body = append(body, p.user...)
	body = append(body, byte(len(p.password)))
	body = append(body, p.password...)
	p.send(pppProtoPAP, pppPacket(papAuthenticateRequest, p.id(), body))
}
