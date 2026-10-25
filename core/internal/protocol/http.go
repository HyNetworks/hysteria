package protocol

import (
	"net/http"
	"strconv"
)

const (
	URLHost = "hysteria"
	URLPath = "/auth"

	RequestHeaderAuth        = "Hysteria-Auth"
	ResponseHeaderUDPEnabled = "Hysteria-UDP"
	CommonHeaderCCRX         = "Hysteria-CC-RX"
	CommonHeaderPadding      = "Hysteria-Padding"
	HeaderL3                 = "Hysteria-L3"
	HeaderL3Mode             = "Hysteria-L3-Mode"
	HeaderL3Lanes            = "Hysteria-L3-Lanes"

	L3ModeDatagram = "datagram"
	L3ModeStream   = "stream"
	// L3ModeHybrid is a local sending policy, not a wire mode. It negotiates
	// stream, then sends inner TCP on the lanes and everything else as datagrams.
	L3ModeHybrid = "hybrid"

	StatusAuthOK = 233
)

// AuthRequest is what client sends to server for authentication.
type AuthRequest struct {
	Auth    string
	Rx      uint64 // 0 = unknown, client asks server to use bandwidth detection
	L3      bool   // client wants the L3 tunnel
	L3Mode  string // empty or datagram keeps the datagram path
	L3Lanes int
}

// AuthResponse is what server sends to client when authentication is passed.
type AuthResponse struct {
	UDPEnabled bool
	Rx         uint64 // 0 = unlimited
	RxAuto     bool   // true = server asks client to use bandwidth detection
	L3         bool   // server granted the L3 tunnel
	L3Mode     string
	L3Lanes    int
}

func AuthRequestFromHeader(h http.Header) AuthRequest {
	rx, _ := strconv.ParseUint(h.Get(CommonHeaderCCRX), 10, 64)
	l3, _ := strconv.ParseBool(h.Get(HeaderL3))
	lanes, _ := strconv.Atoi(h.Get(HeaderL3Lanes))
	return AuthRequest{
		Auth:    h.Get(RequestHeaderAuth),
		Rx:      rx,
		L3:      l3,
		L3Mode:  h.Get(HeaderL3Mode),
		L3Lanes: lanes,
	}
}

func AuthRequestToHeader(h http.Header, req AuthRequest) {
	h.Set(RequestHeaderAuth, req.Auth)
	h.Set(CommonHeaderCCRX, strconv.FormatUint(req.Rx, 10))
	h.Set(HeaderL3, strconv.FormatBool(req.L3))
	if req.L3Mode != "" {
		h.Set(HeaderL3Mode, req.L3Mode)
	}
	if req.L3Lanes > 0 {
		h.Set(HeaderL3Lanes, strconv.Itoa(req.L3Lanes))
	}
	h.Set(CommonHeaderPadding, authRequestPadding.String())
}

func AuthResponseFromHeader(h http.Header) AuthResponse {
	resp := AuthResponse{}
	resp.UDPEnabled, _ = strconv.ParseBool(h.Get(ResponseHeaderUDPEnabled))
	resp.L3, _ = strconv.ParseBool(h.Get(HeaderL3))
	resp.L3Mode = h.Get(HeaderL3Mode)
	resp.L3Lanes, _ = strconv.Atoi(h.Get(HeaderL3Lanes))
	rxStr := h.Get(CommonHeaderCCRX)
	if rxStr == "auto" {
		// Special case for server requesting client to use bandwidth detection
		resp.RxAuto = true
	} else {
		resp.Rx, _ = strconv.ParseUint(rxStr, 10, 64)
	}
	return resp
}

func AuthResponseToHeader(h http.Header, resp AuthResponse) {
	h.Set(ResponseHeaderUDPEnabled, strconv.FormatBool(resp.UDPEnabled))
	h.Set(HeaderL3, strconv.FormatBool(resp.L3))
	if resp.L3Mode != "" {
		h.Set(HeaderL3Mode, resp.L3Mode)
	}
	if resp.L3Lanes > 0 {
		h.Set(HeaderL3Lanes, strconv.Itoa(resp.L3Lanes))
	}
	if resp.RxAuto {
		h.Set(CommonHeaderCCRX, "auto")
	} else {
		h.Set(CommonHeaderCCRX, strconv.FormatUint(resp.Rx, 10))
	}
	h.Set(CommonHeaderPadding, authResponsePadding.String())
}
