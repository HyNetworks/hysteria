module github.com/apernet/hysteria/extras/v2

go 1.26.0

require (
	github.com/apernet/hysteria/core/v2 v2.0.0-00010101000000-000000000000
	github.com/apernet/quic-go v0.62.1-0.20260912175848-73339f7edbb9
	github.com/database64128/tfo-go/v2 v2.3.3
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/libp2p/go-nat v1.0.1-0.20250821073202-01afc089f138
	github.com/miekg/dns v1.1.72
	github.com/pion/stun/v3 v3.1.6
	github.com/refraction-networking/utls v1.8.2
	github.com/stretchr/testify v1.12.1
	github.com/txthinking/socks5 v0.0.0-20230325130024-4230056ae301
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.57.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/database64128/netx-go v0.1.1 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/huin/goupnp v1.2.0 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/koron/go-ssdp v0.0.4 // indirect
	github.com/libp2p/go-netroute v0.2.1 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pion/dtls/v3 v3.1.4 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	github.com/txthinking/runnergroup v0.0.0-20210608031112-152c7c4432bf // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
)

replace github.com/apernet/hysteria/core/v2 => ../core
