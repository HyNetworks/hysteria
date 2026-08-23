module github.com/apernet/hysteria/app/v2

go 1.25.0

toolchain go1.25.1

require (
	github.com/apernet/go-tproxy v0.0.0-20230809025308-8f4723fd742f
	github.com/apernet/hysteria/core/v2 v2.0.0-00010101000000-000000000000
	github.com/apernet/hysteria/extras/v2 v2.0.0-00010101000000-000000000000
	github.com/apernet/sing-tun v0.2.6-0.20250920121535-299f04629986
	github.com/caddyserver/certmagic v0.25.4
	github.com/libdns/cloudflare v0.2.2
	github.com/libdns/duckdns v0.3.0
	github.com/libdns/gandi v1.1.0
	github.com/libdns/godaddy v1.1.0
	github.com/libdns/namecheap v1.0.0
	github.com/libdns/njalla v0.0.0-20250815081032-a55a87a8f20f
	github.com/libdns/porkbun v1.1.0
	github.com/libdns/vultr/v2 v2.0.4
	github.com/mdp/qrterminal/v3 v3.2.1
	github.com/mholt/acmez/v3 v3.1.6
	github.com/sagernet/sing v0.3.2
	github.com/spf13/cobra v1.10.2
	github.com/spf13/viper v1.21.0
	github.com/stretchr/testify v1.11.1
	github.com/txthinking/socks5 v0.0.0-20230325130024-4230056ae301
	go.uber.org/zap v1.28.0
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e // indirect
	github.com/caddyserver/zerossl v0.1.5 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/database64128/netx-go v0.1.1 // indirect
	github.com/database64128/tfo-go/v2 v2.3.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/huin/goupnp v1.2.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/koron/go-ssdp v0.0.4 // indirect
	github.com/libdns/libdns v1.1.1 // indirect
	github.com/libp2p/go-nat v1.0.1-0.20250821073202-01afc089f138 // indirect
	github.com/libp2p/go-netroute v0.2.1 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pion/dtls/v3 v3.1.4 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/stun/v3 v3.1.6 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/sagernet/netlink v0.0.0-20220905062125-8043b4a9aa97 // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/scjalliance/comshim v0.0.0-20230315213746-5e51f40bd3b9 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/txthinking/runnergroup v0.0.0-20210608031112-152c7c4432bf // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	github.com/vultr/govultr/v3 v3.20.0 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/qr v0.2.0 // indirect
)

replace github.com/apernet/hysteria/core/v2 => ../core

replace github.com/apernet/hysteria/extras/v2 => ../extras
