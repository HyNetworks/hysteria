# 用 Hysteria 承载 VXLAN

VXLAN 网卡有两种放法，配置里用 `l3tun.type` 切换。省略 `type` 时是本机网卡。

| 模式 | `type` | VXLAN 网卡在哪 | Hysteria 本机 |
| --- | --- | --- | --- |
| 本机网卡 | `tun` | 和 Hysteria 同一台，建在 `hytun0` 上 | 创建 MTU 1600 的 TUN，需要 root |
| 远程网卡 | `relay` | 另一台机器。中继只在局域网上收发 UDP | 不建 TUN，不需要 root |

两种模式走同一条 L3 通道，`address` / `peer` / `mode` 的含义相同。一条链路一次只服务一个请求了 L3 的客户端。连接还活着时，别的用户拿不走这条链路；同一个用户重新连上来，会顶掉自己的旧连接，旧连接被服务端关闭，然后自己重连。IP 包最大 1600 字节。代理用的 `tun` 不参与这条链路。

两端都要写 `l3tun`。客户端写了，认证请求里才带 `Hysteria-L3`。服务端写了，才会同意。缺任意一侧，这条通道不会通。旧版 Hysteria 不认识这种包，会直接丢掉。

`mode` 省略是 `datagram`：一颗 IP 包放进一条 QUIC datagram，路径装不下就切成均匀的几片，缺一片整包作废。`mode: stream` 把每个内层流放进自己的可靠 QUIC stream。外层 UDP 源端口决定落在 32 条里的哪一条，同一条流不拆开，其它流不被它挡住。丢了的包由 QUIC 重传。每条 lane 最多排 128 颗包，排满后新包直接丢弃，由内层 TCP 自己重传。这样一条被压住的流不会卡住其它 lane，排队延迟也有上限。配置里的 `lanes` 会放进认证头，流池大小固定是 32，不跟着这个数字变。stream 模式下，内层 TCP 的纯 ACK 两个方向都走 datagram：ACK 是累积的，丢一颗没关系，也不会排在一次重传后面。

```yaml
l3tun:
  mode: stream
  lanes: 8
```

`mode: hybrid` 按内层协议分流。内层 TCP 的数据段留在 stream lane 上，由 QUIC 重传。其它包，包括 UDP、ICMP、ARP 和纯 ACK，都走 datagram：丢一颗只损失这一颗，后面的包不用等它重传。VoIP、游戏，以及内层再跑 QUIC 或 WireGuard 时，适合用这个模式。握手时它按 stream 协商，所以对端写 `stream` 或 `hybrid` 都能通。两端各自决定自己发出去的包怎么分。走 datagram 的足额包和 datagram 模式一样，大约 1550 字节时会切成两片。

```yaml
l3tun:
  mode: hybrid
```

datagram 路径会记住路径能装下的最大 datagram，超过的包直接切片，不用每颗都先试一次再失败。每 256 颗需要切片的包会整包试一次，路径 MTU 变大以后能发现。

## 本机网卡

两端各开一张 `hytun0`。VXLAN 的 `local` / `remote` 用这两张网卡的地址。`/30` 自带直连路由。服务器的公网地址在这个网段之外，QUIC 不会绕回隧道。4789 留在隧道里面，公网防火墙不用放行。

```text
客户端 vx0
    |
客户端 hytun0  10.200.0.2/30  MTU 1600
    |
    QUIC
    |
服务端 hytun0  10.200.0.1/30  MTU 1600
    |
服务端 vx0
```

内层 MTU 1500 时，外层大约 1550 字节（IP 20 + UDP 8 + VXLAN 8 + 以太网 14），落在 1600 以内，内核不会再为这颗包分片。

### 客户端

```yaml
l3tun:
  name: hytun0
  mtu: 1600
  address: 10.200.0.2/30
  peer: 10.200.0.1
  mode: stream
```

`hytun0` 出现之后再加 VXLAN。`nolearning` 配上单个 `remote`，内层流量都发给这一台对端。

```bash
ip link add vx0 type vxlan id 500 dev hytun0 local 10.200.0.2 remote 10.200.0.1 dstport 4789 nolearning df unset
ip link set vx0 mtu 1500
ip addr replace 10.201.0.2/24 dev vx0
ip link set vx0 up
```

### 服务端

```yaml
l3tun:
  name: hytun0
  mtu: 1600
  address: 10.200.0.1/30
  peer: 10.200.0.2
  mode: stream
```

```bash
ip link add vx0 type vxlan id 500 dev hytun0 local 10.200.0.1 remote 10.200.0.2 dstport 4789 nolearning df unset
ip link set vx0 up
ip link set vx0 mtu 1500
ip addr replace 10.201.0.1/24 dev vx0
```

程序自己创建 `hytun0` 并配置 `address`。不要再手动加同一个地址。`name` 不能和已有网卡重名。`mtu` 省略时是 1600，不能大于 1600。`peer` 必须和 `address` 同一 IP 版本。

`filter` 省略时是 `vxlan`：从隧道收到的包，只有发往本端 `address`、UDP 目的端口 4789 的才会写进 `hytun0`（IPv4 的后续分片按地址和协议放行）。其它包一律丢掉，所以即使开了 `ip_forward`，对端也到不了这台机器能路由到的其它地方，比如云厂商的 metadata 地址或 VPC 内网。只有在 `hytun0` 上跑的不是 VXLAN 时，才写 `filter: none`。

### 谁能使用这条链路

服务端的 `l3tun.users` 列出可以使用 L3 的认证 ID，也就是 `userpass` 的用户名，或者 `http` 认证返回的 `id`。不在列表里的用户照常使用代理，但拿不到 L3。列表为空时，所有通过认证的用户都能用，启动时会打一条警告。`password` 认证下所有客户端的 ID 都是 `user`，这个列表不起作用，能用 L3 的就是知道密码的人。

```yaml
l3tun:
  users: [homelab]
```

同一对 `hytun0` 上可以再建 VNI 不同的网卡，内核按 VNI 分开，Hysteria 配置不用改：

```bash
ip link add vx1 type vxlan id 600 dev hytun0 local 10.200.0.2 remote 10.200.0.1 dstport 4789 nolearning df unset
```

重启服务端后，客户端的 L3 连接会自己重连，`hytun0` 保持不动。VXLAN 跟着内层流量恢复。先等 `hytun0`，再执行上面的 `ip link`。单元可以用 `After=hysteria` 的 oneshot。

### 本机同时当网关

局域网的下一跳可以是这台 Hysteria 客户端，而不是在路由器上再建一张 VXLAN。客户端把从 `eth0` 进来的内网包转发进 `vx0`，服务端在出口网卡上做 MASQUERADE。

客户端先把 QUIC 和网关钉在物理网卡上，再把默认路由放进隧道。顺序反了，QUIC 会绕进 `vx0`。

```bash
ip route replace 203.0.113.10/32 via 192.168.7.1 dev eth0
ip rule add to 192.168.7.1/32 lookup main priority 10
ip rule add to 203.0.113.10/32 lookup main priority 11

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.eth0.rp_filter=2
sysctl -w net.ipv4.conf.vx0.rp_filter=2
sysctl -w net.ipv4.conf.hytun0.rp_filter=2

ip route replace default via 10.201.0.1 dev vx0 metric 5
iptables -A FORWARD -i eth0 -o vx0 -j ACCEPT
iptables -A FORWARD -i vx0 -o eth0 -j ACCEPT
iptables -t mangle -A FORWARD -i vx0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -o vx0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

`203.0.113.10` 换成服务器的公网地址。DHCP 带来的默认路由留着，metric 设得比 5 大，隧道Down 了才用它。客户端不对隧道做 NAT，服务端因此能看见真实的内网地址。

服务端：

```bash
ip route replace 192.168.7.0/24 via 10.201.0.2 dev vx0
iptables -t nat -A POSTROUTING -s 192.168.7.0/24 -o ens4 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.201.0.0/24 -o ens4 -j MASQUERADE
```

路由器上给要走这条路的源地址单独一张表，默认网关写成这台客户端。去局域网的规则排在它前面，避免同网段也绕进隧道。客户端发往服务器的 QUIC 在路由器上只查 main，排在其它策略路由前面。

## 远程网卡

Hysteria 不创建 `hytun0`。它在 `relay.listen` 上收 UDP，把 VXLAN 载荷补成一颗外层 IPv4/UDP，再交给原来的 L3 通道。对端收到的包和从 `hytun0` 读出来的是同一种。隧道里的 UDP 目的端口固定是 4789。`name` 和 `mtu` 不使用。`address` 可以写前缀，也可以只写地址，必须和对端成对。

`listen` 写成这块网卡自己的地址，不要写 `0.0.0.0`。发回 VTEP 时，源地址就是它。监听端口可以不用 4789，这样本机还能留着一张内核 VXLAN。改端口时，VTEP 的 `dstport` 和 `vtep` 的端口一起改。

每个 VNI 对应一个 VTEP。表里没有的 VNI，两个方向都丢。从局域网进来的包，源地址必须等于该 VNI 的 `vtep`，或者落在 `allow` 里。回去的包总是发到配置的那个 `vtep`，不写端口时用 4789。一个 VNI 只写一个回程地址。换了发送 VXLAN 的机器，就要改两端的 `vtep`，然后按下面的热重载换表，不用重启。只改一边时，另一边仍按旧表转发。

外层 UDP 源端口不沿用 VTEP 原来的端口。有的 VTEP 所有流都用同一个端口，会挤进同一条 QUIC stream。中继按内层以太网帧里的 IP 流重新取源端口。

补出来的 IPv4 外层 UDP 校验和是 0（RFC 7348 允许），对端收到时也不检查校验和。这一段已经由 QUIC 加密和认证，再对 1.5 KB 的包算一遍校验和没有意义。IPv6 要求必须带校验和，所以照常计算。

```text
本地 VTEP
    |  UDP，目的是客户端 listen
客户端中继   外层头 10.200.0.2 -> 10.200.0.1:4789
    |
    QUIC
    |
服务端中继   按 VNI 交给各自的远端 VTEP
    |
远端 VTEP 1 、远端 VTEP 2
```

### 客户端

```yaml
l3tun:
  type: relay
  mode: stream
  address: 10.200.0.2/30
  peer: 10.200.0.1
  relay:
    listen: 192.168.7.62:4789
    vnis:
      - vni: 501
        vtep: 192.168.7.64
      - vni: 502
        vtep: 192.168.7.64
```

两个 VNI 可以共用一个 VTEP，也可以写成不同的 `vtep`。`allow` 用来放地址不固定的 VTEP，例如：

```yaml
      - vni: 501
        vtep: 192.168.7.64
        allow: [192.168.7.0/24]
```

客户端自己的 QUIC 仍要钉在物理网卡上，写法和本机网卡那一节相同。中继进程不持有默认路由，钉的是这台 Hysteria 主机，不是旁边那台 VTEP。

### 服务端

`address` / `peer` 对调。`listen` 用云主机上 Hysteria 能收到包的地址。每个远端 VTEP 一个 VNI。

```yaml
l3tun:
  type: relay
  mode: stream
  address: 10.200.0.1/30
  peer: 10.200.0.2
  relay:
    listen: 10.0.0.2:4789
    vnis:
      - vni: 501
        vtep: 198.51.100.10:4789
      - vni: 502
        vtep: 198.51.100.20:4789
```

服务端只做 L3 时，`acl` 用 `reject(all)`，这个端口不再做 TCP/UDP 代理。这段 VXLAN 在 QUIC 外面。走公网时，云厂商的防火墙要放行 UDP 4789。服务端和远端在同一个云内网时，只放行对端的内网地址，不要对公网放行。

### 热重载 VNI

`l3tun.relay.vnis` 可以在进程运行时换掉。QUIC 连接、L3 通道和 `relay.listen` 上的 UDP socket 都不动。表换掉之后，下一个包按新表转发；正在处理的那一颗包仍用旧表。

只有 `type: relay` 时进程才会接管 SIGHUP。其它配置下 SIGHUP 保持默认行为，进程会退出。

两端的 `hysteria-thv.service` 加上这一行，然后执行 `systemctl daemon-reload`：

```ini
ExecReload=/bin/kill -HUP $MAINPID
```

增加、删除、修改一个 VNI，或者只改某个 VNI 的 `vtep` / `allow`：

1. 两端的配置都改好 `vnis`。只改一边时，另一边仍按旧表转发，这条 VNI 不通。
2. 两端各执行 `systemctl reload hysteria-thv`。先后顺序不限。
3. 增加 VNI 时，两边 reload 完成后再在 VTEP 上执行 `ip link add`。删除时先拆掉 VTEP 上的网卡，再 reload。这样不会出现 VTEP 已经在发、中继表里还没有这条 VNI 的窗口。

配置读不出来，或者新表不合法（VNI 重复、超出 1 到 16777215、一条都没有），旧表继续用，日志里有错误。

`type`、`address`、`peer`、`mode`、`lanes`、`relay.listen` 不会热生效。这些字段变了仍要重启两端的 `hysteria-thv`。重载时如果发现它们变了，只记一条警告，进程里继续用启动时的值。

### 本地 VTEP

这台机器只跑内核 VXLAN，不跑 Hysteria。`remote` 指向客户端中继的 `listen`。`local` 必须等于客户端配置里的 `vtep`。`dstport` 和 `listen` 的端口一致。

Linux 上多张 VXLAN 可以共用 UDP 4789，按 VNI 分开。`nolearning` 加上单个 `remote` 之后，单播也发给这一个中继。

```bash
ip link add vxlan501 type vxlan id 501 dev eth0 local 192.168.7.64 remote 192.168.7.62 dstport 4789 nolearning df unset
ip link add vxlan502 type vxlan id 502 dev eth0 local 192.168.7.64 remote 192.168.7.62 dstport 4789 nolearning df unset
ip link set vxlan501 mtu 1410
ip link set vxlan502 mtu 1410
ip addr replace 10.88.15.2/24 dev vxlan501
ip addr replace 10.88.16.2/24 dev vxlan502
ip link set vxlan501 up
ip link set vxlan502 up

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.eth0.rp_filter=2
sysctl -w net.ipv4.conf.vxlan501.rp_filter=2
sysctl -w net.ipv4.conf.vxlan502.rp_filter=2

ip route replace default via 10.88.15.1 dev vxlan501 metric 5
iptables -A FORWARD -i eth0 -o vxlan501 -j ACCEPT
iptables -A FORWARD -i vxlan501 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o vxlan502 -j ACCEPT
iptables -A FORWARD -i vxlan502 -o eth0 -j ACCEPT
iptables -t mangle -A FORWARD -o vxlan501 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -i vxlan501 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -o vxlan502 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -i vxlan502 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

`192.168.7.62` 在 `eth0` 的直连网段里，所以发往中继的 UDP 不会跟默认路由进隧道。默认路由选其中一个 VNI 当上网出口，另一个 VNI 只靠自己的直连网段到达。DHCP 的默认路由保留，metric 大于 5。

路由器把使用者的源地址查到一张新表，默认网关写成这台 VTEP。去 `192.168.7.0/24` 的规则放在更前面。VTEP 的下一跳在 VXLAN 上，不在进来的那块网卡上，所以它不会让源主机改走直连。

### 远端 VTEP

远端也是内核 VXLAN，`remote` 写成它实际要发 UDP 的地址。服务端和远端在同一个云内网时，`remote` 和中继的 `vtep` 都写内网地址，不要对公网放行 4789。出口做了 NAT、只能走公网时，`remote` 才是 Hysteria 服务器的公网地址，中继的 `vtep` 写成服务器看见的源地址，并加一条主机路由把发往这台服务器的包留在物理网卡上。`local` 用远端自己的内网地址。

```bash
ip route replace 203.0.113.10/32 via 10.0.0.1 dev ens4
ip link add vx0 type vxlan id 501 dev ens4 local 10.0.0.2 remote 203.0.113.10 dstport 4789 nolearning df unset
ip link set vx0 mtu 1410
ip addr replace 10.88.15.1/24 dev vx0
ip link set vx0 up

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.ens4.rp_filter=2
sysctl -w net.ipv4.conf.vx0.rp_filter=2

ip route replace 192.168.7.0/24 via 10.88.15.2 dev vx0
iptables -I INPUT -p udp --dport 4789 -j ACCEPT
iptables -A FORWARD -i vx0 -j ACCEPT
iptables -A FORWARD -o vx0 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.88.15.0/24 -o ens4 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.7.0/24 -o ens4 -j MASQUERADE
iptables -t mangle -A FORWARD -i vx0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -o vx0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

第二个远端换 VNI、网段和 `local`。两边的内层地址要能对上：本地 `10.88.15.2` 的下一跳是远端 `10.88.15.1`，远端回 `192.168.7.0/24` 时下一跳是 `10.88.15.2`。

这些 `ip` 和 `iptables` 放进开机的 oneshot。只在 shell 里跑一次，重启后 VXLAN 和 NAT 都会消失。

### 远程网卡的 MTU

封装是 50 字节。内层 1500 会变成大约 1550，本机网卡模式下这颗包在 `hytun0` 的 1600 里面。远程网卡多了一跳 UDP：服务端中继把包发给远端 VTEP。这一跳的网卡要装得下 1550，VTEP 的 MTU 才能是 1500。网卡只有 1460 时，1550 会被丢掉或再分片，那一对 VTEP 只能用路径 MTU 减 50，也就是 1410。同一台云里的内网如果能把网卡放到 1600，内层就回到 1500。本地 VTEP 到中继的那块网卡也同样，至少 1550，否则内核不让把 VXLAN 设成 1500。

确认时用不允许分片的 ping。1410 字节的 IP 包，ICMP 载荷是 1382：

```bash
ping -M do -s 1382 -c 3 10.88.15.1
ping -M do -s 1472 -c 3 10.88.15.1
```

1382 通、1472 不通，说明 MTU 卡在 1410，而不是隧道本身只有这么大。

局域网是 1500、VTEP 又把 DF 关掉时，大约 1550 字节的 VXLAN 会在到达中继之前被分成 IP 分片，内核会先拼回去。中继往回送时，Linux 上把 `IP_MTU_DISCOVER` 设成不禁止分片。VTEP 和中继之间能开到 1600 以上，就不必依赖分片。

### RouterOS 当 VTEP

`remote-ip` 只决定泛洪发给谁，单播靠学习，所以不要把 `learning` 关掉。`local-address` 必须等于中继配置里的 `vtep`。`port` 同时用于监听和发送。同一 VRF 里多张 VXLAN 可以共用 4789。

```routeros
/interface vxlan
add name=vxlan501 vni=501 port=4789 local-address=192.168.7.1 dont-fragment=disabled mtu=1410
/interface vxlan vteps
add interface=vxlan501 remote-ip=192.168.7.62
```

`dont-fragment=disabled` 会让支持硬件卸载的设备改走慢路径。实测同一帧会从路由器出去两次，相隔约 1 微秒，两个 VNI 都这样。中继只是原样转发，iperf 的 UDP 丢包比例会被重复包算乱。单个 `remote` 的这一跳用上面的 Linux VTEP：`nolearning` 每个内层包只发一份。

## 客户端和服务器的四种配法

`address` 和 `peer` 始终成对。下面只列隧道段，监听、认证、TLS、带宽保持原有写法。

| 客户端 | 服务端 | VXLAN 放在 |
| --- | --- | --- |
| `tun` | `tun` | 两端都在 Hysteria 本机的 `hytun0` 上 |
| `relay` | `tun` | 客户端交给局域网 VTEP，服务端在 `hytun0` 上终结 |
| `tun` | `relay` | 客户端在 `hytun0` 上发出，服务端交给自己的 VTEP |
| `relay` | `relay` | 两端各自交给自己的 VTEP。一条 QUIC 上可以有多个 VNI |

客户端中继、服务端本机网卡：

```yaml
# 客户端
l3tun:
  type: relay
  mode: stream
  address: 10.200.0.2/30
  peer: 10.200.0.1
  relay:
    listen: 192.168.7.62:4789
    vnis:
      - vni: 500
        vtep: 192.168.7.64

# 服务端
l3tun:
  name: hytun0
  mtu: 1600
  address: 10.200.0.1/30
  peer: 10.200.0.2
  mode: stream
```

服务端的 `vx0` 仍建在 `hytun0` 上，`local 10.200.0.1 remote 10.200.0.2`。它看见的外层包就是中继补出来的那一颗。

客户端本机网卡、服务端中继：把上面两段对调。客户端的 `vx0` 建在 `hytun0` 上。服务端按 VNI 把包发给 `vtep`。

字段：

| 字段 | 本机网卡 | 远程网卡 |
| --- | --- | --- |
| `name` | TUN 名称 | 不使用 |
| `mtu` | 省略为 1600，上限 1600 | 不使用 |
| `address` | 本端前缀，程序配置到网卡上 | 写进外层 IP 头，前缀或单个地址 |
| `peer` | 对端地址 | 外层 IP 的目的地址，和对端 `address` 成对 |
| `mode` | `datagram`、`stream` 或 `hybrid` | 相同 |
| `relay.listen` | 无 | 本机网卡地址加端口 |
| `relay.vnis[].vni` | 无。VNI 由内核 VXLAN 区分 | 1 到 16777215，不能重复 |
| `relay.vnis[].vtep` | 无 | 这个 VNI 的回程 `主机:端口`，端口可省略 |
| `relay.vnis[].allow` | 无 | 除 `vtep` 之外还接受的源前缀 |
| `filter` | `vxlan`（默认）或 `none` | 不使用，中继总是只收 VXLAN |
| `users` | 仅服务端：可以使用 L3 的认证 ID，空表示全部 | 相同 |

写入本机 TUN 之前，会核对 IP 源地址等于 `peer`，默认还要求包是发往本端 `address`、端口 4789 的 UDP。中继下行同样核对：外层源是 `peer`，目的是本端 `address`，UDP 目的端口 4789，并且 VNI 在表里。服务端只绑定一个 L3 连接，规则见开头。没有对端时，从本机读到的包直接丢弃。流量计入现有的 `TrafficLogger`，方向和 UDP 代理一致。

## 验证

本机网卡，在客户端：

```bash
ping -M do -s 1472 -c 3 10.201.0.1
```

1472 字节载荷加上内层 IP 头是 1500。通了，说明 1600 的隧道装得下整颗 VXLAN。

远程网卡，在本地 VTEP 上分别打两个内层地址，再从走策略路由的那台主机看出口：

```bash
ping -c 3 10.88.15.1
ping -c 3 10.88.16.1
ping -M do -s 1382 -c 3 10.88.15.1
curl -4 https://ifconfig.me
```

吞吐：

```bash
# 远端 VTEP
iperf3 -s -B 10.88.15.1 -p 5201

# 本地 VTEP 或策略路由后面的主机
iperf3 -c 10.88.15.1 -t 10
iperf3 -c 10.88.15.1 -u -b 40M -t 10
iperf3 -c 10.88.15.1 -u -b 40M -t 10 -R
```

帧被复制时，UDP 的接收报文数会多于发送数，iperf 的丢包百分比不能当丢包。看发送端自己的丢失计数，以及接收速率有没有高于发送速率。TCP 的接收速率和重传次数仍然可用。
