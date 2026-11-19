# Experimental opt-in connection pool

This proposal adds `client.NewReconnectableClientPool(configFunc, connectedFunc, lazy, size)` and an opt-in client-mode YAML setting. Existing constructors and defaults remain unchanged. API/configuration shape and congestion-control policy need maintainer agreement in [#1431](https://github.com/HyNetworks/hysteria/issues/1431).

```yaml
quic:
  connectionPoolSize: 2
```

Supported values are 1..8; omitted or 0 means one connection. Use 2 or 3 to opt in. The setting applies to `hysteria client`, including its SOCKS5, HTTP, forwarding, TPROXY and TUN modes. Realm mode rejects sizes greater than 1. The built-in single-stream `speedtest` command is unchanged, and share URIs do not encode this local setting. More connections consume additional resources and do not bond an individual stream.

- Size 1 delegates to the existing reconnectable client. Sizes 2 through 8 create independent reconnectable QUIC connections; the upper bound is a resource guard, not a recommendation.
- New TCP streams and Hysteria UDP sessions are assigned round-robin. Existing streams/sessions remain on their selected connection. A failed open is returned to the caller; there is no transparent replay, migration, packet striping or single-stream speedup.
- Lazy mode opens each connection on its first selected flow. Eager initialization fails as a whole and closes already initialized members if a later member cannot initialize.
- Config evaluation and success callbacks are serialized within the pool. The success callback receives the connected member and a pool-wide count of successful handshakes, including initial connections and reconnects. A custom connection factory must provide independent packet connections and support concurrent members.
- Nonzero client bandwidth targets are split statically and evenly. Remainders are assigned in bytes/s so the member targets sum to the configured target. Zero targets remain zero. Idle members' allocations are not redistributed. This does not implement a shared limiter or guarantee the aggregate wire rate; loss compensation and server-side per-connection limits still apply.
- `Close` closes all members, aggregates errors, waits for concurrent closes and is idempotent. Established flow ownership remains with each underlying reconnectable client.

## Review status

The inherited transport-cleanup fix [#1696](https://github.com/HyNetworks/hysteria/pull/1696) is a merge prerequisite, kept separate from this proposal. API shape and static congestion targets still need maintainer agreement. Tests cover sizes 1/2/3/8, eager/lazy startup, Chrome parroting on/off, TCP/UDP, fragmentation and member recovery.

A [pool-only benchmark](CONNECTION_POOL_BENCHMARK.md) measured +28.4% median download on MT7981, but observed loss and UDP memory errors. It does not establish long-term stability or justify a new default. No server, quic-go, OpenWrt or overclock changes are included.
