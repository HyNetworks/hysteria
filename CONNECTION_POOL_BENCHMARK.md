# Pool-only benchmark

Three alternating 1/2-connection pairs on 2026-10-13, using the same Ookla
server (50771, Frankfurt) and wired LAN -> TPROXY path. Same upstream quic-go,
binary and settings: aggregate Brutal 450/450 Mbps, default 8/20 MiB receive
windows per member, nice -5, `GOMEMLIMIT=64MiB`, packet steering 0.
A private thin CLI adapter called the proposed core API; no GRO/recycling,
queue/batch or server changes were included.

Hardware: Cudy WR3000S / MT7981, OpenWrt 25.12.5, Linux 6.12.94.
The existing **1700 MHz runtime OC was unchanged**. Cached CCF initially
misreported 1300 MHz; post-run live registers confirmed 1700 MHz, but were not
sampled per trial. These are not stock-clock measurements.

| Metric | 1 connection | 2 connections |
| --- | ---: | ---: |
| Download median | 271.37 Mbps | 348.53 Mbps |
| Upload median | 410.27 Mbps | 409.13 Mbps |
| Download loaded latency median (Ookla IQM) | 213.59 ms | 140.81 ms |
| Upload loaded latency median (Ookla IQM) | 87.53 ms | 92.90 ms |
| Loaded CPU mean | 84.77% | 92.12% |
| Peak RSS / minimum MemAvailable | 71.19 / 47.47 MiB | 68.11 / 59.16 MiB |
| Maximum temperature | 68.5 C | 68.5 C |

Download samples (Mbps): **258.60, 271.37, 320.88** versus
**348.19, 360.40, 348.53**. Median download increased **28.4%**; loaded CPU
increased **7.35 percentage points**. Ordinary light background traffic remained.

## Limits

One pooled run added **2354 kernel UDP MemErrors** and **0.58% Ookla packet
loss**. Pooled ICMP missed 2/70 replies versus 0/75. Two isolated DNS health
timeouts occurred under load; post-trial TCP/UDP DNS and routing checks passed.
UDP receive/send buffer errors and WAN drop deltas were zero, with no OOM,
direct reclaim or guard rollback in these six runs. Guards were not weakened.

These short tests do not prove loss-free or long-term stability, identify the
affected flow, or promise a universal speedup. An aborted tmpfs attempt and a
launcher-error warm-up were excluded. Original router configuration and binary
were restored; raw artifacts remain private because they contain machine metadata.
