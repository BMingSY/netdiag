# netdiag

`netdiag` is a small home-network diagnostic tool for this path:

```text
PC -> WiFi/router -> optical modem/ONT -> ISP -> public internet
```

It samples each layer with `ping`, writes CSV, then prints a diagnosis based on packet loss, p95 latency, jitter, and latency increase between layers.

It also writes a self-contained HTML report next to the CSV. The report includes the diagnosis, target list, summary table, p95 bars, and per-sample details.

## Build

```bash
cd ~/netdiag
go build -o netdiag .
```

## Quick run

```bash
cd ~/netdiag
./netdiag -duration 5m
```

By default it automatically detects your default gateway as the `PC -> WiFi/router` target and also pings several public DNS IPs.

## Better run with modem and ISP targets

If your router can reach the optical modem management IP, add it:

```bash
./netdiag -duration 10m -modem 192.168.1.1
```

If you know the ISP first-hop gateway, add it too:

```bash
./netdiag -duration 10m -modem 192.168.1.1 -isp 10.4.32.1
```

You can usually find the ISP hop with `traceroute`, `mtr`, or from your router status page.

## How to read the result

- Bad `router`: likely PC WiFi signal, WiFi interference, PC wireless card, or router LAN/WiFi side.
- Good `router` but bad `modem`: likely router-to-optical-modem link, router WAN port/cable, or optical modem LAN side.
- Good `router/modem` but bad `isp`: likely optical line, PPPoE/access network, or ISP first hop.
- Good local hops but bad public targets: likely ISP backbone, peering, DNS/public route, or remote network.

CSV output is written to `result/netdiag-<timestamp>.csv` unless `-out` is provided.
HTML output is written to `result/netdiag-<timestamp>.html` unless `-html` is provided.
