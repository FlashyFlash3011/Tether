# Tether

A lightweight personal VPN that connects two machines without exposing any ports, using no VPS, and staying completely free.

Built to connect a MacBook(M-series) to a PC running WSL2/Linux for remote GPU work over SSH.

## How it works

```
Mac ──── WireGuard ──── relay client ──── WebSocket (WSS)
                                                │
                                       Cloudflare network
                                                │
PC  ──── WireGuard ──── relay server ──── cloudflared tunnel
```

1. **Coordination** — A Cloudflare Worker stores each node's public key and endpoint in KV. Nodes register on startup and sync peers every 30 seconds.

2. **WireGuard** — Userspace WireGuard handles all traffic between nodes. Everything is end-to-end encrypted.

3. **Relay** — The PC exposes a UDP↔WebSocket bridge via a `cloudflared` quick tunnel. The Mac connects over WebSocket. WireGuard packets flow through transparently — no open ports required on either machine.

4. **Auth** — Nodes authenticate to the Worker with short-lived HMAC-HS256 JWTs. A WireGuard PSK adds post-quantum resistance.

## Stack

- **Go** — WireGuard userspace, relay bridge, agent daemon
- **Cloudflare Workers + KV** — peer coordination (free tier)
- **cloudflared** — outbound-only tunnel
- **WireGuard** — encrypted VPN layer

## Setup

Run `tether` and it will guide you through the setup.
