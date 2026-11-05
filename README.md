<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

# Pivot

**Secure IP-layer network relay for multi-hop vulnerability scanning.** Gives scanner servers full native access — raw sockets, ICMP, UDP — to target LAN segments through a relay device that is physically connected to those segments, without the protocol limitations of a SOCKS proxy.

```
┌──────────────────┐  TLS+HMAC   ┌─────────────────────────┐  LAN   ┌──────────────────┐
│  Scanner Server  │◄───────────►│  Relay Device            │◄──────►│  Target Network  │
│  (Kali / macOS)  │   port 5200  │  pivot-agent             │        │  10.0.0.0/24     │
│  pivot-client    │             │  tun0: 192.168.1.5 (VPN) │        │  hosts, cameras, │
│  nmap, Nessus…   │             │  eth0: 10.0.0.x  (LAN)   │        │  PLCs, printers  │
└──────────────────┘             └─────────────────────────┘        └──────────────────┘
```

The relay device uses `iptables MASQUERADE` to forward scan traffic from the VPN interface to the target LAN. Scans appear to originate from the relay's LAN IP — nmap, Nessus, OpenVAS, and all other tools work without modification or proxy configuration.

---


> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/pivot)** — detailed features, CLI reference, findings catalogue, and integration guides.

## Features

- **IP-layer relay, not SOCKS** — raw sockets, ICMP, UDP, and OS fingerprinting all work at full fidelity
- **Relay chaining** — reach networks N hops away; chain depth is unlimited with independent security per link
- **Multiple network profiles** — expose several subnets simultaneously in a single session
- **TLS 1.2+ transport** — TLS 1.3 preferred; hardened cipher list excludes NULL, export-grade, DES, RC4, MD5, and anonymous DHE
- **HMAC-SHA256 authentication** — per-connection nonce prevents replay attacks; constant-time comparison resists timing side-channels
- **Optional mutual TLS (mTLS)** — require scanner to present a client certificate signed by the relay's CA
- **IP allowlist** — restrict which peers can connect to the relay, beyond token authentication
- **Clean state restoration** — all iptables rules and the `ip_forward` sysctl are tagged per session and removed on disconnect, SIGTERM, SIGINT, or `atexit`
- **Heartbeat-based session expiry** — sessions close automatically if the client goes silent
- **systemd service installer** — ships with a hardened unit file (`CAP_NET_ADMIN`, `CAP_NET_RAW` only; no new privileges)
- **Asyncio server** — handles multiple concurrent sessions without threads on the agent side
- **No shell injection** — all subprocess calls use explicit argument lists (`shell=False`)

---

## Requirements

| Component | Platform | Privileges |
|-----------|----------|------------|
| `pivot-agent` (relay device) | Linux — Kali, Ubuntu 20.04+ | **root** or `CAP_NET_ADMIN` + `CAP_NET_RAW` |
| `pivot-client` (scanner server) | Linux or macOS | **root / sudo** (for `ip route` / `route add`) |

- Python 3.8+ on both machines
- `iptables` on the relay device
- TCP port 5200 open from scanner to relay (configurable)

### Python dependencies

```
PyYAML>=6.0
cryptography>=41.0.0
```

```bash
pip install .
```

---

## Installation

Install on both the relay device and the scanner server:

```bash
git clone https://github.com/your-org/pivot.git
cd pivot
pip install .
```

This registers two console scripts: `pivot-agent` and `pivot-client`.

---

## Quick Start

### 1. Generate TLS certificates (on the relay device)

```bash
sudo bash tools/pivot-gen-certs.sh /etc/pivot/certs pivot-agent 192.168.1.5
```

Generates a self-signed CA, a 4096-bit RSA agent certificate with DNS + IP SANs, and an optional client certificate for mTLS. Copy `ca.crt` to the scanner machine.

| File | Distribute to |
|------|---------------|
| `ca.crt` | Both machines |
| `agent.crt`, `agent.key` | Relay device only |
| `client.crt`, `client.key` | Scanner machine (mTLS only) |

Store `ca.key` offline after generation — it is not needed at runtime.

### 2. Configure and start the agent (relay device)

```bash
sudo cp config/pivot-agent.yaml.example /etc/pivot/agent_config.yaml
sudo nano /etc/pivot/agent_config.yaml   # set auth_token, target_cidr, interfaces
sudo pivot-agent --config /etc/pivot/agent_config.yaml
```

Or install as a systemd service (auto-start on boot):

```bash
sudo bash tools/pivot-install-service.sh
sudo systemctl start pivot-agent
sudo journalctl -u pivot-agent -f
```

### 3. Configure and start the client (scanner server)

```bash
sudo cp config/pivot-client.yaml.example /etc/pivot/client_config.yaml
sudo nano /etc/pivot/client_config.yaml  # set relay.host, auth_token, cafile
sudo pivot-client --config /etc/pivot/client_config.yaml
```

While `pivot-client` is running, OS routes to the target CIDR are active on the scanner:

```bash
# Linux — route added automatically:
ip route show | grep 10.0.0.0

# macOS — route added automatically:
netstat -rn | grep 10.0.0
```

### 4. Scan

```bash
nmap -sS -sV -O 10.0.0.0/24
# or
nessus-cli scan --target 10.0.0.0/24
```

Press **Ctrl-C** on the client when done. Routes are removed and the relay session closes cleanly.

---

## Configuration Reference

### Agent (`pivot-agent.yaml`)

```yaml
# ── Listener ──────────────────────────────────────────────────────────────────
relay:
  bind_address: "0.0.0.0"   # Interface to listen on
  port: 5200                  # Control port (must match client)

# ── Security ──────────────────────────────────────────────────────────────────
security:
  # Generate with: openssl rand -hex 32
  auth_token: "REPLACE_WITH_LONG_RANDOM_SECRET"

  tls:
    enabled: true
    certfile: "/etc/pivot/certs/agent.crt"
    keyfile:  "/etc/pivot/certs/agent.key"
    cafile:   "/etc/pivot/certs/ca.crt"    # Required only for mTLS
    require_client_cert: false              # Set true to enforce mTLS

  # Optional: restrict which scanner IPs can connect (beyond token auth)
  allowed_peers:
    # - "192.168.1.10"

# ── Network Profiles ──────────────────────────────────────────────────────────
networks:
  - name: "site-a"
    target_cidr: "10.0.0.0/24"   # Target LAN subnet
    egress_interface: "eth0"       # Interface facing the target LAN
    vpn_interface: "tun0"          # Interface connected to VPN / scanner

# ── Session ───────────────────────────────────────────────────────────────────
session:
  heartbeat_timeout: 90   # Close session if no heartbeat within N seconds
  max_sessions: 5          # Maximum concurrent relay sessions

# ── Logging ───────────────────────────────────────────────────────────────────
logging:
  level: "INFO"                       # DEBUG | INFO | WARNING | ERROR
  file: "/var/log/pivot/agent.log"    # Omit for stdout only
  max_bytes: 10485760                 # Rotate at 10 MB
```

### Client (`pivot-client.yaml`)

```yaml
relay:
  host: "192.168.1.5"   # Relay device's VPN IP (reachable from scanner)
  port: 5200

security:
  auth_token: "REPLACE_WITH_LONG_RANDOM_SECRET"   # Must match agent exactly

  tls:
    enabled: true
    cafile: "/etc/pivot/certs/ca.crt"    # CA that signed the agent cert
    certfile: ""                          # Client cert (mTLS only)
    keyfile:  ""                          # Client key (mTLS only)
    server_hostname: "pivot-agent"        # Must match agent cert CN / SAN
    verify_hostname: true

# Which profiles to activate. Empty = activate all profiles on the agent.
activate_networks: []

client_id: "scanner-01"      # Appears in agent audit log

# Timing
connect_timeout: 10           # TCP connection timeout (seconds)
operation_timeout: 30         # Protocol message timeout (seconds)
heartbeat_interval: 30        # Must be < agent's heartbeat_timeout

logging:
  level: "INFO"
  file: ""
```

---

## CLI Reference

### `pivot-agent`

```
pivot-agent --config FILE [--verbose]
```

| Flag | Description |
|------|-------------|
| `--config FILE` / `-c` | Path to agent YAML configuration (required) |
| `--verbose` / `-v` | Override config log level with DEBUG |

Requires root or `CAP_NET_ADMIN` + `CAP_NET_RAW`. Exits immediately with a clear message if run without sufficient privileges.

### `pivot-client`

```
pivot-client --config FILE [--verbose]
```

| Flag | Description |
|------|-------------|
| `--config FILE` / `-c` | Path to client YAML configuration (required) |
| `--verbose` / `-v` | Override config log level with DEBUG |

Warns (non-fatal) if run without root/sudo; route installation will fail without it.

---

## Protocol

All messages are JSON objects framed with a 4-byte big-endian length prefix, transmitted over TLS 1.2+ on TCP port 5200. Maximum message size: 1 MB.

```
┌──────────────┬──────────────────────────────────────────────────────────────┐
│ 4 bytes      │ N bytes                                                       │
│ length (BE)  │ JSON payload  {"type": "AUTH", ...}                           │
└──────────────┴──────────────────────────────────────────────────────────────┘
```

| Message | Direction | Purpose |
|---------|-----------|---------|
| `AUTH` | Client → Agent | Nonce + HMAC-SHA256 digest of the shared secret |
| `AUTH_RESPONSE` | Agent → Client | Accept (session ID) or reject |
| `ACTIVATE` | Client → Agent | Request activation of named network profiles |
| `ACTIVATE_RESPONSE` | Agent → Client | Activated profile list + relay VPN IPs for route installation |
| `HEARTBEAT` | Client → Agent | Keep session alive |
| `HEARTBEAT_ACK` | Agent → Client | Acknowledge heartbeat |
| `STATUS` | Client → Agent | Query current session state |
| `STATUS_RESPONSE` | Agent → Client | Session state snapshot |
| `DEACTIVATE` | Client → Agent | Shut down session cleanly |
| `DEACTIVATE_RESPONSE` | Agent → Client | Confirm deactivation |
| `ERROR` | Either → Either | Protocol error with code and reason |

**Authentication flow:** The client sends a random 64-hex nonce in `AUTH`. The agent verifies `HMAC-SHA256(secret, nonce)` using constant-time comparison. The nonce ensures each `AUTH` message produces a unique digest, preventing replay of captured traffic.

---

## Kernel State (per session, per profile)

The agent installs three iptables rules and one sysctl change per active network profile, all tagged with the session ID for precise cleanup:

```
# Enable IP forwarding (ref-counted; original value restored on last session close)
net.ipv4.ip_forward = 1

# Allow VPN → LAN forwarding
-A FORWARD -i tun0 -o eth0 -d 10.0.0.0/24 -j ACCEPT -m comment --comment "pivot-<session>"

# Allow established/related return traffic
-A FORWARD -i eth0 -o tun0 -m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment "pivot-<session>"

# NAT: rewrite source IP so scans originate from the relay's LAN IP
-t nat -A POSTROUTING -o eth0 -d 10.0.0.0/24 -j MASQUERADE -m comment --comment "pivot-<session>"
```

All rules are removed on clean disconnect, SIGTERM, SIGINT, and `atexit` (emergency cleanup).

---

## Relay Chaining

Reach networks that are 2 or more hops away. Each relay needs to reach only its direct next hop.

```
Scanner → [VPN] → Relay A → [LAN A–B] → Relay B → [LAN B] → Target 10.1.0.0/24
```

### How activation works

1. Scanner sends `ACTIVATE` to **Relay A**
2. Relay A spawns a `ChainConnector` (an internal pivot-client) and connects to **Relay B**
3. Relay B activates its direct profile, returns `relay_vpn_ip = 10.0.5.10`
4. Relay A installs a kernel route: `10.1.0.0/24 via 10.0.5.10`
5. Relay A installs its own iptables rules (VPN → egress toward Relay B)
6. Relay A responds to the scanner with its own VPN IP
7. Scanner installs route: `10.1.0.0/24 via relay_a_vpn_ip` — scanning begins

On disconnect, cleanup propagates back through the chain in reverse order.

### Chained profile configuration (Relay A)

```yaml
networks:
  - name: "site-b-via-relay-b"
    target_cidr: "10.1.0.0/24"
    egress_interface: "eth1"         # Faces Relay B's network
    vpn_interface: "tun0"            # Where scanner traffic arrives

    upstream:
      host: "10.0.5.10"             # Relay B's IP (reachable from eth1)
      port: 5200
      auth_token: "relay-b-secret"  # Relay B's token — NOT Relay A's
      tls:
        enabled: true
        cafile: "/etc/pivot/certs/relay-b-ca.crt"
        server_hostname: "relay-b"
        verify_hostname: true
      activate_networks: ["site-b"] # Empty = activate all on Relay B
      client_id: "relay-a-chain"
      connect_timeout: 30
      operation_timeout: 60
      heartbeat_interval: 30
```

**Relay B** uses a standard direct profile — no changes needed.

**Scanner** connects to Relay A only — no knowledge of the chain is required.

### 3-hop chain

For Scanner → A → B → C → Target:
- Relay C: direct profile for the final target LAN
- Relay B: chained profile with `upstream` → Relay C
- Relay A: chained profile with `upstream` → Relay B
- Scanner: connects to Relay A only

### Security per link

Each link in the chain is independently secured. The scanner ↔ Relay A link uses Relay A's `auth_token` and TLS certificate. The Relay A ↔ Relay B link uses Relay B's `auth_token` and a separate CA. Each relay can independently require mTLS. Generate separate certificates for each relay with `tools/pivot-gen-certs.sh`.

---

## Security

| Property | Implementation |
|----------|---------------|
| **Transport encryption** | TLS 1.2 minimum (TLS 1.3 preferred); TLS compression disabled (CRIME) |
| **Cipher hardening** | Excludes `!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!ADH:!3DES` |
| **Authentication** | HMAC-SHA256 over a per-connection nonce — no replay possible |
| **Timing attack resistance** | `hmac.compare_digest` (constant-time) for all token verification |
| **Mutual TLS** | Optional per relay — `require_client_cert: true` + `cafile` |
| **IP allowlist** | `security.allowed_peers` restricts connecting IPs after TLS handshake |
| **Input validation** | All CIDR/IP strings validated with `ipaddress` before use |
| **No shell injection** | All subprocess calls use explicit argument lists (`shell=False`) |
| **State cleanup** | `atexit`, SIGINT, and SIGTERM handlers guarantee iptables removal |
| **Minimal footprint** | Agent needs only `CAP_NET_ADMIN` + `CAP_NET_RAW`; no kernel modules |

---

## Project Structure

```
pivot/
├── pivot/
│   ├── common/
│   │   ├── protocol.py        4-byte length-prefixed JSON framing + MsgType enum
│   │   ├── crypto.py          HMAC-SHA256 auth, TLS context builders
│   │   └── logging_setup.py   Rotating file + console logging
│   ├── agent/
│   │   ├── config.py          AgentConfig dataclass + YAML loader/validator
│   │   ├── network_manager.py iptables, sysctl, kernel routes (thread-safe)
│   │   ├── session_manager.py Session lifecycle, heartbeat expiry
│   │   ├── chain_connector.py Internal pivot-client for chained hops
│   │   ├── server.py          Asyncio TLS server + connection handlers
│   │   └── main.py            CLI entry point, privilege check, signal handling
│   └── client/
│       ├── config.py          ClientConfig dataclass + YAML loader/validator
│       ├── route_manager.py   Cross-platform route add/remove (Linux + macOS)
│       ├── connection.py      TLS connect, auth, activate, heartbeat loop
│       └── main.py            CLI entry point, privilege warning, signal handling
├── config/
│   ├── pivot-agent.yaml.example
│   └── pivot-client.yaml.example
├── tools/
│   ├── pivot-gen-certs.sh         Self-signed CA + leaf cert generation (openssl)
│   └── pivot-install-service.sh   systemd unit installer
├── requirements.txt
└── setup.py
```

---

## Troubleshooting

**Scans time out / no response from hosts**
- Check that `pivot-client` is running and shows "Relay is ACTIVE"
- Verify the route exists on the scanner: `ip route show` (Linux) or `netstat -rn` (macOS)
- Confirm `net.ipv4.ip_forward=1` on the relay: `sysctl net.ipv4.ip_forward`
- Check iptables rules: `sudo iptables -L FORWARD -n -v && sudo iptables -t nat -L POSTROUTING -n -v`

**Chained relay not reaching target**
- Verify `net.ipv4.ip_forward=1` on every relay in the chain
- Check the kernel route was installed on each intermediate relay: `ip route show`
- Confirm `egress_interface` on each relay faces the *next hop*, not the final target
- Use `--verbose` on each relay to trace the activation sequence
- Verify `upstream.auth_token` matches the *next* relay's `security.auth_token`, not the current relay's

**Authentication rejected**
- Confirm `security.auth_token` matches exactly on both agent and client configs
- For chained profiles, confirm `upstream.auth_token` matches the upstream relay's token

**TLS errors**
- Ensure `ca.crt` on the client was generated by the same CA that signed `agent.crt`
- Confirm `security.tls.server_hostname` in the client config matches the CN or SAN in `agent.crt`

**Route permission denied**
- Linux: run `pivot-client` with `sudo`
- macOS: run with `sudo pivot-client ...`

---

## License

MIT

---

## Contributors

Pivot is built entirely on Python standard library modules and a small set of pip packages. Full credit to their authors.

### Python Standard Library Modules

| Module | Author / Organisation | Link |
|--------|-----------------------|------|
| asyncio | Python Software Foundation | https://docs.python.org/3/library/asyncio.html |
| ssl | Python Software Foundation | https://docs.python.org/3/library/ssl.html |
| json | Python Software Foundation | https://docs.python.org/3/library/json.html |
| struct | Python Software Foundation | https://docs.python.org/3/library/struct.html |
| hmac | Python Software Foundation | https://docs.python.org/3/library/hmac.html |
| hashlib | Python Software Foundation | https://docs.python.org/3/library/hashlib.html |
| subprocess | Python Software Foundation | https://docs.python.org/3/library/subprocess.html |
| ipaddress | Python Software Foundation | https://docs.python.org/3/library/ipaddress.html |
| socket | Python Software Foundation | https://docs.python.org/3/library/socket.html |
| signal | Python Software Foundation | https://docs.python.org/3/library/signal.html |
| logging | Python Software Foundation | https://docs.python.org/3/library/logging.html |
| platform | Python Software Foundation | https://docs.python.org/3/library/platform.html |

### Python Pip Packages

| Package | Author / Organisation | Link |
|---------|-----------------------|------|
| PyYAML | Kirill Simonov / yaml/pyyaml contributors | https://github.com/yaml/pyyaml |
| cryptography | The Python Cryptographic Authority (PyCA) | https://github.com/pyca/cryptography |

### System Tools

| Tool | Author / Organisation | Handle | Link |
|------|-----------------------|--------|------|
| iptables | Netfilter Project / Harald Welte | @laforge | https://www.netfilter.org |
| ip (iproute2) | Stephen Hemminger / iproute2 contributors | — | https://github.com/iproute2/iproute2 |
| openssl | OpenSSL Project | — | https://github.com/openssl/openssl |
| systemd | Lennart Poettering / systemd contributors | @poettering | https://github.com/systemd/systemd |
