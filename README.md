# ALE Stellar External Captive Portal + RADIUS  
**MAC Authentication (MAB) with Cache – Lab Implementation**

This project implements an **External Captive Portal** and **RADIUS server** for  
**Alcatel-Lucent Enterprise (ALE) Stellar Access Points**, designed for **lab testing, validation, and learning**.

The Stellar AP acts as **gateway, traffic blocker, and redirector**.  
This server makes **authentication decisions** and hosts the **captive portal and admin UI**.

---

## Architecture Overview

```
Client
  ↓
Stellar AP (Gateway)
  ├─ MAC Authentication (RADIUS)
  │     ├─ Access-Accept → Client online
  │     └─ Access-Reject → Redirect to portal
  │
  └─ External Captive Portal (HTTP)
        └─ User registers → MAC cached → reconnect → MAB succeeds
```

---

## Components

### Server
- Python 3
- Flask (captive portal + admin UI)
- pyrad (RADIUS server)
- SQLite (state and logs)

### Network
- ALE Stellar AP (Standalone or OmniVista mode)
- RADIUS Authentication: UDP/1812
- RADIUS Accounting: UDP/1813
- Portal: HTTP (port 80 or 8080)

---

## Features

### RADIUS
- MAC Authentication (MAB)
- Portal authentication phase
- MAC allowlist
- Time-based MAC cache
- Accounting (Start / Interim / Stop)
- NAS-IP and NAS-Identifier logging
- Structured logging (SQLite + JSONL)

### Captive Portal
- ALE external captive portal (`/login/ale`)
- Displays all variables received from the AP
- Displays variables sent back to the AP
- Editable:
  - Success URL
  - On-error URL
- Auto-POST back to AP captive endpoint

### Admin UI
Available at:

```
/admin
```

Features:
- View allowlist
- View MAC cache (with expiry)
- View recent events
- Remove MAC from allowlist
- Remove MAC from cache
- Clear cache
- **Expire cache now** (keeps rows, forces re-portal)
- Clear events
- Human-readable timestamps (local browser timezone)
- Expired cache entries highlighted

An optional admin token can be configured in `config.py`.

---

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Running the Lab

```bash
./run.sh
```

This will:
- initialize the database
- start the RADIUS server
- start the captive portal and admin UI

---

## Verifying Services Are Listening

After starting the lab, verify that the services are bound to their ports.

### Check listening ports (recommended)

```bash
sudo ss -ltnup | grep -E ':(80|1812|1813)\s'
```

Expected:
- UDP 1812 → RADIUS authentication
- UDP 1813 → RADIUS accounting
- TCP 80   → Captive portal / admin UI

### Check processes directly

```bash
ps aux | grep -E 'app.py|radius_server.py' | grep -v grep
```

---

## Stellar AP Configuration

### External Captive Portal
```
http://<PORTAL_IP>/login/ale
```

### RADIUS
- Server IP: `<RADIUS_IP>`
- Shared secret: `sharedsecret`
- Auth port: `1812`
- Acct port: `1813`

### Other Settings
- Enable **MAC Authentication**
- Configure:
  - Pre-Login Role (used on Access-Reject)
  - Final Role (used on Access-Accept)

---

## Testing (from the AP)

```bash
curl -v "http://<PORTAL_IP>/login/ale?\
clientmac=AA:BB:CC:DD:EE:FF&\
clientip=192.168.50.23&\
switchmac=11:22:33:44:55:66&\
switchip=192.168.50.1&\
ssid=Stellar-Lab&\
url=http://example.com/"
```

---

## Packet-Level Tracing

```bash
sudo tcpdump -ni any udp port 1812 or udp port 1813
sudo tcpdump -ni any -A tcp port 80
```

---

## Project Structure

```
.
├── app.py
├── radius_server.py
├── db.py
├── init_db.py
├── config.py
├── radius_dictionary
├── requirements.txt
├── run.sh
├── clean.sh
├── static/
│   └── ale_logo.png
└── data/
    ├── cp.db
    ├── radius_events.jsonl
    └── portal_events.jsonl
```

---

## Resetting the Lab

```bash
./clean.sh
```

---

## Notes

- HTTP is recommended for lab testing
- MAC authentication is vulnerable to spoofing
- This is **not a hardened production solution**
- Intended for testing, learning, and validation

---

## License

Lab / reference use only.  
No warranty. Use responsibly.
