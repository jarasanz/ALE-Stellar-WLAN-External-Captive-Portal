import socket, select
import json, time
from pyrad.server import Server, RemoteHost
from pyrad.packet import AccessAccept, AccessReject, AccountingResponse
from pyrad.dictionary import Dictionary
from config import Settings
from db import (
    ensure_dir, init_db, normalize_mac_any,
    allowed_decision, allow_and_cache, log_event,
    get_setting, get_mac_role,
)
import re
import traceback

MAC_PREFIX_COLON = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
MAC_PREFIX_DASH  = re.compile(r"^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}")
MAC_PREFIX_HEX12 = re.compile(r"^[0-9A-Fa-f]{12}")

s = Settings()
ensure_dir(s.data_dir)
init_db(s.db_path)

def log_jsonl(path: str, rec: dict) -> None:
    rec = {**rec, "ts": int(time.time())}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")

def extract_mac_from_radius(pkt) -> str:
    """
    Stellar memo says for vendor type "ale":
      - Calling-Station-ID is client MAC (default uppercase no delimiter)
      - User-Name is MAC for MAC-Auth, or portal username for portal-auth
    We'll try Calling-Station-ID first, else fall back to parsing from User-Name.
    """
    calling = str(pkt.get("Calling-Station-Id", [""])[0]) or str(pkt.get("Calling-Station-ID", [""])[0])
    user = str(pkt.get("User-Name", [""])[0])

    mac12 = normalize_mac_any(calling)
    if mac12:
        return mac12

    mac12 = normalize_mac_any(user)
    if mac12:
        return mac12

    return ""

def is_mac_auth(pkt) -> bool:
    user = str(pkt.get("User-Name", [""])[0])
    calling = str(pkt.get("Calling-Station-Id", [""])[0]) or str(pkt.get("Calling-Station-ID", [""])[0])
    u = normalize_mac_any(user)
    c = normalize_mac_any(calling)
    return bool(u) and bool(c) and u == c

def extract_nas_fields(pkt) -> dict:
    """
    Pull NAS identity fields for debugging multi-AP scenarios.
    """
    nas_ip = str(pkt.get("NAS-IP-Address", [""])[0] or "")
    nas_id = str(pkt.get("NAS-Identifier", [""])[0] or "")
    nas_port = str(pkt.get("NAS-Port", [""])[0] or "")
    nas_port_type = str(pkt.get("NAS-Port-Type", [""])[0] or "")
    return {
        "nas_ip": nas_ip,
        "nas_id": nas_id,
        "nas_port": nas_port,
        "nas_port_type": nas_port_type,
    }

def parse_called_station_id(called: str) -> tuple[str, str]:
    """
    Called-Station-Id is typically 'APMAC:SSID'
    where APMAC may be colon, dash, or plain 12-hex.
    Returns (ap_mac12, ssid).
    """
    if not called:
        return "", ""

    s = str(called).strip()

    m = MAC_PREFIX_COLON.match(s) or MAC_PREFIX_DASH.match(s) or MAC_PREFIX_HEX12.match(s)
    if not m:
        return "", s

    mac_raw = m.group(0)
    ap_mac12 = normalize_mac_any(mac_raw)  # -> AABBCCDDEEFF

    rest = s[len(mac_raw):]
    # After the MAC there is usually a ":" then the SSID
    if rest.startswith(":"):
        rest = rest[1:]
    elif rest.startswith("-"):
        rest = rest[1:]

    ssid = rest
    return ap_mac12, ssid

def _pick_arp_for_mac(db_path: str, mac12: str, default_role: str) -> str:
    arp = (get_mac_role(db_path, mac12) or default_role or "").strip()
    if arp and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", arp):
        return ""
    return arp

class ALEStellarRadius(Server):
    def send_accept(self, pkt, mac12: str, filter_id: str = "", redirect_url: str = ""):
        reply = self.CreateReplyPacket(pkt)
        reply.code = AccessAccept
        reply["User-Name"] = mac12
        reply["Session-Timeout"] = s.session_timeout_seconds
        reply["Reply-Message"] = "OK"
        if filter_id:
            reply["Filter-Id"] = filter_id
        
        # Redirect attribute (only for unknown redirect mode)
        # If present, push redirect URL attribute (naming varies in docs)
        if redirect_url:
            # whichever attribute name exists in your dictionary
            try:
                reply["Alcatel-Redirect-URL"] = redirect_url
            except Exception:
                pass
            try:
                reply["Alcatel-Redirection-URL"] = redirect_url
            except Exception:
                pass    
            
        tpg = str(pkt.get("Tunnel-Private-Group-ID", [""])[0] or "")
        if tpg:
            reply["Tunnel-Private-Group-ID"] = tpg

        # IMPORTANT: include Message-Authenticator in the reply
        reply.add_message_authenticator()
        print(f"Access-Accept sent for {mac12} from {pkt.source}", flush=True)
        self.SendReplyPacket(pkt.fd, reply)
    
    def HandleAuthPacket(self, pkt):
        mac12 = extract_mac_from_radius(pkt)
        decision = allowed_decision(s.db_path, mac12, s.cache_ttl_seconds)
        allowed = (decision != "reject")
        framed_ip = str(pkt.get("Framed-IP-Address", [""])[0] or "")
        called = str(pkt.get("Called-Station-Id", [""])[0] or "")
        if not called:
            called = str(pkt.get("Called-Station-ID", [""])[0] or "")
        ap_mac12, ssid = parse_called_station_id(called)
        user = str(pkt.get("User-Name", [""])[0] or "")
        fid = str(pkt.get("Filter-Id", [""])[0] or "")
        nas = extract_nas_fields(pkt)
        if not nas.get("nas_id"):
            if ap_mac12:
                nas["nas_id"] = f"AP-{ap_mac12}"
            elif nas.get("nas_ip"):
                nas["nas_id"] = f"NAS-{nas['nas_ip']}"
        
        phase = "mab" if is_mac_auth(pkt) else "portal"
        src_ip = getattr(pkt, "src_ip", "")
        
        # dict for logs
        detail_base = {
            "phase": phase,
            "decision": decision,
            "src_ip": src_ip,
            "called": called,
            "user": user,
            "ap_mac": ap_mac12,
            "ssid": ssid,
            **nas,
        }

        if not mac12:
            log_event(
                s.db_path,
                "radius",
                "reject_no_mac",
                ip=framed_ip,
                detail={
                    "phase": phase,
                    "user": user,
                    "called": called,
                    **nas,
                },
            )
            log_jsonl(
                s.radius_log_jsonl,
                {
                    "event":"reject_no_mac",
                    "decision": decision,
                    "ip":framed_ip,
                    "src_ip": src_ip,
                    "user":user,
                    "called":called, 
                    "ap_mac":ap_mac12, 
                    "ssid":ssid, 
                    **nas
                },
            )

            reply = self.CreateReplyPacket(pkt)
            reply.code = AccessReject
            reply.add_message_authenticator()
            self.SendReplyPacket(pkt.fd, reply)
            return

        if is_mac_auth(pkt):
            # MAC Authentication phase (optional, but we want it enabled)
            if allowed:
                arp = _pick_arp_for_mac(s.db_path, mac12, s.role_final)
                log_event(
                    s.db_path, 
                    "radius", 
                    "mab_accept", 
                    mac=mac12, 
                    ip=framed_ip,
                    detail={
                        **detail_base,
                        "ARP": arp,
                    }
                )
                log_jsonl(
                    s.radius_log_jsonl,
                    {
                        "event":"mab_accept",
                        "decision": decision,
                        "mac":mac12,
                        "ip":framed_ip,
                        "src_ip": src_ip,
                        "called":called, 
                        "ap_mac":ap_mac12, 
                        "ssid":ssid, 
                        **nas,
                        "ARP": arp,
                    },
                )

                self.send_accept(pkt, mac12, filter_id=arp)
                return
            else:
                # Unknown MAC during MAB
                unknown_policy = get_setting(s.db_path, "unknown_policy", s.unknown_mac_policy_default)
                unknown_arp    = get_setting(s.db_path, "unknown_arp", s.unknown_mac_arp_default).strip()
                portal_base    = get_setting(s.db_path, "portal_base", s.portal_public_base_url).strip().rstrip("/")

                if unknown_policy == "redirect" and portal_base:
                    # Build redirect URL to your portal. Keep it simple first: just client MAC + called station id.
                    # You can enrich later with NAS fields if needed.
                    redir = portal_base + "/login/ale?" + urlencode({
                        "clientmac": mac_to_portal_param(mac12) or mac12,
                        "ssid": ssid,
                        "switchip": nas.get("nas_ip", ""),
                        "switchmac": ap_mac12,
                        "url": "http://example.com/",
                    })

                    log_event(
                        s.db_path, "radius", "mab_unknown_redirect",
                        mac=mac12, ip=framed_ip,
                        detail={**detail_base, "unknown_policy": unknown_policy, "unknown_arp": unknown_arp, "redirect": redir}
                    )
                    log_jsonl(s.radius_log_jsonl, {
                        "event": "mab_unknown_redirect",
                        "decision": decision,
                        "mac": mac12,
                        "ip": framed_ip,
                        "src_ip": src_ip,
                        "called": called,
                        "ap_mac": ap_mac12,
                        "ssid": ssid,
                        **nas,
                        "unknown_arp": unknown_arp,
                        "redirect": redir,
                    })

                    # Accept with pre-auth ARP + redirect URL
                    self.send_accept(pkt, mac12, unknown_arp, redir)
                    return

                # Default: reject
                log_event(
                    s.db_path, "radius", "mab_reject",
                    mac=mac12, ip=framed_ip, detail=detail_base
                )
                log_jsonl(s.radius_log_jsonl, {
                    "event": "mab_reject",
                    "decision": decision,
                    "mac": mac12,
                    "ip": framed_ip,
                    "src_ip": src_ip,
                    "called": called,
                    "ap_mac": ap_mac12,
                    "ssid": ssid,
                    **nas
                })

                reply = self.CreateReplyPacket(pkt)
                reply.code = AccessReject
                reply.add_message_authenticator()
                self.SendReplyPacket(pkt.fd, reply)
                return

        # Portal authentication phase:
        # Portal already enrolled MAC in DB. If MAC is allowed, accept.
        if allowed:
            kind = "mab_accept" if is_mac_auth(pkt) else "portal_accept"
            arp = _pick_arp_for_mac(s.db_path, mac12, s.role_final)
            
            log_event(
                s.db_path,
                "radius",
                kind,
                mac=mac12,
                ip=framed_ip,
                detail={
                    **detail_base,
                    "ARP": arp,
                }
            )
            log_jsonl(
                s.radius_log_jsonl,
                {
                    "event": kind,
                    "decision": decision,
                    "mac": mac12,
                    "ip": framed_ip,
                    "src_ip": src_ip,
                    "called": called,
                    "user": user,
                    "ap_mac":ap_mac12,
                    "ssid":ssid, 
                    **nas,
                    "ARP": arp,
                },
            )

            self.send_accept(pkt, mac12, filter_id=arp)
            return

        # Otherwise reject
        log_event(
            s.db_path, "radius", "portal_reject", mac=mac12, ip=framed_ip, 
            detail=detail_base
        )
        log_jsonl(
            s.radius_log_jsonl,
            {
                "event":"portal_reject",
                "decision": decision,
                "mac":mac12,
                "ip":framed_ip,
                "src_ip": src_ip,
                "called":called,
                "user":user, 
                "ap_mac":ap_mac12, 
                "ssid":ssid, 
                **nas
            },
        )

        reply = self.CreateReplyPacket(pkt)
        reply.code = AccessReject
        reply.add_message_authenticator()
        self.SendReplyPacket(pkt.fd, reply)

    def HandleAcctPacket(self, pkt):
        # Memo says standard accounting (Start/Interim/Stop), and provides formats.
        # We’ll just log it.
        mac12 = extract_mac_from_radius(pkt)
        framed_ip = str(pkt.get("Framed-IP-Address", [""])[0] or "")
        status = str(pkt.get("Acct-Status-Type", [""])[0] or "")
        user = str(pkt.get("User-Name", [""])[0] or "")
        nas = extract_nas_fields(pkt)
        src_ip = getattr(pkt, "src_ip", "")
        
        # dict for logs
        detail = {
            "phase": "acct",
            "src_ip": src_ip,
            "user": user,
            **nas,
        }

        log_event(
            s.db_path, 
            "radius", 
            f"acct_{status}".lower(), 
            mac=mac12, 
            ip=framed_ip, 
            detail=detail
        )
        log_jsonl(
            s.radius_log_jsonl,
            {
                "event":"acct",
                "status":status,
                "mac":mac12,
                "ip":framed_ip,
                "src_ip": src_ip,
                "user":user, 
                **nas
            },
        )

        reply = self.CreateReplyPacket(pkt)
        reply.code = AccountingResponse
        self.SendReplyPacket(pkt.fd, reply)

if __name__ == "__main__":
    import os

    dict_path = os.path.join(os.path.dirname(__file__), "radius_dictionary")
    srv = ALEStellarRadius(dict=Dictionary(dict_path))

    srv.authport = s.radius_auth_port
    srv.acctport = s.radius_acct_port

    # Bind explicitly (IPv4)
    auth_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    acct_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    auth_sock.bind((s.radius_host, s.radius_auth_port))
    acct_sock.bind((s.radius_host, s.radius_acct_port))

    # Register the AP as a known client (important for Message-Authenticator)
    # srv.hosts = {}
    # srv.hosts["192.168.10.201"] = RemoteHost("192.168.10.201", s.radius_secret, "StellarAP")
    # srv.hosts["192.168.10.195"] = RemoteHost("192.168.10.195", s.radius_secret, "StellarAP")
    srv.hosts = {
        "192.168.10.201": RemoteHost("192.168.10.201", s.radius_secret, "AP-201"),
        "192.168.10.195": RemoteHost("192.168.10.195", s.radius_secret, "AP-195"),
        "0.0.0.0":        RemoteHost("0.0.0.0", s.radius_secret, "fallback"),
    }


    print(f"RADIUS bound on {s.radius_host} UDP/{s.radius_auth_port} and UDP/{s.radius_acct_port}", flush=True)

    # Simple select loop: receive packet bytes, let pyrad decode + dispatch
    while True:
        r, _, _ = select.select([auth_sock, acct_sock], [], [])
        for sock_ in r:
            data, addr = sock_.recvfrom(8192)
            src_ip = addr[0]
            
            try:
                pkt = srv.CreatePacket(packet=data)
                pkt.source = addr
                pkt.src_ip = src_ip
                # "fd" is used by pyrad SendReplyPacket. We pass the socket itself.
                pkt.fd = sock_
                
                # ✅ IMPORTANT: attach the correct shared secret to the packet
                rh = srv.hosts.get(src_ip) or srv.hosts.get("0.0.0.0")
                if not rh:
                    print(f"Unknown RADIUS client {src_ip} (not in srv.hosts) -> dropping", flush=True)
                    continue

                pkt.secret = rh.secret
                
                if sock_ is auth_sock:
                    srv.HandleAuthPacket(pkt)
                else:
                    srv.HandleAcctPacket(pkt)
            except Exception as e:
                print(f"Error handling packet from {addr}: {e}", flush=True)
                traceback.print_exc()
