from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad import packet
import ipaddress

COA_CODE_NAME = {
    40: "Disconnect-Request",
    41: "Disconnect-ACK",
    42: "Disconnect-NAK",
    43: "CoA-Request",
    44: "CoA-ACK",
    45: "CoA-NAK",
}

ERROR_CAUSE = {
    201: "Residual-Session-Context-Removed",
    202: "Invalid-EAP-Packet-Ignored",
    401: "Unsupported-Attribute",
    402: "Missing-Attribute",
    403: "NAS-Identification-Mismatch",
    404: "Invalid-Request",
    405: "Unsupported-Service",
    406: "Unsupported-Extension",
    501: "Administratively-Prohibited",
    502: "Request-Not-Routable",
    503: "Session-Context-Not-Found",
    504: "Session-Context-Not-Removable",
    505: "Other-Proxy-Processing-Error",
    506: "Resources-Unavailable",
    507: "Request-Initiated",
}

def _attr_name(pkt, attr_id):
    try:
        a = pkt.dict.attrindex.get(attr_id)
        if a:
            return a.name
    except Exception:
        pass
    return str(attr_id)

def _decode_bytes(attr_id, b):
    if not isinstance(b, (bytes, bytearray)):
        return str(b)

    # 4-byte integers (Error-Cause, IPs, etc.)
    if len(b) == 4:
        i = int.from_bytes(b, "big", signed=False)

        if attr_id in (4, 8):  # NAS-IP-Address, Framed-IP-Address
            return str(ipaddress.IPv4Address(i))

        if attr_id == 101:  # Error-Cause
            return f"{i} ({ERROR_CAUSE.get(i, 'Unknown')})"

        return str(i)

    # Message-Authenticator (80): show compact hex
    if attr_id == 80:
        hx = b.hex()
        return hx[:16] + "…" + hx[-8:]  # e.g. 32 chars total, readable

    # Strings
    return b.decode("utf-8", errors="replace")


def _pkt_to_dict(pkt_obj):
    out = {}

    try:
        for k, v in pkt_obj.items():
            attr_id = int(k)
            name = _attr_name(pkt_obj, attr_id)

            values = v if isinstance(v, (list, tuple)) else [v]
            decoded = [_decode_bytes(attr_id, x) for x in values]

            # Collapse one-element lists (cleaner admin logs)
            out[name] = decoded[0] if len(decoded) == 1 else decoded

    except Exception as e:
        return {"_decode_error": repr(e)}

    return out


def send_disconnect(
    nas_ip: str,
    secret: str,
    dictionary_path: str,
    calling_station_id: str = "",
    acct_session_id: str = "",
    framed_ip: str = "",
    nas_identifier: str = "",
    timeout: int = 2,
    coa_port: int = 3799,
):
    nas_ip = (nas_ip or "").strip()
    if not nas_ip:
        return False, "Missing NAS IP"

    dict_obj = Dictionary(dictionary_path)

    client = Client(
        server=nas_ip,
        secret=secret.encode(),
        dict=dict_obj,
        coaport=coa_port,   # IMPORTANT: use coaport (not authport)
    )
    client.timeout = timeout
    client.retries = 1

    attrs = {}
    if calling_station_id:
        attrs["Calling-Station-Id"] = calling_station_id
    if acct_session_id:
        attrs["Acct-Session-Id"] = acct_session_id
    if framed_ip:
        attrs["Framed-IP-Address"] = framed_ip
    if nas_identifier:
        attrs["NAS-Identifier"] = nas_identifier

    # Create a DM packet properly
    req = client.CreateCoAPacket(code=packet.DisconnectRequest, **attrs)

    # Try to add Message-Authenticator if available in your pyrad version
    try:
        req.add_message_authenticator()
    except Exception:
        pass

    tx = {
        "nas_ip": nas_ip,
        "coa_port": coa_port,
        "request_code": getattr(req, "code", None),
        "request_attrs": _pkt_to_dict(req),
    }
    
    try:
        reply = client.SendPacket(req)
        rx = {
            "reply_code": getattr(reply, "code", None),
            "reply_attrs": _pkt_to_dict(reply),
        }
        return True, {"tx": tx, "rx": rx}
    except Exception as e:
        return False, {"tx": tx, "error": repr(e)}
        
        
def send_coa_role_update(
    nas_ip: str,
    secret: str,
    dictionary_path: str,
    role_filter_id: str,
    calling_station_id: str = "",
    acct_session_id: str = "",
    framed_ip: str = "",
    user_name: str = "",
    nas_identifier: str = "",
    timeout: int = 2,
    coa_port: int = 3799,
):
    """
    Send a CoA-Request to update authorization attributes (Filter-Id role).
    Returns (ok: bool, info: dict with tx/rx or tx/error).
    """
    nas_ip = (nas_ip or "").strip()
    role_filter_id = (role_filter_id or "").strip()
    if not nas_ip:
        return False, {"error": "Missing NAS IP"}
    if not role_filter_id:
        return False, {"error": "Missing role_filter_id"}

    dict_obj = Dictionary(dictionary_path)

    client = Client(
        server=nas_ip,
        secret=secret.encode(),
        dict=dict_obj,
        coaport=coa_port,
    )
    client.timeout = timeout
    client.retries = 1

    # Build packet first (no kwargs), then set attrs explicitly (more reliable)
    req = client.CreateCoAPacket(code=packet.CoARequest)

    # Payload: role / ARP
    req["Filter-Id"] = role_filter_id

    # Session identification (send what we have; NAS decides what it needs)
    if calling_station_id:
        req["Calling-Station-Id"] = calling_station_id
    if acct_session_id:
        req["Acct-Session-Id"] = acct_session_id
    if framed_ip:
        req["Framed-IP-Address"] = framed_ip
    if nas_identifier:
        req["NAS-Identifier"] = nas_identifier
    if user_name:
        req["User-Name"] = user_name

    # Some NAS require Message-Authenticator on CoA/DM
    try:
        req.add_message_authenticator()
    except Exception:
        pass

    tx = {
        "nas_ip": nas_ip,
        "coa_port": coa_port,
        "request_code": getattr(req, "code", None),
        "request_attrs": _pkt_to_dict(req),
    }

    try:
        reply = client.SendPacket(req)
        rx = {
            "reply_code": getattr(reply, "code", None),  # 44=CoA-ACK, 45=CoA-NAK :contentReference[oaicite:2]{index=2}
            "reply_attrs": _pkt_to_dict(reply),
        }
        return True, {"tx": tx, "rx": rx}
    except Exception as e:
        return False, {"tx": tx, "error": repr(e)}

