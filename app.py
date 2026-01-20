import json, time
from urllib.parse import urlencode, quote
from flask import Flask, request, render_template_string, url_for, abort, request
from config import Settings
from db import (
    ensure_dir, init_db, normalize_mac_any, log_event, mac_to_portal_param, allow_and_cache,
    list_allow_macs, list_cache, list_events, delete_allow_mac, delete_cache_mac, clear_cache, 
    clear_events, expire_cache_now, get_setting, set_setting, set_mac_role,
    list_mac_roles, delete_mac_role, list_sessions, clear_sessions, prune_sessions,
    get_session, delete_session, get_mac_role, clear_stop_sessions,
)
from coa import send_disconnect, send_coa_role_update
import re

COA_CODE_NAME = {
    40: "Disconnect-Request",
    41: "Disconnect-ACK",
    42: "Disconnect-NAK",
    43: "CoA-Request",
    44: "CoA-ACK",
    45: "CoA-NAK",
}

s = Settings()
ensure_dir(s.data_dir)
init_db(s.db_path)
prune_sessions(s.db_path, max_age_seconds=24*3600)

app = Flask(__name__)

FORM_PAGE = """
<!doctype html><meta charset="utf-8">
<title>ALE Stellar Lab Portal</title>
<body style="font-family:system-ui;max-width:760px;margin:40px auto;">
  <div style="display:flex;align-items:center;gap:14px;margin-bottom:18px;">
    <img src="{{ url_for('static', filename='ale_logo.png') }}"
         alt="ALE"
         style="height:72px;max-height:20vw;width:auto;">

    <h2 style="margin:0;">ALE Stellar External Captive Portal (Lab)</h2>
  </div>

  {% if errmsg %}
    <p style="color:#b00020"><b>Error from AP:</b> {{ errmsg }}</p>
  {% endif %}

  <h3>Client / AP Information</h3>
  <p><b>Client MAC (display):</b> {{ clientmac }}</p>
  <p><b>Client IP:</b> {{ clientip }}</p>
  <p><b>AP MAC:</b> {{ switchmac }}</p>
  <p><b>AP IP:</b> {{ switchip }}</p>
  <p><b>SSID:</b> {{ ssid }}</p>

  <details style="margin-top:20px;">
    <summary><b>Raw parameters received from AP</b></summary>
    <pre style="background:#f6f8fa;padding:12px;overflow:auto;">
clientmac = {{ raw.clientmac }}
clientip  = {{ raw.clientip }}
switchmac = {{ raw.switchmac }}
switchip  = {{ raw.switchip }}
ssid      = {{ raw.ssid }}
url       = {{ raw.url }}
errmsg    = {{ raw.errmsg }}
    </pre>
  </details>

  <details style="margin-top:20px;">
    <summary><b>POST parameters that will be sent to AP</b></summary>
    <pre style="background:#f6f8fa;padding:12px;overflow:auto;">
POST {{ ap_login_url }}
user     = {{ post.user }}
password = {{ post.password }}
url      = {{ post.success_url }}
onerror  = {{ post.onerror_url }}
    </pre>
  </details>

  <hr>

  <form method="post" action="/register">
    {% for k,v in hidden.items() %}
      <input type="hidden" name="{{ k }}" value="{{ v }}">
    {% endfor %}

    <h3>Variables to send in the POST (editable)</h3>

    <label>Success URL
        <input name="url_override" value="{{ post.success_url }}"
               style="width:100%;max-width:680px;">
    </label>
    <br><br>

    <label>On-error URL
        <input name="onerror_override" value="{{ post.onerror_url }}"
               style="width:100%;max-width:680px;">
    </label>
    
    <p style="color:#666;font-size:13px;">
        Tip: values above will be used for the AP POST when you click Accept.
    </p>
    
    <br><br>

    <label>ARP / Role (optional, sent as Filter-Id after registration)
      <input name="arp" value="" placeholder="{{ s.role_final }}"
             style="width:100%;max-width:240px;">
    </label>
    <small style="color:#666;display:block;margin-top:6px;">
      Leave empty to use the default role or not sending any role if default role equals "" (config.py). Fill to store a per-MAC role.
    </small>

    
    <br><br>

    <label>Email (lab field)
      <input name="email" required style="width:100%;max-width:420px;">
    </label>
    <button type="submit">Accept</button>
  </form>

  <p style="margin-top:24px;color:#666">
    This page shows exactly what the AP sent and what will be sent back.
  </p>
</body>
"""

POST_TO_AP_PAGE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Connecting…</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {
      font-family: system-ui;
      max-width: 720px;
      margin: 40px auto;
      text-align: center;
      color: #222;
    }
    .brand {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 14px;
      margin-bottom: 28px;
    }
    .brand img {
      height: 44px;
      width: auto;
    }
    .hint {
      color: #666;
      font-size: 14px;
      margin-top: 12px;
    }
    button {
      margin-top: 24px;
      padding: 10px 22px;
      font-size: 16px;
    }
    a.btnlink {
      display: inline-block;
      margin-top: 18px;
      padding: 10px 22px;
      font-size: 16px;
      text-decoration: none;
      border: 1px solid #bbb;
      border-radius: 8px;
      color: #222;
    }
    .small {
      margin-top: 16px;
      font-size: 12px;
      color: #666;
      word-break: break-word;
    }
  </style>
</head>

<body>
  <div class="brand">
    <img src="{{ url_for('static', filename='ale_logo.png') }}" alt="ALE">
    <strong>ALE Stellar</strong>
  </div>

  <h2>Connecting you to the network…</h2>
  <p class="hint">This should only take a moment.</p>

  <form id="loginForm" method="post" action="{{ ap_login_url }}">
    <!-- Required for vendor type "ale" -->
    <input type="hidden" name="user" value="{{ user }}">
    <input type="hidden" name="password" value="{{ password }}">
    <input type="hidden" name="url" value="{{ success_url }}">
    <input type="hidden" name="onerror" value="{{ onerror_url }}">

    <noscript>
      <p class="hint">JavaScript is disabled. Click below to continue.</p>
      <button type="submit">Continue</button>
    </noscript>
  </form>
  <a class="btnlink" href="{{ success_url }}">Continue</a>

  <div class="small">
    If you are not redirected automatically, your browser can continue to:<br>
    <code>{{ success_url }}</code>
  </div>

  <script>
    // Auto-submit immediately for captive portal flow (AP should intercept).
    document.getElementById('loginForm').submit();

    // Fallback: if the captive interception/DNS behaves oddly, try navigating anyway.
    setTimeout(function () {
      try { window.location.replace("{{ success_url }}"); } catch (e) {}
    }, 6000);
  </script>

</body>
</html>
"""

ADMIN_PAGE = """
<!doctype html><meta charset="utf-8">
<title>ALE Lab Admin</title>
<body style="font-family:system-ui;max-width:1100px;margin:40px auto;">
{# <body style="font-family:system-ui;max-width:1600px;margin:24px auto;padding:0 14px;"> #}
  {% macro token_input() -%}
    {% if admin_token %}
      <input type="hidden" name="token" value="{{ admin_token }}">
    {% endif %}
  {%- endmacro %}

  <style>
    :root { --base-font: 14px; }

    body { font-size: var(--base-font); }

    .expired {
      color: #b00020;
      font-weight: 600;
    }

    table {
      width: 100%;
      border-collapse: collapse;
    }

    /*table { table-layout: fixed; width: 100%; }*/
    
    th, td {
      border: 1px solid #333;
      padding: 6px;
      vertical-align: top;
      font-size: var(--base-font);          /* enforce same size everywhere */
    }
    th { font-weight: 700; }

    /* Make <code> consistent in size, just monospace */
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 1em;                        /* same size as surrounding text */
    }

    /* Detail column wrapping + readable formatting */
    td.detail {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    td.detail code {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
      display: block;

      background: #f6f8fa;
      padding: 6px;
      border-radius: 4px;
      font-size: 1em;                        /* IMPORTANT: match table font size */
      line-height: 1.25;
    }
    td code {
      font-size: 13px;
      background: #f6f8fa;
      padding: 2px 6px;
      border-radius: 4px;
    }
    td.session_key, td.acct_id {
      white-space: normal;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .highlight {
      outline: 3px solid rgba(255, 193, 7, 0.9);
      background: rgba(255, 193, 7, 0.18);
      transition: background 0.6s ease, outline 0.6s ease;
    }
    .sess-actions {
      display: flex;
      flex-direction: column;
      gap: 6px;
      align-items: flex-start;
    }
    .sess-actions button {
      min-width: 92px; /* optional, makes buttons uniform */
    }
  </style>

  <div style="display:flex;align-items:center;gap:18px;margin-bottom:22px;">
    <img src="{{ url_for('static', filename='ale_logo.png') }}"
         alt="ALE"
         style="height:72px;max-height:20vw;width:auto;">
    <div>
      <h2 style="margin:0;">ALE Stellar Captive Portal – Admin</h2>
      <p style="margin:4px 0 0;color:#666;">DB: {{ db_path }}</p>
    </div>
  </div>
  <hr style="margin:16px 0 22px;">

  <h3 style="margin-top:22px;">Unknown MAC policy (MAB)</h3>

  <form method="post" action="/admin/save-unknown-policy{{ qs }}"
        style="display:flex;gap:16px;flex-wrap:wrap;align-items:flex-end;margin:10px 0 18px;">
    
    {{ token_input() }}
    
    <div style="display:flex;gap:20px;flex-wrap:wrap;align-items:flex-start;margin-bottom:12px;">
      <label style="display:flex;flex-direction:column;gap:6px;min-width:240px;flex:1 1 0;">
        Decision for unknown MACs
         <select name="unknown_policy">
          <option value="reject">Access-Reject</option>
          <option value="redirect">Access-Accept + Redirect</option>
        </select>
      </label>

      <label style="display:flex;flex-direction:column;gap:6px;min-width:240px;flex:1;">
        ARP for unknown users (Filter-Id)
        <input name="unknown_arp" value="{{ unknown_arp }}">
        <small style="color:#666;">Effective value used in RADIUS replies.</small>
      </label>
    </div>


    <label style="display:flex;flex-direction:column;gap:6px;min-width:min(520px,100%);flex:1;">
      Portal base URL (used in Alcatel-Redirect-URL)
      <input name="portal_base" value="{{ portal_base }}">
      <small style="color:#666;">
        Public URL reachable by clients/APs.
        {% if portal_base != s.portal_public_base_url %}
          <br>Config default: <code>{{ s.portal_public_base_url or "(not set)" }}</code>
        {% else %}
          <br>Using config default.
        {% endif %}
      </small>
    </label>


    <button type="submit">Save</button>
  </form>

  <p style="margin:0 0 10px;color:#666;">
    Notes: In “redirect” mode, unknown MACs are accepted with <code>Filter-Id=&lt;ARP&gt;</code> and
    <code>Alcatel-Redirect-URL=&lt;portal&gt;</code>.
  </p>

  <div style="display:flex;gap:12px;flex-wrap:wrap;margin:10px 0 18px;">
    <form method="post" action="/admin/expire-cache{{ qs }}">
      {{ token_input() }}
      <button type="submit">Expire cache now</button>
    </form>
    <form method="post" action="/admin/clear-cache{{ qs }}">
      {{ token_input() }}
      <button type="submit">Clear cache</button>
    </form>
    <form method="post" action="/admin/clear-sessions{{ qs }}">
      {{ token_input() }}
      <button type="submit">Clear sessions</button>
    </form>
    <form method="post" action="/admin/prune-sessions{{ qs }}">
      {{ token_input() }}
      <button type="submit">Prune old sessions</button>
    </form>
    <form method="post" action="/admin/clear-stop-sessions{{ qs }}">
      {{ token_input() }}
      <button type="submit">Clear STOP sessions</button>
    </form>
    <form method="post" action="/admin/clear-events{{ qs }}">
      {{ token_input() }}
      <button type="submit">Clear events</button>
    </form>
  </div>

  <div style="background:#f6f8fa;border:1px solid #ccc;padding:12px;border-radius:6px;margin:16px 0;">
    <b>MAC lifecycle overview:</b>
    <ul style="margin:8px 0 0 18px;padding:0;">
      <li><b>Allowlist</b>: MACs permanently approved to access the network.</li>
      <li><b>Cache</b>: MACs temporarily allowed (auto-expire).</li>
      <li><b>MAC Roles (ARP)</b>: Per-MAC access role (Filter-Id) assignments.</li>
    </ul>
  </div>


  <h3>Allowlist ({{ allow|length }})</h3>
    <p style="color:#666;margin:4px 0 10px;">
      MAC addresses that are permanently allowed to authenticate via RADIUS (MAB).
      Unknown MACs not in this list will be rejected or redirected based on the policy above.
    </p>
  
  <table border="1" cellpadding="6" cellspacing="0"
         style="border-collapse:collapse;width:100%;">
         
    <tr>
      <th>MAC</th>
      <th>ARP</th>
      <th>Added (unix)</th>
      <th>Added (local)</th>
      <th>Action</th>
    </tr>
    
    {% for r in allow %}
      <tr>
        <td><code>{{ r.mac }}</code></td>
        <td><code>{{ role_by_mac.get(r.mac, "") }}</code></td>
        <td>{{ r.added_ts }}</td>
        <td class="ts" data-ts="{{ r.added_ts }}"></td>
        <td>
          <form method="post" action="/admin/delete-allow{{ qs }}" style="margin:0;">
            {{ token_input() }}
            <input type="hidden" name="mac" value="{{ r.mac }}">
            <button type="submit">Remove</button>
          </form>
        </td>
      </tr>

    {% endfor %}
  </table>

  <h3 style="margin-top:26px;">Cache ({{ cache|length }})</h3>
    <p style="color:#666;margin:4px 0 10px;">
      Temporary allowlist used to avoid repeated portal redirects and re-authentication.
      Entries expire automatically after a TTL.
    </p>

  <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%;">
    <tr><th>MAC</th><th>ARP</th><th>Expires (unix)</th><th>Expires (local)</th><th>Action</th></tr>
    {% for r in cache %}
      <tr>
        <td><code>{{ r.mac }}</code></td>
        <td><code>{{ role_by_mac.get(r.mac, "") }}</code></td>
        <td>{{ r.expires_ts }}</td>
        <td class="ts {% if r.expires_ts and r.expires_ts < now_ts %}expired{% endif %}"
            data-ts="{{ r.expires_ts }}"></td>
        <td>
          <form method="post" action="/admin/delete-cache{{ qs }}" style="margin:0;">
            {{ token_input() }}
            <input type="hidden" name="mac" value="{{ r.mac }}">
            <button type="submit">Remove</button>
          </form>
        </td>
      </tr>
    {% endfor %}
  </table>

  <h3 style="margin-top:26px;">MAC Roles (ARP) ({{ roles|length }})</h3>
    <p style="color:#666;margin:4px 0 10px;">
      Per-MAC Access Role Profile (Filter-Id) assignments.
      This determines the policy, VLAN, ACLs, and privileges applied by the AP.
    </p>

    <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%;">
      <tr><th>MAC</th><th>ARP</th><th>Updated (unix)</th><th>Updated (local)</th><th>Action</th></tr>
      {% for r in roles %}
        <tr>
          <td><code>{{ r.mac }}</code></td>
          <td><code>{{ r.arp }}</code></td>
          <td>{{ r.updated_ts }}</td>
          <td class="ts" data-ts="{{ r.updated_ts }}"></td>
          <td>
            <form method="post" action="/admin/delete-role{{ qs }}" style="margin:0;">
              {{ token_input() }}
              <input type="hidden" name="mac" value="{{ r.mac }}">
              <button type="submit">Remove</button>
            </form>
          </td>
        </tr>
      {% endfor %}
    </table>

  <h3 style="margin-top:26px;">Sessions (latest 50)</h3>
  <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%;">
    <tr>
      <th>last seen (unix)</th><th>last seen (local)</th>
      <th>status</th>
      <th>MAC</th>
      <th>Framed IP</th>
      <th>NAS IP</th>
      <th>Acct-Session-Id</th>
      <th>SSID</th>
      <th>session_key</th>
      <th>Action</th>
    </tr>
    {% for srow in sessions %}
      <tr data-session-key="{{ srow.session_key }}">
        <td>{{ srow.last_seen_ts }}</td>
        <td class="ts" data-ts="{{ srow.last_seen_ts }}"></td>
        <td><code>{{ srow.status }}</code></td>
        <td><code>{{ srow.mac }}</code></td>
        <td><code>{{ srow.framed_ip }}</code></td>
        <td><code>{{ srow.nas_ip or srow.src_ip }}</code></td>
        <td class="acct_id"><code>{{ srow.acct_session_id }}</code></td>
        <td><code>{{ srow.ssid }}</code></td>
        <td class="session_key"><code>{{ srow.session_key }}</code></td>
        <td style="white-space:normal;">
          <div class="sess-actions">
            <form method="post" action="/admin/delete-session{{ qs }}" style="margin:0;">
              {{ token_input() }}
              <input type="hidden" name="session_key" value="{{ srow.session_key }}">
              <button type="submit">Delete</button>
            </form>
          
            <form method="post" action="/admin/disconnect-session{{ qs }}" style="margin:0;">
              {{ token_input() }}
              <input type="hidden" name="session_key" value="{{ srow.session_key }}">
              <button type="submit">Disconnect</button>
            </form>
          
            <form method="post" action="/admin/coa-role{{ qs }}" style="margin:0;">
              {{ token_input() }}
              <input type="hidden" name="session_key" value="{{ srow.session_key }}">

              <div style="display:flex;gap:6px;align-items:center;">
                <input name="role" placeholder="ARP" style="width:100px;">
                <button type="submit">CoA Role</button>
              </div>
            </form>
          </div>
        </td>
      </tr>
    {% endfor %}
  </table>

  <h3 style="margin-top:26px;">Recent Events ({{ events|length }})</h3>
  <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%;">
    <tr>
      <th>ts (unix)</th>
      <th>ts (local)</th>
      <th>event-ts (unix)</th>
      <th>event-ts (local)</th>
      <th>source</th>
      <th>type</th>
      <th>mac</th>
      <th>ip</th>
      <th>detail</th>
    </tr>
    {% for e in events %}
      <tr>
        <td>{{ e.ts }}</td>
        <td class="ts" data-ts="{{ e.ts }}"></td>
        <td>
          {% if e.detail_obj and e.detail_obj.event_timestamp %}
            {{ e.detail_obj.event_timestamp }}
          {% endif %}
        </td>
        <td class="ts" data-ts="{% if e.detail_obj and e.detail_obj.event_timestamp %}{{ e.detail_obj.event_timestamp }}{% endif %}"></td>
        <td>{{ e.source }}</td>
        <td><code>{% if e.dir %}{{ e.dir }} {% endif %}{{ e.type }}</code></td>
        <td><code>{{ e.mac }}</code></td>
        <td><code>{{ e.ip }}</code></td>
        <td class="detail"><code>{{ e.detail }}</code></td>
      </tr>
    {% endfor %}
  </table>

  <p style="margin-top:18px;color:#666">
    Tip: bookmark <code>/admin{{ qs }}</code>
  </p>
  
  <script>
    (function () {
      const fmt = new Intl.DateTimeFormat(undefined, {
        year: "numeric", month: "2-digit", day: "2-digit",
        hour: "2-digit", minute: "2-digit", second: "2-digit",
        hour12: false
      });

      document.querySelectorAll(".ts[data-ts]").forEach(el => {
        const ts = Number(el.getAttribute("data-ts"));
        if (!ts || Number.isNaN(ts)) {
          el.textContent = "";
          return;
        }
        const d = new Date(ts * 1000);
        el.textContent = fmt.format(d);
        el.title = d.toISOString(); // hover shows ISO UTC
      });
    })();
  </script>
  <script>
    (function () {
      const params = new URLSearchParams(window.location.search);
      const hi = params.get("hi");
      if (!hi) return;

      // Find the session row
      const row = document.querySelector(`tr[data-session-key="${CSS.escape(hi)}"]`);
      if (!row) return;

      row.classList.add("highlight");
      row.scrollIntoView({ behavior: "smooth", block: "center" });

      // Remove highlight after a few seconds
      setTimeout(() => row.classList.remove("highlight"), 3500);

      // Optional: remove hi= from URL so refresh doesn't re-highlight
      params.delete("hi");
      const newQs = params.toString();
      const newUrl = window.location.pathname + (newQs ? "?" + newQs : "");
      window.history.replaceState({}, "", newUrl);
    })();
  </script>
  
</body>
"""

def _require_admin_token_or_403():
    token_cfg = (getattr(s, "admin_token", "") or "").strip()
    if not token_cfg:
        return  # token disabled (lab mode)

    token_req = (request.args.get("token") or request.form.get("token") or "").strip()
    if token_req != token_cfg:
        abort(403)

def prettify_errmsg(msg: str) -> str:
    msg = (msg or "").strip()
    if not msg:
        return ""
    # Insert a separator between "...failureService..." → "...failure | Service..."
    msg = re.sub(r"(?i)(failure)(service)", r"\1 | \2", msg)
    # Also: add separator between a lowercase followed by uppercase (word boundary in concatenated strings)
    msg = re.sub(r"([a-z])([A-Z])", r"\1 | \2", msg)
    # Compress multiple spaces
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg

def log_jsonl(path: str, rec: dict) -> None:
    rec = {**rec, "ts": int(time.time()), "ua": request.headers.get("User-Agent", "")}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")

def get_params():
    # As per memo: clientmac, clientip, switchmac, swicthip (typo in memo), ssid, url, errmsg
    # We'll accept both "swicthip" and "switchip" for sanity.
    q = request.args
    clientmac = q.get("clientmac", "")
    clientip = q.get("clientip", "")
    switchmac = q.get("switchmac", "")
    switchip = q.get("swicthip", "") or q.get("switchip", "")
    ssid = q.get("ssid", "")
    url = q.get("url", "")
    errmsg = prettify_errmsg(q.get("errmsg", ""))
    return clientmac, clientip, switchmac, switchip, ssid, url, errmsg

def admin_ok() -> bool:
    token = getattr(s, "admin_token", "")
    if not token:
        return True  # lab mode: open
    return request.args.get("token", "") == token

def _admin_qs_or_403():
    """
    Return "?token=..." (or "") for admin redirects and action URLs.
    Enforces token if s.admin_token is set.
    """
    token_cfg = (getattr(s, "admin_token", "") or "").strip()
    token_req = (request.args.get("token") or "").strip()

    if token_cfg:
        if token_req != token_cfg:
            return None  # caller returns 403
        return "?token=" + token_req

    return ""

def _admin_qs():
    """Return '?token=...' if token is present, else ''."""
    token = (request.args.get("token") or "").strip()
    return f"?token={token}" if token else ""

def _admin_redirect(hi: str | None = None):
    """Redirect to /admin preserving token, optionally adding hi=..."""
    qs = _admin_qs()
    base = "/admin" + qs
    if hi:
        sep = "&" if "?" in base else "?"
        base = f"{base}{sep}hi={quote(hi)}"
    return ("", 303, {"Location": base})


@app.get("/login/ale")
def login_ale():
    clientmac, clientip, switchmac, switchip, ssid, url, errmsg = get_params()
    clientmac_raw = clientmac
    
    mac12 = normalize_mac_any(clientmac)
    log_event(s.db_path, "portal", "hit", mac=mac12, ip=clientip, detail=request.query_string.decode(errors="ignore"))
    log_jsonl(s.portal_log_jsonl, {
        "event": "hit",
        "clientmac_raw": clientmac,
        "clientmac_norm": mac12,
        "clientip": clientip,
        "switchmac": switchmac,
        "switchip": switchip,
        "ssid": ssid,
        "url": url,
        "errmsg": errmsg,
    })

    # Display MAC in the same "lowercase colon" style mentioned as default in memo
    clientmac_display = mac_to_portal_param(mac12) if mac12 else clientmac

    # Build derived POST preview values (no side effects)
    user = mac12
    password = mac12

    portal_base = request.host_url.rstrip("/")
    onerror_url = portal_base + "/login/ale?" + urlencode({
        "clientmac": clientmac_raw,
        "clientip": clientip,
        "switchmac": switchmac,
        "switchip": switchip,
        "ssid": ssid,
        "url": url,
        "errmsg": "Authentication failure",
    })

    print("FULL_URL:", request.url, flush=True)
    print("ARGS:", dict(request.args.lists()), flush=True)
    print("ERRMSG_LIST:", request.args.getlist("errmsg"), flush=True)
    
    return render_template_string(
        FORM_PAGE,
        s=s,
        url_for=url_for,
        clientmac=clientmac_display,
        clientip=clientip,
        switchmac=switchmac,
        switchip=switchip,
        ssid=ssid,
        errmsg=errmsg,

        raw={
            "clientmac": clientmac_raw,
            "clientip": clientip,
            "switchmac": switchmac,
            "switchip": switchip,
            "ssid": ssid,
            "url": url,
            "errmsg": errmsg,
        },

        post={
            "user": user,
            "password": password,
            "success_url": url or "http://example.com/",
            "onerror_url": onerror_url,
        },

        hidden={
            "clientmac": clientmac_raw,
            "clientip": clientip,
            "switchmac": switchmac,
            "switchip": switchip,
            "ssid": ssid,
            "url": url,
        },

        ap_login_url=s.ap_login_url,
    )

@app.post("/register")
def register():
    clientmac = request.form.get("clientmac", "")
    clientip = request.form.get("clientip", "")
    switchmac = request.form.get("switchmac", "")
    switchip  = request.form.get("switchip", "")
    ssid = request.form.get("ssid", "")
    url = request.form.get("url", "")  # original URL from AP (hidden)

    url_override = (request.form.get("url_override", "") or "").strip()
    onerror_override = (request.form.get("onerror_override", "") or "").strip()
    email = (request.form.get("email", "") or "").strip()

    arp = (request.form.get("arp", "") or "").strip()
    if arp and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", arp):
        return "Invalid ARP format.", 400
    
    mac12 = normalize_mac_any(clientmac)
    if not mac12:
        return "Missing/invalid clientmac (AP didn’t send one we can parse).", 400

    if arp:
        set_mac_role(s.db_path, mac12, arp)
        log_event(s.db_path, "portal", "set_role", mac=mac12, ip=clientip, detail={"arp": arp})

    # Compute effective URLs BEFORE logging them
    success_url = url_override or url or "http://example.com/"

    portal_base = request.host_url.rstrip("/")
    computed_onerror_url = portal_base + "/login/ale?" + urlencode({
        "clientmac": clientmac,
        "clientip": clientip,
        "switchmac": switchmac,
        "switchip": switchip,
        "ssid": ssid,
        "url": success_url,
        "errmsg": "Authentication failure",
    })
    onerror_url = onerror_override or computed_onerror_url

    # Now logging is safe
    log_event(
        s.db_path, "portal", "register", mac=mac12, ip=clientip,
        detail={
            "ssid": ssid,
            "email": email,
            "success_url": success_url,
            "onerror_url": onerror_url,
            "arp": arp,
        }
    )
    log_jsonl(s.portal_log_jsonl, {
        "event": "register",
        "clientmac_raw": clientmac,
        "clientmac_norm": mac12,
        "clientip": clientip,
        "ssid": ssid,
        "email": email,
        "url_original": url,
        "url_override": url_override,
        "success_url": success_url,
        "onerror_override": onerror_override,
        "onerror_url": onerror_url,
        "switchmac": switchmac,
        "switchip": switchip,
        "arp": arp,
    })

    # Enroll + cache after successful parse
    allow_and_cache(s.db_path, mac12, getattr(s, "cache_ttl_seconds", 6*3600))

    # Portal-auth credentials (lab)
    user = mac12
    password = mac12

    return render_template_string(
        POST_TO_AP_PAGE,
        ap_login_url=s.ap_login_url,
        user=user,
        password=password,
        success_url=success_url,
        onerror_url=onerror_url
    )


@app.get("/admin")
def admin():
    _require_admin_token_or_403()

    allow = list_allow_macs(s.db_path, limit=500)
    cache = list_cache(s.db_path, limit=500)
    events = list_events(s.db_path, limit=200)
    # Convert sqlite3.Row -> dict so we can safely modify fields
    events = [dict(r) for r in events]
    unknown_policy = get_setting(s.db_path, "unknown_policy", s.unknown_mac_policy_default)
    unknown_arp    = get_setting(s.db_path, "unknown_arp", s.unknown_mac_arp_default)
    portal_base    = get_setting(s.db_path, "portal_base", s.portal_public_base_url)
    roles = list_mac_roles(s.db_path, limit=500)
    role_by_mac = {r["mac"]: r["arp"] for r in roles}
    hi = (request.args.get("hi", "") or "").strip()


    # preserve token in action URLs
    qs = _admin_qs()
    admin_token = (request.args.get("token") or "").strip()

    sessions = list_sessions(s.db_path, limit=50)

    # Pretty-print JSON details for admin UI readability (+ enrich CoA/DM rx/tx)
    for e in events:
        e["dir"] = ""
        try:
            d = json.loads(e["detail"]) if isinstance(e["detail"], str) else (e["detail"] or {})
            e["dir"] = d.get("dir", "") or ""

            # --- Add readable labels for CoA/DM codes ---
            if isinstance(d, dict):
                tx = d.get("tx") or {}
                rx = d.get("rx") or {}

                # request_code label
                if isinstance(tx, dict):
                    code = tx.get("request_code")
                    if isinstance(code, int):
                        tx["request_code_label"] = f"{code} ({COA_CODE_NAME.get(code, '')})".strip()

                # reply_code label
                if isinstance(rx, dict):
                    code = rx.get("reply_code")
                    if isinstance(code, int):
                        rx["reply_code_label"] = f"{code} ({COA_CODE_NAME.get(code, '')})".strip()

            e["detail"] = json.dumps(d, indent=2, ensure_ascii=False)
        except Exception:
            pass


    return render_template_string(
        ADMIN_PAGE,
        roles=roles,
        role_by_mac=role_by_mac,
        s=s,
        db_path=s.db_path,
        allow=allow,
        cache=cache,
        events=events,
        sessions=sessions,
        qs=qs,
        hi=hi,
        admin_token=admin_token,
        now_ts=int(time.time()),
        unknown_policy=unknown_policy,
        unknown_arp=unknown_arp,
        portal_base=portal_base,
    )

@app.post("/admin/delete-allow")
def admin_delete_allow():
    _require_admin_token_or_403()
    
    mac = request.form.get("mac", "")
    delete_allow_mac(s.db_path, mac)
    # also drop from cache so it really re-portals
    delete_cache_mac(s.db_path, mac)
    log_event(s.db_path, "admin", "delete_allow", mac=normalize_mac_any(mac), detail={"mac": mac})
    return _admin_redirect()

@app.post("/admin/delete-cache")
def admin_delete_cache():
    _require_admin_token_or_403()
    
    mac = request.form.get("mac", "")
    delete_cache_mac(s.db_path, mac)
    log_event(s.db_path, "admin", "delete_cache", mac=normalize_mac_any(mac), detail={"mac": mac})
    return _admin_redirect()

@app.post("/admin/clear-cache")
def admin_clear_cache():
    _require_admin_token_or_403()
    
    clear_cache(s.db_path)
    log_event(s.db_path, "admin", "clear_cache")
    return _admin_redirect()

@app.post("/admin/clear-events")
def admin_clear_events():
    _require_admin_token_or_403()
    
    clear_events(s.db_path)
    log_event(s.db_path, "admin", "clear_events")
    return _admin_redirect()

@app.post("/admin/expire-cache")
def admin_expire_cache():
    _require_admin_token_or_403()
    
    expire_cache_now(s.db_path)
    log_event(s.db_path, "admin", "expire_cache_now")
    return _admin_redirect()

@app.post("/admin/save-unknown-policy")
def admin_save_unknown_policy():
    # if you have admin token enforcement, apply it here too (same as other admin POSTs)
    _require_admin_token_or_403()
    
    policy = (request.form.get("unknown_policy", "") or "").strip().lower()
    arp    = (request.form.get("unknown_arp", "") or "").strip()
    pbase  = (request.form.get("portal_base", "") or "").strip().rstrip("/")

    if policy not in ("reject", "redirect"):
        policy = "redirect"

    set_setting(s.db_path, "unknown_policy", policy)
    set_setting(s.db_path, "unknown_arp", arp)
    set_setting(s.db_path, "portal_base", pbase)

    log_event(s.db_path, "portal", "admin_set_unknown_policy",
              detail={"unknown_policy": policy, "unknown_arp": arp, "portal_base": pbase})
    return _admin_redirect()

@app.post("/admin/delete-role")
def admin_delete_role():
    _require_admin_token_or_403()
    
    mac = request.form.get("mac", "")
    mac12 = normalize_mac_any(mac)
    if mac12:
        delete_mac_role(s.db_path, mac12)
        log_event(s.db_path, "portal", "admin_delete_role", mac=mac12, detail={})
    return _admin_redirect()

@app.post("/admin/clear-sessions")
def admin_clear_sessions():
    _require_admin_token_or_403()
    clear_sessions(s.db_path)
    log_event(s.db_path, "portal", "admin_clear_sessions")
    return _admin_redirect()


@app.post("/admin/prune-sessions")
def admin_prune_sessions():
    _require_admin_token_or_403()
    prune_sessions(s.db_path, max_age_seconds=24*3600)
    log_event(s.db_path, "portal", "admin_prune_sessions")
    return _admin_redirect()

@app.post("/admin/clear-stop-sessions")
def admin_clear_stop_sessions():
    _require_admin_token_or_403()

    n = clear_stop_sessions(s.db_path)
    log_event(s.db_path, "portal", "admin_clear_stop_sessions", detail={"deleted": n})

    return _admin_redirect()


@app.post("/admin/disconnect-session")
def admin_disconnect_session():
    _require_admin_token_or_403()
    
    clicked_by = request.remote_addr or ""
    session_key = (request.form.get("session_key", "") or "").strip()
    row = get_session(s.db_path, session_key)
    if not row:
        return "Unknown session_key", 404

    # Choose NAS target: prefer NAS-IP-Address; fallback to src_ip
    nas_ip = (row["nas_ip"] or row["src_ip"] or "").strip()
    if not nas_ip:
        return "Cannot determine NAS IP for CoA/DM (missing nas_ip/src_ip).", 400

    log_event(
        s.db_path,
        "radius",
        "dm_tx",
        mac=row["mac"],
        ip=row["framed_ip"],
        detail={
            "dir": "<-",  # RADIUS -> AP (as you requested)
            "nas_ip": nas_ip,
            "coa_port": getattr(s, "coa_port", 3799),
            "session_key": session_key,
            "calling_station_id": row["calling_station_id"] or row["mac"],
            "acct_session_id": row["acct_session_id"] or "",
            "framed_ip": row["framed_ip"] or "",
            "nas_id": row["nas_id"] or "",
            "clicked_by": clicked_by,
        },
    )

    ok, info = send_disconnect(
        nas_ip=nas_ip,
        secret=s.coa_secret,
        dictionary_path=s.radius_dictionary_path,
        calling_station_id=row["calling_station_id"] or row["mac"],
        acct_session_id=row["acct_session_id"] or "",
        framed_ip=row["framed_ip"] or "",
        nas_identifier=row["nas_id"] or "",
        timeout=getattr(s, "coa_timeout_seconds", 2),
        coa_port=getattr(s, "coa_port", 3799),
    )
    
    if isinstance(info, dict) and "tx" in info and ok:
        info = {"rx": info.get("rx", {}), "tx_note": "see dm_tx"}


    log_event(
        s.db_path,
        "radius",
        "dm_rx",
        mac=row["mac"],
        ip=row["framed_ip"],
        detail={
            "dir": "->",  # AP -> RADIUS (reply)
            "ok": ok,
            "session_key": session_key,
            **(info if isinstance(info, dict) else {"info": str(info)}),
            "clicked_by": clicked_by,
        },
    )
    
    if not ok:
        log_event(
            s.db_path, "radius", "dm_error",
            mac=row["mac"], ip=row["framed_ip"],
            detail={"dir": "->", "session_key": session_key, **(info if isinstance(info, dict) else {"info": str(info)})},
        )
    return _admin_redirect(hi=session_key)

@app.post("/admin/delete-session")
def admin_delete_session():
    _require_admin_token_or_403()
    
    session_key = (request.form.get("session_key", "") or "").strip()
    delete_session(s.db_path, session_key)
    log_event(s.db_path, "portal", "admin_delete_session", detail={"session_key": session_key})
    return _admin_redirect(hi=session_key)

@app.post("/admin/coa-role")
def admin_coa_role():
    _require_admin_token_or_403()
    
    session_key = (request.form.get("session_key", "") or "").strip()
    role = (request.form.get("role", "") or "").strip()
    clicked_by = request.remote_addr or ""
    row = get_session(s.db_path, session_key)
    if not row:
        return "Unknown session_key", 404

    nas_ip = (row["nas_ip"] or row["src_ip"] or "").strip()
    if not nas_ip:
        return "Cannot determine NAS IP for CoA (missing nas_ip/src_ip).", 400

    # If role not provided, try DB role per MAC; else fallback to Settings default
    if not role:
        try:
            role = (get_mac_role(s.db_path, row["mac"]) or "").strip()
        except Exception:
            role = ""
    if not role:
        role = (getattr(s, "role_final", "") or "").strip()  # your default final ARP/role

    # Add the username so we can add it in the CoA.
    # Stellar APs expect "username" among other attributes
    user_name = row["calling_station_id"] or row["mac"]
    
    calling_station_id = row["calling_station_id"] or row["mac"]
    # Convert 12-hex to colon format if needed
    if len(calling_station_id) == 12 and ":" not in calling_station_id:
        calling_station_id = ":".join(calling_station_id[i:i+2] for i in range(0, 12, 2))
    
    # TX log: RADIUS -> AP
    log_event(
        s.db_path,
        "radius",
        "coa_tx",
        mac=row["mac"],
        ip=row["framed_ip"],
        detail={
            "dir": "<-",
            "clicked_by": clicked_by,
            "session_key": session_key,
            "nas_ip": nas_ip,
            "coa_port": getattr(s, "coa_port", 3799),
            "ARP": role,
            "calling_station_id": row["calling_station_id"] or row["mac"],
            "acct_session_id": row["acct_session_id"] or "",
            "framed_ip": row["framed_ip"] or "",
            "nas_id": row["nas_id"] or "",
        },
    )

    ok, info = send_coa_role_update(
        nas_ip=nas_ip,
        secret=s.coa_secret,
        dictionary_path=s.radius_dictionary_path,
        role_filter_id=role,
        user_name=user_name,
        calling_station_id=calling_station_id,
        acct_session_id=row["acct_session_id"] or "",
        framed_ip=row["framed_ip"] or "",
        nas_identifier=row["nas_id"] or "",
        timeout=getattr(s, "coa_timeout_seconds", 2),
        coa_port=getattr(s, "coa_port", 3799),
    )

    # RX log: AP -> RADIUS
    log_event(
        s.db_path,
        "radius",
        "coa_rx",
        mac=row["mac"],
        ip=row["framed_ip"],
        detail={
            "dir": "->",
            "clicked_by": clicked_by,
            "ok": ok,
            "session_key": session_key,
            **(info if isinstance(info, dict) else {"info": str(info)}),
        },
    )
    return _admin_redirect(hi=session_key)

if __name__ == "__main__":
    app.run(
        host=s.portal_host,
        port=s.portal_port,
        debug=False
    )

