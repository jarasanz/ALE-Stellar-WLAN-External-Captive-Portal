from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
    # Shared DB + logs
    data_dir: str = "data"
    db_path: str = "data/cp.db"
    portal_log_jsonl: str = "data/portal_events.jsonl"
    radius_log_jsonl: str = "data/radius_events.jsonl"

    # Portal listener
    portal_host: str = "0.0.0.0"
    portal_port: int = 80

    # RADIUS listener (UDP/1812,1813)
    radius_host: str = "0.0.0.0"
    radius_auth_port: int = 1812
    radius_acct_port: int = 1813
    radius_secret: bytes = b"sharedsecret"  # MUST match Stellar SSID config

    # Cache behavior
    cache_ttl_seconds: int = 6 * 3600  # 6 hours lab cache

    # AP Login POST target (as per memo)
    ap_login_url: str = "http://cportal.al-enterprise.com/login"

    # Optional RADIUS policy
    session_timeout_seconds: int = 3600  # 1 hour
    
    # Small admin token
    admin_token: str = ""  # set to a random string to require ?token=... on /admin

