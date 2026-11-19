import hashlib
import time
import threading
from app.db import get_cursor
from app.config import Config

_rate_lock = threading.Lock()
_rate_state = {}


def hash_token(raw_token):
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def resolve_honeypot(raw_token):
    if not raw_token or len(raw_token) < 32 or len(raw_token) > 256:
        return None

    token_hash = hash_token(raw_token)

    with get_cursor() as cur:
        cur.execute(
            """
            SELECT it.honeypot_id, h.code
            FROM ingest_tokens it
            JOIN honeypots h ON h.id = it.honeypot_id
            WHERE it.token_hash = %s AND it.revoked_at IS NULL
            """,
            (token_hash,),
        )
        row = cur.fetchone()
        if row is None:
            return None

        honeypot_id, honeypot_code = row
        cur.execute(
            "UPDATE ingest_tokens SET last_used_at = now() WHERE token_hash = %s",
            (token_hash,),
        )
        return {"honeypot_id": honeypot_id, "honeypot_code": honeypot_code}


def check_rate_limit(honeypot_id):
    now = time.time()
    window_start = now - 60
    limit = Config.TOKEN_RATE_LIMIT_PER_MINUTE

    with _rate_lock:
        timestamps = _rate_state.get(honeypot_id, [])
        timestamps = [t for t in timestamps if t > window_start]
        if len(timestamps) >= limit:
            _rate_state[honeypot_id] = timestamps
            return False
        timestamps.append(now)
        _rate_state[honeypot_id] = timestamps
        return True
