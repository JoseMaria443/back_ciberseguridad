from dataclasses import dataclass

import jwt
from fastapi import Header, HTTPException

from api.config import Config
from api.db import get_pool

_public_keys: dict[str, str] = {}


def load_keys() -> None:
    global _public_keys
    _public_keys = Config.load_agent_public_keys()


@dataclass(frozen=True)
class Honeypot:
    id: int
    code: str


async def _lookup_honeypot(code: str) -> Honeypot:
    pool = get_pool()
    row = await pool.fetchrow(
        "SELECT id, code FROM honeypots WHERE code = $1 AND revoked_at IS NULL",
        code,
    )
    if row is None:
        raise HTTPException(status_code=401, detail="honeypot desconocido o revocado")
    return Honeypot(id=row["id"], code=row["code"])


async def authenticate_agent(authorization: str | None = Header(default=None)) -> Honeypot:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="falta token")

    token = authorization[len("Bearer "):].strip()

    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="token malformado")

    kid = unverified_header.get("kid")
    if kid is None or kid not in _public_keys:
        raise HTTPException(status_code=401, detail="kid desconocido")

    public_key = _public_keys[kid]

    try:
        jwt.decode(
            token,
            public_key,
            algorithms=[Config.JWT_ALGORITHM],
            audience=Config.JWT_AUDIENCE,
            issuer=Config.JWT_ISSUER,
            options={"require": ["exp", "iat"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expirado")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="token invalido")

    return await _lookup_honeypot(kid)
