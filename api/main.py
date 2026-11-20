from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from sysmeta_schema import EventAdapter, Heartbeat, RawBatch
from api.auth import authenticate_agent, load_keys, Honeypot
from api.config import Config
from api.db import close_pool, get_pool, init_pool
from api.handlers import HANDLERS, store_rejected


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_keys()
    await init_pool()
    yield
    await close_pool()


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None and int(content_length) > Config.MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "cuerpo demasiado grande"})
    return await call_next(request)


@app.post("/v1/ingest", status_code=202)
async def ingest(batch: RawBatch, hp: Honeypot = Depends(authenticate_agent)):
    accepted = []
    rejected = []

    for index, raw in enumerate(batch.events):
        try:
            accepted.append(EventAdapter.validate_python(raw))
        except ValidationError as exc:
            rejected.append((index, raw, exc.errors(include_input=False, include_url=False)))

    pool = get_pool()
    async with pool.acquire() as conn, conn.transaction():
        for event in accepted:
            handler = HANDLERS[type(event)]
            await handler(conn, hp, batch.boot_id, event)

        for index, raw, errors in rejected:
            await store_rejected(conn, hp, batch.boot_id, index, raw, errors)

    max_seq = max((event.seq for event in accepted), default=None)

    return {"accepted": len(accepted), "rejected": len(rejected), "ack_seq": max_seq}


@app.post("/v1/heartbeat", status_code=202)
async def heartbeat(hb: Heartbeat, hp: Honeypot = Depends(authenticate_agent)):
    pool = get_pool()
    await pool.execute(
        """
        INSERT INTO heartbeats
            (honeypot_id, boot_id, seq, sent_at, agent_version, auditd_ok, rules_immutable, spool_pending, last_event_seq)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        """,
        hp.id,
        hb.boot_id,
        hb.seq,
        hb.sent_at,
        hb.agent_version,
        hb.auditd_ok,
        hb.rules_immutable,
        hb.spool_pending,
        hb.last_event_seq,
    )
    return {"status": "ok"}


@app.get("/v1/health")
async def health():
    return {"status": "ok"}
