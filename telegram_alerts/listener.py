import asyncio
import logging

import asyncpg

from formatting import build_telegram_event

log = logging.getLogger("listener")

FETCH_EVENT_SQL = """
SELECT e.id, e.priority, e.occurred_at, e.source_ip, h.code, ec.name, e.raw_payload
FROM events e
JOIN honeypots h ON h.id = e.honeypot_id
JOIN event_categories ec ON ec.id = e.category_id
WHERE e.id = $1
"""

LATEST_HEARTBEATS_SQL = """
SELECT h.code, MAX(hb.received_at)
FROM honeypots h
LEFT JOIN heartbeats hb ON hb.honeypot_id = h.id
GROUP BY h.code
ORDER BY h.code
"""

RECENT_CRITICAL_COUNT_SQL = """
SELECT count(*) FROM events
WHERE priority IN ('critical', 'high') AND occurred_at > now() - interval '1 hour'
"""


async def build_dsn(cfg):
    return (
        f"postgresql://{cfg.DB_USER}:{cfg.DB_PASSWORD}"
        f"@{cfg.DB_HOST}:{cfg.DB_PORT}/{cfg.DB_NAME}?sslmode={cfg.DB_SSLMODE}"
    )


async def handle_alert(pool, notifier, event_id):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(FETCH_EVENT_SQL, event_id)

    if row is None:
        return

    event_id_db, priority, occurred_at, source_ip, honeypot_code, category, raw_payload = row

    telegram_event = build_telegram_event(
        event_id_db, priority, occurred_at, source_ip, honeypot_code, category, raw_payload
    )

    try:
        await notifier.notify(telegram_event)
    except Exception:
        log.exception("fallo enviando alerta para event_id=%s", event_id_db)


def make_notify_callback(pool, notifier, loop):
    def _callback(connection, pid, channel, payload):
        try:
            event_id = int(payload)
        except (TypeError, ValueError):
            log.warning("payload de notify invalido: %s", payload)
            return
        loop.create_task(handle_alert(pool, notifier, event_id))

    return _callback


async def run_listener(cfg, pool, notifier):
    dsn = await build_dsn(cfg)
    listen_conn = await asyncpg.connect(dsn)
    loop = asyncio.get_running_loop()
    callback = make_notify_callback(pool, notifier, loop)

    await listen_conn.add_listener("honeypot_alert", callback)
    log.info("escuchando honeypot_alert")

    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        await listen_conn.remove_listener("honeypot_alert", callback)
        await listen_conn.close()


async def estado_handler(pool):
    async def _handler():
        async with pool.acquire() as conn:
            heartbeats = await conn.fetch(LATEST_HEARTBEATS_SQL)
            recent = await conn.fetchval(RECENT_CRITICAL_COUNT_SQL)

        lines = ["<b>Estado de honeypots</b>"]
        for code, last_seen in heartbeats:
            if last_seen is None:
                lines.append(f"• {code}: sin heartbeat registrado")
            else:
                lines.append(f"• {code}: ultimo heartbeat {last_seen.isoformat(sep=' ', timespec='seconds')}")
        lines.append(f"Eventos criticos/altos en la ultima hora: <b>{recent}</b>")
        return "\n".join(lines)

    return _handler
