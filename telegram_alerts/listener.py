import asyncio
import logging

import asyncpg

from formatting import build_telegram_event, build_malformed_alert

log = logging.getLogger("listener")

FETCH_EVENT_SQL = """
SELECT e.id, e.severity, e.event_type, e.occurred_at, e.src_ip, h.code, e.raw_payload
FROM events e
JOIN honeypots h ON h.id = e.honeypot_id
WHERE e.id = $1
"""

FETCH_REJECTED_SQL = """
SELECT r.boot_id, r.batch_index, r.errors, h.code
FROM rejected_events r
JOIN honeypots h ON h.id = r.honeypot_id
WHERE r.id = $1
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
WHERE severity IN ('critical', 'high') AND occurred_at > now() - interval '1 hour'
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

    event_id_db, severity, event_type, occurred_at, src_ip, honeypot_code, raw_payload = row

    telegram_event = build_telegram_event(
        event_id_db, severity, event_type, occurred_at, src_ip, honeypot_code, raw_payload
    )

    try:
        await notifier.notify(telegram_event)
    except Exception:
        log.exception("fallo enviando alerta para event_id=%s", event_id_db)


async def handle_malformed(pool, notifier, rejected_id):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(FETCH_REJECTED_SQL, rejected_id)

    if row is None:
        return

    boot_id, batch_index, errors, honeypot_code = row
    telegram_event = build_malformed_alert(honeypot_code, boot_id, batch_index, errors)

    try:
        await notifier.notify(telegram_event)
    except Exception:
        log.exception("fallo enviando alerta de rechazo para rejected_id=%s", rejected_id)


def make_notify_callback(pool, notifier, loop, handler):
    def _callback(connection, pid, channel, payload):
        try:
            record_id = int(payload)
        except (TypeError, ValueError):
            log.warning("payload de notify invalido: %s", payload)
            return
        loop.create_task(handler(pool, notifier, record_id))

    return _callback


async def run_listener(cfg, pool, notifier):
    dsn = await build_dsn(cfg)
    listen_conn = await asyncpg.connect(dsn)
    loop = asyncio.get_running_loop()

    alert_callback = make_notify_callback(pool, notifier, loop, handle_alert)
    malformed_callback = make_notify_callback(pool, notifier, loop, handle_malformed)

    await listen_conn.add_listener("honeypot_alert", alert_callback)
    await listen_conn.add_listener("honeypot_malformed", malformed_callback)
    log.info("escuchando honeypot_alert y honeypot_malformed")

    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        await listen_conn.remove_listener("honeypot_alert", alert_callback)
        await listen_conn.remove_listener("honeypot_malformed", malformed_callback)
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
