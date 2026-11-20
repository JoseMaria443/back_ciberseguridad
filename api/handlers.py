import json

from sysmeta_schema import (
    HttpRequestEvent,
    AuthAttemptEvent,
    FileAccessEvent,
    CommandExecEvent,
    SqlStatementEvent,
    SessionEvent,
)
from api.severity import resolve_severity
from api.sessions import resolve_session_id, apply_session_event

INSERT_EVENT_SQL = """
INSERT INTO events
    (honeypot_id, boot_id, seq, session_id, event_type, severity, source, occurred_at, src_ip, raw_payload)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (honeypot_id, boot_id, seq) DO NOTHING
RETURNING id
"""


async def _insert_core_event(conn, hp, boot_id, event, session_id):
    row = await conn.fetchrow(
        INSERT_EVENT_SQL,
        hp.id,
        boot_id,
        event.seq,
        session_id,
        event.event_type,
        resolve_severity(event),
        event.source.value,
        event.occurred_at,
        str(event.src_ip) if event.src_ip else None,
        json.dumps(event.model_dump(mode="json")),
    )
    return row["id"] if row is not None else None


async def handle_http_request(conn, hp, boot_id, event: HttpRequestEvent):
    session_id = await resolve_session_id(conn, hp.id, boot_id, event.session_ref)
    event_id = await _insert_core_event(conn, hp, boot_id, event, session_id)
    if event_id is None:
        return

    data = event.data
    await conn.execute(
        """
        INSERT INTO http_request_events
            (event_id, method, path, query, status, bytes, user_agent, referer, body_excerpt)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        """,
        event_id,
        data.method,
        data.path,
        data.query,
        data.status,
        data.bytes,
        data.user_agent,
        data.referer,
        data.body_excerpt,
    )


async def handle_auth_attempt(conn, hp, boot_id, event: AuthAttemptEvent):
    session_id = await resolve_session_id(conn, hp.id, boot_id, event.session_ref)
    event_id = await _insert_core_event(conn, hp, boot_id, event, session_id)
    if event_id is None:
        return

    data = event.data
    await conn.execute(
        """
        INSERT INTO auth_attempt_events
            (event_id, service, username, key_fingerprint, success)
        VALUES ($1, $2, $3, $4, $5)
        """,
        event_id,
        data.service,
        data.username,
        data.key_fingerprint,
        data.success,
    )


async def handle_file_access(conn, hp, boot_id, event: FileAccessEvent):
    session_id = await resolve_session_id(conn, hp.id, boot_id, event.session_ref)
    event_id = await _insert_core_event(conn, hp, boot_id, event, session_id)
    if event_id is None:
        return

    data = event.data
    await conn.execute(
        """
        INSERT INTO file_access_events
            (event_id, path, operation, via, success)
        VALUES ($1, $2, $3, $4, $5)
        """,
        event_id,
        data.path,
        data.operation,
        data.via,
        data.success,
    )


async def handle_command_exec(conn, hp, boot_id, event: CommandExecEvent):
    session_id = await resolve_session_id(conn, hp.id, boot_id, event.session_ref)
    event_id = await _insert_core_event(conn, hp, boot_id, event, session_id)
    if event_id is None:
        return

    data = event.data
    await conn.execute(
        """
        INSERT INTO command_exec_events
            (event_id, command_line, truncated, cwd, uid, auid, exit_code)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
        event_id,
        data.command_line,
        data.truncated,
        data.cwd,
        data.uid,
        data.auid,
        data.exit_code,
    )


async def handle_sql_statement(conn, hp, boot_id, event: SqlStatementEvent):
    session_id = await resolve_session_id(conn, hp.id, boot_id, event.session_ref)
    event_id = await _insert_core_event(conn, hp, boot_id, event, session_id)
    if event_id is None:
        return

    data = event.data
    await conn.execute(
        """
        INSERT INTO sql_statement_events
            (event_id, db_user, database, command_tag, statement, truncated)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        event_id,
        data.db_user,
        data.database,
        data.command_tag,
        data.statement,
        data.truncated,
    )


async def handle_session(conn, hp, boot_id, event: SessionEvent):
    session_id = await apply_session_event(conn, hp.id, boot_id, event)
    await _insert_core_event(conn, hp, boot_id, event, session_id)


HANDLERS = {
    HttpRequestEvent: handle_http_request,
    AuthAttemptEvent: handle_auth_attempt,
    FileAccessEvent: handle_file_access,
    CommandExecEvent: handle_command_exec,
    SqlStatementEvent: handle_sql_statement,
    SessionEvent: handle_session,
}


async def store_rejected(conn, hp, boot_id, batch_index, raw, errors):
    excerpt = json.dumps(raw)[:4000]
    await conn.execute(
        """
        INSERT INTO rejected_events (honeypot_id, boot_id, batch_index, errors, raw_excerpt)
        VALUES ($1, $2, $3, $4, $5)
        """,
        hp.id,
        boot_id,
        batch_index,
        json.dumps(errors),
        excerpt,
    )
