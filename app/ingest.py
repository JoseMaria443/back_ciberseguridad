from app.db import get_cursor
from app.priority import resolve_priority
import json
import uuid

_source_ids = {}
_category_ids = {}


def load_lookups():
    with get_cursor() as cur:
        cur.execute("SELECT id, name FROM event_sources")
        for row in cur.fetchall():
            _source_ids[row[1]] = row[0]

        cur.execute("SELECT id, name FROM event_categories")
        for row in cur.fetchall():
            _category_ids[row[1]] = row[0]


def resolve_session(cur, honeypot_id, session_id, source_ip):
    if session_id is None:
        return None

    try:
        parsed = uuid.UUID(session_id)
    except ValueError:
        return None

    cur.execute(
        "SELECT id FROM sessions WHERE id = %s AND honeypot_id = %s",
        (str(parsed), honeypot_id),
    )
    row = cur.fetchone()
    if row is not None:
        return row[0]

    cur.execute(
        """
        INSERT INTO sessions (id, honeypot_id, protocol, source_ip, started_at)
        VALUES (%s, %s, %s, %s, now())
        RETURNING id
        """,
        (str(parsed), honeypot_id, "http", source_ip),
    )
    return cur.fetchone()[0]


def insert_event(honeypot_id, session_id, source_name, category_name, occurred_at, source_ip, raw_fields, parsed_fields):
    source_id = _source_ids.get(source_name)
    category_id = _category_ids.get(category_name)
    if source_id is None or category_id is None:
        raise ValueError("lookup values not loaded")

    priority = resolve_priority(category_name, parsed_fields)

    with get_cursor() as cur:
        resolved_session_id = resolve_session(cur, honeypot_id, session_id, source_ip)

        cur.execute(
            """
            INSERT INTO events (honeypot_id, session_id, source_id, category_id, priority, occurred_at, source_ip, raw_payload)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                honeypot_id,
                resolved_session_id,
                source_id,
                category_id,
                priority,
                occurred_at,
                source_ip,
                json.dumps(raw_fields),
            ),
        )
        event_id = cur.fetchone()[0]

        _insert_child_row(cur, event_id, category_name, parsed_fields, honeypot_id)

        return event_id, priority


def _insert_child_row(cur, event_id, category_name, fields, honeypot_id):
    if category_name == "file_access":
        cur.execute(
            """
            INSERT INTO file_access_events (event_id, file_path, action, success, bytes_read, is_sensitive)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                event_id,
                fields["file_path"],
                fields["action"],
                fields["success"],
                fields.get("bytes_read"),
                fields.get("file_path", "").lower().find(".ssh/") != -1
                or "authorized_keys" in fields.get("file_path", "").lower()
                or ".bash_history" in fields.get("file_path", "").lower(),
            ),
        )
        return

    if category_name == "auth":
        cur.execute(
            """
            INSERT INTO auth_events (event_id, auth_method, username, success, failure_reason)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (event_id, fields["auth_method"], fields.get("username"), fields["success"], fields.get("failure_reason")),
        )
        return

    if category_name == "command":
        cur.execute(
            """
            INSERT INTO command_events (event_id, command_text, working_directory, exit_code, executed_by)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (event_id, fields["command_text"], fields.get("working_directory"), fields.get("exit_code"), fields.get("executed_by")),
        )
        return

    if category_name == "http":
        cur.execute(
            """
            INSERT INTO http_events (event_id, method, path, status_code, user_agent)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (event_id, fields["method"], fields["path"], fields.get("status_code"), fields.get("user_agent")),
        )
        return

    if category_name == "docker":
        cur.execute(
            """
            INSERT INTO docker_event_details (event_id, container_id, image, action, used_socket)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (event_id, fields.get("container_id"), fields.get("image"), fields["action"], fields.get("used_socket", False)),
        )
        return

    if category_name == "network_flow":
        cur.execute(
            """
            INSERT INTO network_flow_events (event_id, src_ip, dst_ip, src_port, dst_port, protocol, bytes_transferred, action)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                event_id,
                fields["src_ip"],
                fields["dst_ip"],
                fields.get("src_port"),
                fields.get("dst_port"),
                fields["protocol"],
                fields.get("bytes_transferred"),
                fields["action"],
            ),
        )
        return

    if category_name == "db":
        cur.execute(
            """
            INSERT INTO db_events (event_id, db_role, statement_type, query_text, rows_affected, auth_result)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (event_id, fields["db_role"], fields["statement_type"], fields.get("query_text"), fields.get("rows_affected"), fields.get("auth_result")),
        )
        return

    if category_name == "config_change":
        cur.execute(
            """
            INSERT INTO config_change_events (event_id, target, change_type)
            VALUES (%s, %s, %s)
            """,
            (event_id, fields["target"], fields["change_type"]),
        )
        return

    if category_name == "agent_tamper":
        cur.execute(
            """
            INSERT INTO agent_tamper_events (event_id, target_service, attempted_action)
            VALUES (%s, %s, %s)
            """,
            (event_id, fields["target_service"], fields["attempted_action"]),
        )
        return

    if category_name == "honeytoken_trigger":
        cur.execute(
            "SELECT id FROM honeytokens WHERE id = %s AND honeypot_id = %s",
            (fields["honeytoken_id"], honeypot_id),
        )
        row = cur.fetchone()
        if row is None:
            raise ValueError("unknown honeytoken for this honeypot")

        cur.execute(
            """
            INSERT INTO honeytoken_trigger_events (event_id, honeytoken_id, context)
            VALUES (%s, %s, %s)
            """,
            (event_id, row[0], fields.get("context")),
        )
        return

    raise ValueError("unhandled category")


def record_heartbeat(honeypot_id):
    with get_cursor() as cur:
        cur.execute(
            "INSERT INTO heartbeats (honeypot_id, status) VALUES (%s, %s)",
            (honeypot_id, "alive"),
        )
