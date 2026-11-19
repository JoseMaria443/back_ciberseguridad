import ipaddress
from datetime import datetime, timezone

MAX_TEXT_LENGTH = 8192
MAX_PATH_LENGTH = 4096

ALLOWED_SOURCES = {
    "auditd", "nginx", "flask_login", "docker_events",
    "postgres_log", "pgaudit", "vpc_flow_logs", "ssh_auth",
    "heartbeat_agent",
}

ALLOWED_CATEGORIES = {
    "file_access", "auth", "command", "http", "docker",
    "network_flow", "db", "config_change", "agent_tamper",
    "honeytoken_trigger",
}


class ValidationError(Exception):
    pass


def _require(fields, name, expected_type):
    if name not in fields:
        raise ValidationError("missing field: " + name)
    value = fields[name]
    if not isinstance(value, expected_type):
        raise ValidationError("wrong type for field: " + name)
    return value


def _optional(fields, name, expected_type, default=None):
    if name not in fields or fields[name] is None:
        return default
    value = fields[name]
    if not isinstance(value, expected_type):
        raise ValidationError("wrong type for field: " + name)
    return value


def _bounded_text(value, max_length):
    if len(value) == 0 or len(value) > max_length:
        raise ValidationError("text field out of bounds")
    return value


def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ValidationError("invalid ip address")
    return value


def _valid_timestamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise ValidationError("invalid timestamp")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def validate_envelope(payload):
    if not isinstance(payload, dict):
        raise ValidationError("payload must be an object")

    source = _require(payload, "source", str)
    if source not in ALLOWED_SOURCES:
        raise ValidationError("unknown source")

    category = _require(payload, "category", str)
    if category not in ALLOWED_CATEGORIES:
        raise ValidationError("unknown category")

    occurred_at = _valid_timestamp(_require(payload, "occurred_at", str))

    source_ip = _optional(payload, "source_ip", str)
    if source_ip is not None:
        _valid_ip(source_ip)

    session_id = _optional(payload, "session_id", str)

    fields = _require(payload, "fields", dict)

    return {
        "source": source,
        "category": category,
        "occurred_at": occurred_at,
        "source_ip": source_ip,
        "session_id": session_id,
        "fields": fields,
    }


def validate_category_fields(category, fields):
    if category == "file_access":
        path = _bounded_text(_require(fields, "file_path", str), MAX_PATH_LENGTH)
        action = _require(fields, "action", str)
        if action not in ("read", "list", "stat"):
            raise ValidationError("invalid file access action")
        success = _require(fields, "success", bool)
        bytes_read = _optional(fields, "bytes_read", int)
        return {
            "file_path": path,
            "action": action,
            "success": success,
            "bytes_read": bytes_read,
        }

    if category == "auth":
        method = _require(fields, "auth_method", str)
        if method not in ("password", "public_key", "web_form"):
            raise ValidationError("invalid auth method")
        success = _require(fields, "success", bool)
        username = _optional(fields, "username", str, "")
        failure_reason = _optional(fields, "failure_reason", str, "")
        return {
            "auth_method": method,
            "username": _bounded_text(username, 256) if username else None,
            "success": success,
            "failure_reason": _bounded_text(failure_reason, 512) if failure_reason else None,
        }

    if category == "command":
        command_text = _bounded_text(_require(fields, "command_text", str), MAX_TEXT_LENGTH)
        working_directory = _optional(fields, "working_directory", str)
        exit_code = _optional(fields, "exit_code", int)
        executed_by = _optional(fields, "executed_by", str)
        return {
            "command_text": command_text,
            "working_directory": working_directory,
            "exit_code": exit_code,
            "executed_by": executed_by,
        }

    if category == "http":
        method = _bounded_text(_require(fields, "method", str), 16)
        path = _bounded_text(_require(fields, "path", str), MAX_PATH_LENGTH)
        status_code = _optional(fields, "status_code", int)
        user_agent = _optional(fields, "user_agent", str)
        if user_agent:
            user_agent = _bounded_text(user_agent, 512)
        return {
            "method": method,
            "path": path,
            "status_code": status_code,
            "user_agent": user_agent,
        }

    if category == "docker":
        action = _bounded_text(_require(fields, "action", str), 64)
        container_id = _optional(fields, "container_id", str)
        image = _optional(fields, "image", str)
        used_socket = _optional(fields, "used_socket", bool, False)
        return {
            "action": action,
            "container_id": container_id,
            "image": image,
            "used_socket": used_socket,
        }

    if category == "network_flow":
        src_ip = _valid_ip(_require(fields, "src_ip", str))
        dst_ip = _valid_ip(_require(fields, "dst_ip", str))
        protocol = _bounded_text(_require(fields, "protocol", str), 16)
        action = _require(fields, "action", str)
        if action not in ("accept", "reject"):
            raise ValidationError("invalid flow action")
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": _optional(fields, "src_port", int),
            "dst_port": _optional(fields, "dst_port", int),
            "protocol": protocol,
            "bytes_transferred": _optional(fields, "bytes_transferred", int),
            "action": action,
        }

    if category == "db":
        db_role = _bounded_text(_require(fields, "db_role", str), 128)
        statement_type = _bounded_text(_require(fields, "statement_type", str), 32)
        query_text = _optional(fields, "query_text", str)
        if query_text:
            query_text = _bounded_text(query_text, MAX_TEXT_LENGTH)
        return {
            "db_role": db_role,
            "statement_type": statement_type,
            "query_text": query_text,
            "rows_affected": _optional(fields, "rows_affected", int),
            "auth_result": _optional(fields, "auth_result", str),
        }

    if category == "config_change":
        target = _bounded_text(_require(fields, "target", str), 256)
        change_type = _bounded_text(_require(fields, "change_type", str), 64)
        return {"target": target, "change_type": change_type}

    if category == "agent_tamper":
        target_service = _bounded_text(_require(fields, "target_service", str), 128)
        attempted_action = _bounded_text(_require(fields, "attempted_action", str), 256)
        return {"target_service": target_service, "attempted_action": attempted_action}

    if category == "honeytoken_trigger":
        honeytoken_id = _bounded_text(_require(fields, "honeytoken_id", str), 64)
        context = _optional(fields, "context", str)
        if context:
            context = _bounded_text(context, 1024)
        return {"honeytoken_id": honeytoken_id, "context": context}

    raise ValidationError("unsupported category")
