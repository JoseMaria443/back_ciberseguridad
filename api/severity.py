SENSITIVE_PATH_MARKERS = (
    ".ssh/",
    "authorized_keys",
    ".bash_history",
    "sshd_config",
)


def _path_is_sensitive(path: str | None) -> bool:
    if not path:
        return False
    lowered = path.lower()
    return any(marker in lowered for marker in SENSITIVE_PATH_MARKERS)


def resolve_severity(event) -> str:
    event_type = event.event_type
    data = event.data

    if event_type == "file.access":
        if _path_is_sensitive(data.path):
            return "critical"
        return "low"

    if event_type == "command.exec":
        return "high"

    if event_type == "auth.attempt":
        if not data.success:
            return "high"
        return "medium"

    if event_type == "sql.statement":
        tag = (data.command_tag or "").upper()
        if tag in ("COPY", "DELETE", "DROP", "TRUNCATE", "ALTER"):
            return "high"
        return "medium"

    if event_type == "session":
        return "medium"

    if event_type == "http.request":
        if data.status >= 500:
            return "medium"
        return "low"

    return "medium"


def resolve_malformed_severity() -> str:
    return "high"
