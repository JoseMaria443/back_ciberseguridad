SENSITIVE_PATH_MARKERS = (
    ".ssh/",
    "authorized_keys",
    ".bash_history",
    "sshd_config",
)


def _path_is_sensitive(path):
    lowered = path.lower()
    return any(marker in lowered for marker in SENSITIVE_PATH_MARKERS)


def resolve_priority(category_name, fields):
    if category_name == "agent_tamper":
        return "critical"

    if category_name == "honeytoken_trigger":
        return "critical"

    if category_name == "config_change":
        return "critical"

    if category_name == "file_access":
        if _path_is_sensitive(fields.get("file_path", "")):
            return "critical"
        return "low"

    if category_name == "command":
        return "high"

    if category_name == "auth":
        return "high" if not fields.get("success", True) else "medium"

    if category_name == "docker":
        return "high" if fields.get("used_socket") else "medium"

    if category_name == "db":
        statement_type = (fields.get("statement_type") or "").upper()
        if statement_type in ("COPY", "DELETE", "DROP"):
            return "high"
        return "medium"

    if category_name == "network_flow":
        return "medium" if fields.get("action") == "reject" else "low"

    if category_name == "http":
        return "low"

    return "medium"
