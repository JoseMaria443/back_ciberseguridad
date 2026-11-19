PRIORITY_TO_SEVERITY = {
    "critical": 5,
    "high": 4,
    "medium": 2,
    "low": 1,
}

STAGE_BY_CATEGORY = {
    "file_access": "Lectura de archivo sensible del honeypot",
    "auth": "Intento de autenticacion",
    "command": "Ejecucion de comandos tras acceso",
    "docker": "Interaccion con el socket de Docker",
    "db": "Consulta u operacion sensible en PostgreSQL",
    "config_change": "Modificacion de configuracion critica",
    "agent_tamper": "Intento de desactivar auditd o el agente",
    "honeytoken_trigger": "Uso de un honeytoken sembrado",
    "network_flow": "Trafico de red rechazado",
    "http": "Acceso al servidor web",
}


def build_telegram_event(event_id, priority, occurred_at, source_ip, honeypot_code, category, raw_payload):
    severity = PRIORITY_TO_SEVERITY.get(priority, 1)

    telegram_event = {
        "event_id": event_id,
        "category": category,
        "sensor": honeypot_code,
        "src_ip": source_ip,
        "severity": severity,
        "stage": STAGE_BY_CATEGORY.get(category, category),
        "time": occurred_at.isoformat(sep=" ", timespec="seconds"),
    }

    if category == "file_access":
        telegram_event["path"] = raw_payload.get("file_path")

    elif category == "auth":
        telegram_event["username"] = raw_payload.get("username")
        telegram_event["detail"] = "exito" if raw_payload.get("success") else "fallo"

    elif category == "command":
        telegram_event["command"] = raw_payload.get("command_text")

    elif category == "docker":
        telegram_event["detail"] = raw_payload.get("action")

    elif category == "db":
        telegram_event["detail"] = raw_payload.get("statement_type")

    elif category == "config_change":
        telegram_event["detail"] = raw_payload.get("target")

    elif category == "agent_tamper":
        telegram_event["detail"] = raw_payload.get("attempted_action")

    elif category == "honeytoken_trigger":
        telegram_event["detail"] = raw_payload.get("context")

    elif category == "network_flow":
        telegram_event["detail"] = raw_payload.get("dst_ip")

    elif category == "http":
        telegram_event["path"] = raw_payload.get("path")

    return telegram_event
