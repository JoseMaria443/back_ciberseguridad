SEVERITY_TEXT = {
    "critical": "Critica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
}

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 2, "low": 1}

TITLES = {
    "http.request": "Acceso HTTP",
    "auth.attempt": "Intento de autenticacion",
    "file.access": "Lectura de archivo",
    "command.exec": "Ejecucion de comando",
    "sql.statement": "Operacion en base de datos",
    "session": "Apertura o cierre de sesion",
}


def build_telegram_event(event_id, severity, event_type, occurred_at, src_ip, honeypot_code, raw_payload):
    data = raw_payload.get("data", {})

    telegram_event = {
        "event_id": event_id,
        "event_type": event_type,
        "sensor": honeypot_code,
        "src_ip": src_ip,
        "severity": SEVERITY_RANK.get(severity, 1),
        "severity_text": SEVERITY_TEXT.get(severity, severity),
        "time": occurred_at.isoformat(sep=" ", timespec="seconds"),
    }

    if event_type == "file.access":
        telegram_event["path"] = data.get("path")
        telegram_event["detail"] = data.get("operation")

    elif event_type == "auth.attempt":
        telegram_event["username"] = data.get("username")
        telegram_event["detail"] = "exito" if data.get("success") else "fallo"

    elif event_type == "command.exec":
        telegram_event["command"] = data.get("command_line")

    elif event_type == "sql.statement":
        telegram_event["detail"] = data.get("command_tag")
        telegram_event["path"] = data.get("database")

    elif event_type == "session":
        telegram_event["detail"] = f"{data.get('action')} ({data.get('kind')})"
        telegram_event["username"] = data.get("auth_user")

    elif event_type == "http.request":
        telegram_event["path"] = data.get("path")
        telegram_event["detail"] = f"{data.get('method')} -> {data.get('status')}"

    return telegram_event


def build_malformed_alert(honeypot_code, boot_id, batch_index, errors):
    return {
        "event_type": "agent.malformed",
        "sensor": honeypot_code,
        "severity": 4,
        "severity_text": "Alta",
        "detail": f"boot_id={boot_id} indice={batch_index} errores={len(errors)}",
    }
