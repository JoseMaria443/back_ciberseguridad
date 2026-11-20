import asyncio
import html
import logging
import time

import httpx

log = logging.getLogger("notifier")

API_URL = "https://api.telegram.org/bot{token}/{method}"

TITLES = {
    "http.request": "Acceso HTTP",
    "auth.attempt": "Intento de autenticacion",
    "file.access": "Lectura de archivo",
    "command.exec": "Ejecucion de comando",
    "sql.statement": "Operacion en base de datos",
    "session": "Apertura o cierre de sesion",
    "agent.malformed": "Lote rechazado por el colector",
}

COOLDOWN = {
    "http.request": 60,
    "auth.attempt": 60,
    "file.access": 0,
    "command.exec": 0,
    "sql.statement": 60,
    "session": 120,
    "agent.malformed": 0,
}


def esc(value, limit=300) -> str:
    text = str(value) if value is not None else "-"
    if len(text) > limit:
        text = text[:limit] + "…"
    return html.escape(text)


class TelegramNotifier:
    def __init__(self, token: str, chat_id: str, min_interval: float = 1.1):
        self.token = token
        self.chat_id = str(chat_id)
        self.min_interval = min_interval
        self._client = httpx.AsyncClient(timeout=15)
        self._lock = asyncio.Lock()
        self._last_sent = 0.0
        self._cooldowns: dict[tuple, float] = {}

    async def send(self, text: str) -> bool:
        url = API_URL.format(token=self.token, method="sendMessage")
        payload = {
            "chat_id": self.chat_id,
            "text": text[:4000],
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        async with self._lock:
            for _ in range(3):
                wait = self.min_interval - (time.monotonic() - self._last_sent)
                if wait > 0:
                    await asyncio.sleep(wait)
                try:
                    r = await self._client.post(url, json=payload)
                except httpx.HTTPError as exc:
                    log.warning("Error de red enviando a Telegram: %s", exc)
                    await asyncio.sleep(2)
                    continue
                self._last_sent = time.monotonic()
                if r.status_code == 200:
                    return True
                if r.status_code == 429:
                    retry = r.json().get("parameters", {}).get("retry_after", 5)
                    log.warning("Telegram 429, esperando %ss", retry)
                    await asyncio.sleep(retry + 1)
                    continue
                log.error("Telegram respondio %s: %s", r.status_code, r.text)
                return False
        return False

    def _in_cooldown(self, honeypot_code: str, event_type: str) -> bool:
        seconds = COOLDOWN.get(event_type, 30)
        if seconds == 0:
            return False
        key = (honeypot_code, event_type)
        now = time.time()
        if now - self._cooldowns.get(key, 0) < seconds:
            return True
        self._cooldowns[key] = now
        return False

    async def notify(self, event: dict) -> None:
        event_type = event.get("event_type", "unknown")
        honeypot_code = event.get("sensor", "?")

        if self._in_cooldown(honeypot_code, event_type):
            return

        await self.send(self.format_event(event))

    def format_event(self, e: dict) -> str:
        sev = int(e.get("severity", 1))
        level = e.get("severity_text", "Baja")
        title = TITLES.get(e.get("event_type"), "Evento")
        lines = [
            f"<b>{esc(title)}</b>",
            f"Severidad: {esc(level)} ({sev}/5)",
            f"Honeypot: <b>{esc(e.get('sensor'))}</b>",
        ]
        if e.get("src_ip"):
            lines.append(f"IP: <code>{esc(e.get('src_ip'))}</code>")
        if e.get("username") is not None:
            lines.append(f"Usuario: <code>{esc(e.get('username'))}</code>")
        if e.get("command"):
            lines.append(f"Comando: <code>{esc(e['command'], 300)}</code>")
        if e.get("path"):
            lines.append(f"Ruta: <code>{esc(e['path'], 300)}</code>")
        if e.get("detail"):
            lines.append(f"Detalle: {esc(e['detail'], 300)}")
        lines.append(f"Hora: {esc(e.get('time', time.strftime('%Y-%m-%d %H:%M:%S')))}")
        return "\n".join(lines)

    async def close(self) -> None:
        await self._client.aclose()
