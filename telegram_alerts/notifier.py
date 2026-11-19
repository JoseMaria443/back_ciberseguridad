import asyncio
import html
import logging
import time

import httpx

log = logging.getLogger("notifier")

API_URL = "https://api.telegram.org/bot{token}/{method}"

SEVERITY_TEXT = {1: "Baja", 2: "Media", 3: "Alta", 4: "Critica", 5: "EMERGENCIA"}

TITLES = {
    "file_access": "Lectura de archivo sensible",
    "auth": "Evento de autenticacion",
    "command": "Ejecucion de comando",
    "docker": "Uso del socket de Docker",
    "db": "Operacion sensible en base de datos",
    "config_change": "Cambio de configuracion critica",
    "agent_tamper": "Intento de manipular el agente",
    "honeytoken_trigger": "Honeytoken disparado",
    "network_flow": "Flujo de red rechazado",
    "http": "Acceso HTTP",
}

COOLDOWN = {
    "file_access": 0,
    "auth": 60,
    "command": 0,
    "docker": 120,
    "db": 60,
    "config_change": 0,
    "agent_tamper": 0,
    "honeytoken_trigger": 0,
    "network_flow": 300,
    "http": 0,
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

    def _in_cooldown(self, honeypot_code: str, category: str) -> bool:
        seconds = COOLDOWN.get(category, 30)
        if seconds == 0:
            return False
        key = (honeypot_code, category)
        now = time.time()
        if now - self._cooldowns.get(key, 0) < seconds:
            return True
        self._cooldowns[key] = now
        return False

    async def notify(self, event: dict) -> None:
        category = event.get("category", "unknown")
        honeypot_code = event.get("sensor", "?")

        if self._in_cooldown(honeypot_code, category):
            return

        await self.send(self.format_event(event))

    def format_event(self, e: dict) -> str:
        sev = int(e.get("severity", 1))
        level = SEVERITY_TEXT.get(sev, "Baja")
        title = TITLES.get(e.get("category"), "Evento")
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
        if e.get("stage"):
            lines.append(f"Contexto: <b>{esc(e['stage'])}</b>")
        lines.append(f"Hora: {esc(e.get('time', time.strftime('%Y-%m-%d %H:%M:%S')))}")
        return "\n".join(lines)

    async def close(self) -> None:
        await self._client.aclose()
