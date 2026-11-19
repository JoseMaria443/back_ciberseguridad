import asyncio
import logging

import httpx

log = logging.getLogger("commands")


class CommandListener:
    def __init__(self, token: str, chat_id: str, handlers: dict):
        self.token = token
        self.chat_id = str(chat_id)
        self.handlers = handlers
        self.offset = 0
        self.base = f"https://api.telegram.org/bot{token}"

    async def _reply(self, client: httpx.AsyncClient, text: str) -> None:
        await client.post(
            f"{self.base}/sendMessage",
            json={"chat_id": self.chat_id, "text": text[:4000], "parse_mode": "HTML"},
        )

    async def run(self) -> None:
        async with httpx.AsyncClient(timeout=40) as client:
            while True:
                try:
                    r = await client.get(
                        f"{self.base}/getUpdates",
                        params={"timeout": 30, "offset": self.offset},
                    )
                    for upd in r.json().get("result", []):
                        self.offset = upd["update_id"] + 1
                        msg = upd.get("message") or {}
                        if str(msg.get("chat", {}).get("id")) != self.chat_id:
                            continue
                        parts = (msg.get("text") or "").split("@")[0].split()
                        if not parts:
                            continue
                        handler = self.handlers.get(parts[0])
                        if handler:
                            await self._reply(client, await handler())
                except Exception:
                    log.exception("Error en el polling de comandos")
                    await asyncio.sleep(5)
