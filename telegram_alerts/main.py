import asyncio
import logging

from config import Config
from notifier import TelegramNotifier
from commands import CommandListener
from listener import run_listener, estado_handler, build_dsn

import asyncpg

logging.basicConfig(level=logging.INFO)


async def main() -> None:
    cfg = Config()
    dsn = await build_dsn(cfg)
    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5)

    notifier = TelegramNotifier(cfg.TELEGRAM_BOT_TOKEN, cfg.TELEGRAM_CHAT_ID)
    estado = await estado_handler(pool)

    command_listener = CommandListener(
        cfg.TELEGRAM_BOT_TOKEN, cfg.TELEGRAM_CHAT_ID, {"/estado": estado}
    )

    try:
        await asyncio.gather(
            run_listener(cfg, pool, notifier),
            command_listener.run(),
        )
    finally:
        await notifier.close()
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
