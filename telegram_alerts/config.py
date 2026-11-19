import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
    TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]
    DB_HOST = os.environ["DB_HOST"]
    DB_PORT = int(os.environ.get("DB_PORT", "5432"))
    DB_NAME = os.environ["DB_NAME"]
    DB_USER = os.environ.get("ALERTS_DB_USER", "honeypot_reader")
    DB_PASSWORD = os.environ["ALERTS_DB_PASSWORD"]
    DB_SSLMODE = os.environ.get("DB_SSLMODE", "require")
