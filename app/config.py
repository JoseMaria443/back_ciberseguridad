import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    DB_HOST = os.environ["DB_HOST"]
    DB_PORT = int(os.environ.get("DB_PORT", "5432"))
    DB_NAME = os.environ["DB_NAME"]
    DB_USER = os.environ["DB_USER"]
    DB_PASSWORD = os.environ["DB_PASSWORD"]
    DB_SSLMODE = os.environ.get("DB_SSLMODE", "require")
    MAX_CONTENT_LENGTH = int(os.environ.get("FLASK_MAX_CONTENT_LENGTH", "65536"))
    TOKEN_RATE_LIMIT_PER_MINUTE = int(os.environ.get("TOKEN_RATE_LIMIT_PER_MINUTE", "120"))
