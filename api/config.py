import json
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

    MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", "2097152"))

    JWT_ALGORITHM = "RS256"
    JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "honeypot-ingest")
    JWT_ISSUER = os.environ.get("JWT_ISSUER", "honeypot-fleet")

    AGENT_PUBLIC_KEYS_PATH = os.environ["AGENT_PUBLIC_KEYS_PATH"]

    @staticmethod
    def load_agent_public_keys():
        with open(Config.AGENT_PUBLIC_KEYS_PATH, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        return {entry["kid"]: entry["public_key_pem"] for entry in raw}
