import sys
import secrets
import hashlib
import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()


def main():
    if len(sys.argv) != 2:
        print("usage: python create_honeypot_token.py <honeypot_code>")
        sys.exit(1)

    honeypot_code = sys.argv[1]
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    conn = psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ.get("DB_PORT", "5432")),
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        sslmode=os.environ.get("DB_SSLMODE", "require"),
    )
    cur = conn.cursor()
    cur.execute("SELECT id FROM honeypots WHERE code = %s", (honeypot_code,))
    row = cur.fetchone()
    if row is None:
        print("honeypot not found: " + honeypot_code)
        sys.exit(1)

    honeypot_id = row[0]
    cur.execute(
        "INSERT INTO ingest_tokens (honeypot_id, token_hash) VALUES (%s, %s)",
        (honeypot_id, token_hash),
    )
    conn.commit()
    cur.close()
    conn.close()

    print("token for " + honeypot_code + " (store securely, shown once):")
    print(raw_token)


if __name__ == "__main__":
    main()
