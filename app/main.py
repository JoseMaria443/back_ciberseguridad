from flask import Flask, request, jsonify
from app.config import Config
from app.auth import resolve_honeypot, check_rate_limit
from app.validation import validate_envelope, validate_category_fields, ValidationError
from app.ingest import insert_event, record_heartbeat, load_lookups


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH

    load_lookups()

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    def authenticate():
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        raw_token = auth_header[len("Bearer "):].strip()
        return resolve_honeypot(raw_token)

    @app.route("/api/v1/events", methods=["POST"])
    def receive_event():
        identity = authenticate()
        if identity is None:
            return jsonify({"error": "unauthorized"}), 401

        if not check_rate_limit(identity["honeypot_id"]):
            return jsonify({"error": "rate limited"}), 429

        body = request.get_json(silent=True)
        if body is None:
            return jsonify({"error": "invalid json"}), 400

        try:
            envelope = validate_envelope(body)
            parsed_fields = validate_category_fields(envelope["category"], envelope["fields"])
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400

        client_ip = envelope["source_ip"] or request.remote_addr

        try:
            event_id, priority = insert_event(
                honeypot_id=identity["honeypot_id"],
                session_id=envelope["session_id"],
                source_name=envelope["source"],
                category_name=envelope["category"],
                occurred_at=envelope["occurred_at"],
                source_ip=client_ip,
                raw_fields=envelope["fields"],
                parsed_fields=parsed_fields,
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        return jsonify({"event_id": event_id, "priority": priority}), 201

    @app.route("/api/v1/heartbeat", methods=["POST"])
    def receive_heartbeat():
        identity = authenticate()
        if identity is None:
            return jsonify({"error": "unauthorized"}), 401

        record_heartbeat(identity["honeypot_id"])
        return jsonify({"status": "ok"}), 200

    @app.route("/api/v1/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"}), 200

    return app


app = create_app()
