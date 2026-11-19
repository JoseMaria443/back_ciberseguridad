# Backend de ingesta — honeypots

Recolector normalizado para los 4 honeypots descritos en `modelado_servidores.md`. Cada honeypot envía sus eventos (lectura de archivos, SSH, comandos, docker, flows, Postgres/pgaudit, honeytokens) a esta API, que los valida, clasifica por prioridad del lado del servidor y los guarda en PostgreSQL ya normalizados.

## Por qué está estructurado así

- **La prioridad la calcula el backend, no el honeypot** (`app/priority.py`). Si un atacante compromete el agente de un honeypot, no puede hacer que sus propias acciones críticas se reporten como de baja prioridad.
- **El honeypot de origen se deriva del token, nunca del payload.** Un honeypot no puede hacerse pasar por otro aunque modifique el JSON que envía.
- **Solo INSERT, nunca UPDATE/DELETE** en las tablas de eventos desde el rol de la app (`roles.sql`). Si el token de ingesta se filtra, el atacante puede escribir basura pero no puede borrar ni alterar lo ya registrado.
- **Validación estricta por categoría** (`app/validation.py`): tipos, longitudes máximas y valores permitidos antes de tocar la base de datos. Todo lo que entra se queda también como `raw_payload` JSONB para no perder nada, aunque la tabla normalizada solo guarde lo validado.
- **Tabla núcleo + tablas hijas** (`schema.sql`): `events` tiene los campos comunes a todo; cada categoría (file_access, auth, command, docker, network_flow, db, config_change, agent_tamper, honeytoken_trigger) tiene su propia tabla con sus columnas específicas, sin columnas nulas desperdiciadas.
- **Tokens de ingesta se guardan como hash SHA-256**, nunca en texto plano, y son revocables sin tocar nada más (`ingest_tokens.revoked_at`).

## Puesta en marcha

```bash
createdb honeypot_collector
psql honeypot_collector -f schema.sql
psql honeypot_collector -f seed.sql
psql honeypot_collector -f roles.sql   # cambia las contraseñas antes de correrlo
```

```bash
cp .env.example .env   # y llena las credenciales reales
pip install -r requirements.txt
python scripts/create_honeypot_token.py hp1
python scripts/create_honeypot_token.py hp2
python scripts/create_honeypot_token.py hp3
python scripts/create_honeypot_token.py hp4
```

Cada comando imprime un token una sola vez — es lo que cada honeypot usará como `Authorization: Bearer <token>`.

Correr en desarrollo:

```bash
python wsgi.py
```

En producción, detrás de un reverse proxy con TLS:

```bash
gunicorn -w 4 -b 127.0.0.1:8080 wsgi:app
```

El tráfico entre los honeypots y este backend debe ir siempre sobre TLS (el reverse proxy lo termina) y la conexión a PostgreSQL con `sslmode=require` como mínimo.

## Formato de envío

```
POST /api/v1/events
Authorization: Bearer <token del honeypot>
Content-Type: application/json

{
  "source": "auditd",
  "category": "file_access",
  "occurred_at": "2026-11-18T20:10:00Z",
  "source_ip": "10.0.1.15",
  "session_id": "b7b1...-uuid-de-sesion-opcional",
  "fields": {
    "file_path": "/home/victima/.ssh/authorized_keys",
    "action": "read",
    "success": true
  }
}
```

Categorías soportadas: `file_access`, `auth`, `command`, `http`, `docker`, `network_flow`, `db`, `config_change`, `agent_tamper`, `honeytoken_trigger`. Cada una tiene sus propios campos obligatorios — ver `app/validation.py`.

```
POST /api/v1/heartbeat
Authorization: Bearer <token del honeypot>
```

## Alertas por Telegram (`telegram_alerts/`)

Servicio aparte, de solo lectura, que avisa por Telegram en cuanto se inserta un evento `critical` o `high`. No hace polling: `triggers.sql` agrega un trigger en `events` que llama `pg_notify('honeypot_alert', id)` solo para esas prioridades, y `listener.py` se queda escuchando ese canal con `asyncpg`. Cuando llega un aviso, busca el evento completo y lo manda formateado a Telegram.

```bash
psql honeypot_collector -f triggers.sql
cd telegram_alerts
pip install -r requirements.txt
python main.py
```

Usa el rol `honeypot_reader` (ya creado en `roles.sql`, solo `SELECT`) — este proceso nunca necesita escribir en la base. El `/estado` por chat de Telegram consulta el último heartbeat de cada honeypot y cuántos eventos critical/high hubo en la última hora, en vez de responder un texto fijo.

La prioridad que dispara la alerta sigue siendo la que calculó `app/priority.py` al insertar el evento — este servicio no decide nada de eso, solo transporta lo que ya se clasificó.

## Pendiente de ajustar para tu entorno

- Las contraseñas en `roles.sql` y `.env.example` son placeholders.
- El rate limit (`app/auth.py`) es en memoria por proceso; si corres varios workers de gunicorn, cada uno lleva su propio contador — para un conteo global real se necesitaría Redis u otro store compartido.
- `resolve_session` crea una sesión genérica con protocolo `http` si no existe; si quieres que SSH y Postgres abran sus propias sesiones desde el agente del honeypot, ese es el punto para extenderlo.
