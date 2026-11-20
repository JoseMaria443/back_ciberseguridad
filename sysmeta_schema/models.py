from enum import StrEnum
from typing import Annotated, Literal, Union
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StringConstraints,
    TypeAdapter,
)

SCHEMA_VERSION = 1


def _clean(value: str) -> str:
    cleaned = value.replace("\x00", "\\x00")
    return cleaned.encode("utf-8", "replace").decode("utf-8")


def _text(max_length: int):
    return Annotated[str, StringConstraints(max_length=max_length), AfterValidator(_clean)]


Tiny = _text(64)
Short = _text(256)
Path = _text(1024)
Large = _text(4096)
Huge = _text(8192)

Fingerprint = Annotated[str, StringConstraints(pattern=r"^SHA256:[A-Za-z0-9+/]{43}$")]


class Source(StrEnum):
    NGINX = "nginx"
    FLASK = "flask"
    AUDITD = "auditd"
    SSHD = "sshd"
    POSTGRES = "postgres"
    DOCKER = "docker"
    AGENT = "agent"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HttpRequestData(Strict):
    method: Tiny
    path: Path
    query: Path | None = None
    status: int = Field(ge=100, le=599)
    bytes: int = Field(ge=0)
    user_agent: Short | None = None
    referer: Path | None = None
    body_excerpt: Large | None = None


class AuthAttemptData(Strict):
    service: Literal["flask_login", "ssh", "postgres"]
    username: Short | None = None
    secret: Short | None = None
    key_fingerprint: Fingerprint | None = None
    success: bool


class FileAccessData(Strict):
    path: Path
    operation: Literal["read", "write", "delete", "chmod"]
    via: Literal["flask", "shell"]
    success: bool


class CommandExecData(Strict):
    command_line: Large
    truncated: bool = False
    cwd: Path | None = None
    uid: int | None = None
    auid: int | None = None
    exit_code: int | None = None


class SqlStatementData(Strict):
    db_user: Short | None = None
    database: Short | None = None
    command_tag: Tiny | None = None
    statement: Huge
    truncated: bool = False


class SessionData(Strict):
    action: Literal["open", "close"]
    kind: Literal["http", "ssh", "sql"]
    auth_user: Short | None = None
    auth_method: Literal["password", "publickey"] | None = None
    key_fingerprint: Fingerprint | None = None


class EventBase(Strict):
    seq: int = Field(ge=0)
    occurred_at: AwareDatetime
    source: Source
    src_ip: IPvAnyAddress | None = None
    session_ref: Tiny | None = None


class HttpRequestEvent(EventBase):
    event_type: Literal["http.request"]
    data: HttpRequestData


class AuthAttemptEvent(EventBase):
    event_type: Literal["auth.attempt"]
    data: AuthAttemptData


class FileAccessEvent(EventBase):
    event_type: Literal["file.access"]
    data: FileAccessData


class CommandExecEvent(EventBase):
    event_type: Literal["command.exec"]
    data: CommandExecData


class SqlStatementEvent(EventBase):
    event_type: Literal["sql.statement"]
    data: SqlStatementData


class SessionEvent(EventBase):
    event_type: Literal["session"]
    data: SessionData


Event = Annotated[
    Union[
        HttpRequestEvent,
        AuthAttemptEvent,
        FileAccessEvent,
        CommandExecEvent,
        SqlStatementEvent,
        SessionEvent,
    ],
    Field(discriminator="event_type"),
]

EventAdapter = TypeAdapter(Event)


class Heartbeat(Strict):
    schema_version: Literal[1]
    boot_id: UUID
    seq: int = Field(ge=0)
    sent_at: AwareDatetime
    agent_version: Tiny
    auditd_ok: bool
    rules_immutable: bool
    spool_pending: int = Field(ge=0)
    last_event_seq: int = Field(ge=0)


class RawBatch(Strict):
    schema_version: Literal[1]
    boot_id: UUID
    events: list[dict] = Field(min_length=1, max_length=500)
