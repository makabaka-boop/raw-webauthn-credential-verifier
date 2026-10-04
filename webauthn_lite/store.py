"""SQLite 持久化：用户、凭据公钥、挑战（含用途）、签名计数。

并发正确性靠一个原则：成功路径里“挑战消费 + 计数更新”在同一个
BEGIN IMMEDIATE 事务内条件完成，失败回滚，因此同一挑战的并发成功
至多提交一次。
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

CHALLENGE_BYTES = 32
PURPOSE_REGISTRATION = "registration"
PURPOSE_AUTHENTICATION = "authentication"

_SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    display_name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT NOT NULL REFERENCES users(id),
    credential_id BLOB NOT NULL UNIQUE,
    pub_cose      BLOB NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges (
    challenge  BLOB PRIMARY KEY,
    purpose    TEXT NOT NULL CHECK (purpose IN ('registration', 'authentication')),
    user_id    TEXT NOT NULL REFERENCES users(id),
    consumed   INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1)),
    created_at TEXT NOT NULL
);
"""


class StoreError(Exception):
    pass


class ChallengeAlreadyConsumed(StoreError):
    pass


class CounterRejected(StoreError):
    pass


@dataclass(frozen=True)
class Credential:
    user_id: str
    credential_id: bytes
    pub_cose: bytes
    sign_count: int


def connect(db_path: str) -> sqlite3.Connection:
    # check_same_thread=False：HTTP 工作线程共享连接；写操作统一用
    # BEGIN IMMEDIATE 串行化，读操作在 WAL 下互不阻塞。
    conn = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    conn.commit()


def seed_user(conn: sqlite3.Connection, user_id: str, display_name: str) -> None:
    """测试夹具入口：身份来自夹具，不提供注册账户的 HTTP 接口。"""
    conn.execute(
        "INSERT INTO users(id, display_name) VALUES (?, ?) "
        "ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name",
        (user_id, display_name),
    )
    conn.commit()


def get_user(conn: sqlite3.Connection, user_id: str) -> tuple[str, str] | None:
    row = conn.execute("SELECT id, display_name FROM users WHERE id=?", (user_id,)).fetchone()
    return tuple(row) if row else None


def _new_challenge(conn: sqlite3.Connection, purpose: str, user_id: str) -> bytes:
    if get_user(conn, user_id) is None:
        raise StoreError(f"用户不存在: {user_id!r}（身份只能由测试夹具提供）")
    challenge = os.urandom(CHALLENGE_BYTES)
    conn.execute(
        "INSERT INTO challenges(challenge, purpose, user_id, consumed, created_at) "
        "VALUES (?, ?, ?, 0, ?)",
        (challenge, purpose, user_id, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    return challenge


def begin_registration(conn: sqlite3.Connection, user_id: str) -> bytes:
    return _new_challenge(conn, PURPOSE_REGISTRATION, user_id)


def begin_authentication(conn: sqlite3.Connection, user_id: str) -> bytes:
    return _new_challenge(conn, PURPOSE_AUTHENTICATION, user_id)


def get_pending_challenge(conn: sqlite3.Connection, challenge: bytes, purpose: str) -> str | None:
    """返回未消费挑战归属的 user_id；已消费/不存在/用途不符均返回 None。"""
    row = conn.execute(
        "SELECT user_id FROM challenges WHERE challenge=? AND purpose=? AND consumed=0",
        (challenge, purpose),
    ).fetchone()
    return row[0] if row else None


def commit_registration(
    conn: sqlite3.Connection,
    challenge: bytes,
    user_id: str,
    credential_id: bytes,
    pub_cose: bytes,
    sign_count: int,
) -> None:
    """原子完成：条件消费注册挑战 + 写入凭据。失败回滚，不消费挑战。"""
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE challenges SET consumed=1 "
            "WHERE challenge=? AND purpose=? AND user_id=? AND consumed=0",
            (challenge, PURPOSE_REGISTRATION, user_id),
        )
        if cur.rowcount != 1:
            raise ChallengeAlreadyConsumed("注册挑战不存在、用途错误、归属不符或已被消费")
        exists = conn.execute(
            "SELECT 1 FROM credentials WHERE credential_id=?", (credential_id,)
        ).fetchone()
        if exists:
            raise StoreError("credential ID 已注册")
        conn.execute(
            "INSERT INTO credentials(user_id, credential_id, pub_cose, sign_count, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                user_id,
                credential_id,
                pub_cose,
                sign_count,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def get_credential(conn: sqlite3.Connection, credential_id: bytes) -> Credential | None:
    row = conn.execute(
        "SELECT user_id, credential_id, pub_cose, sign_count FROM credentials "
        "WHERE credential_id=?",
        (credential_id,),
    ).fetchone()
    if row is None:
        return None
    return Credential(
        user_id=row[0], credential_id=row[1], pub_cose=row[2], sign_count=row[3]
    )


def commit_authentication(
    conn: sqlite3.Connection,
    challenge: bytes,
    user_id: str,
    credential_id: bytes,
    new_count: int,
) -> int:
    """原子完成：条件消费认证挑战 + 签名计数更新。

    计数规则：库中为 0 的凭据可一直提交 0，也可升级为正数；一旦记录过
    正数，只接受严格更大的值。任何失败都回滚，挑战不被消费。
    返回提交后计数值。
    """
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE challenges SET consumed=1 "
            "WHERE challenge=? AND purpose=? AND user_id=? AND consumed=0",
            (challenge, PURPOSE_AUTHENTICATION, user_id),
        )
        if cur.rowcount != 1:
            raise ChallengeAlreadyConsumed("认证挑战不存在、用途错误、归属不符或已被消费")
        row = conn.execute(
            "SELECT sign_count FROM credentials WHERE credential_id=? AND user_id=?",
            (credential_id, user_id),
        ).fetchone()
        if row is None:
            raise StoreError("凭据不存在或不属于该用户")
        stored = row[0]
        if stored == 0:
            if new_count < 0:
                raise CounterRejected("签名计数不能为负")
        elif new_count <= stored:
            raise CounterRejected(f"签名计数必须严格增大：已记录 {stored}，收到 {new_count}")
        conn.execute(
            "UPDATE credentials SET sign_count=? WHERE credential_id=?",
            (new_count, credential_id),
        )
        conn.commit()
        return new_count
    except Exception:
        conn.rollback()
        raise
