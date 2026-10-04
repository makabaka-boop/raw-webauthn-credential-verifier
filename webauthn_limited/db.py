"""SQLite 持久层：用户、凭据、挑战（含用途）与签名计数。

每个调用使用独立连接；成功路径上的「挑战消耗 + 计数更新」放在同一个
``BEGIN IMMEDIATE`` 事务中一次提交。失败验证（如签名错误）在事务外完成，
不会触碰数据库，因此不消耗挑战。
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Optional

# 挑战的两种用途，注册与认证严格分开，禁止交叉使用。
PURPOSE_REGISTRATION = "registration"
PURPOSE_AUTHENTICATION = "authentication"


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY,
    display_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    credential_id BLOB PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(user_id),
    public_key    BLOB NOT NULL,          -- SEC1 未压缩点（65 字节）
    sign_count    INTEGER NOT NULL,       -- 最近一次成功认证的计数
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS challenges (
    challenge BLOB PRIMARY KEY,
    user_id   TEXT NOT NULL REFERENCES users(user_id),
    purpose   TEXT NOT NULL CHECK (purpose IN
                  ('registration', 'authentication'))
);
"""


class Database:
    def __init__(self, path: str, busy_timeout_ms: int = 5000):
        self.path = path
        self.busy_timeout_ms = busy_timeout_ms
        self.init_schema()

    def connect(self) -> sqlite3.Connection:
        # isolation_level=None：autocommit，事务由我们显式控制
        conn = sqlite3.connect(
            self.path, timeout=self.busy_timeout_ms / 1000, isolation_level=None
        )
        conn.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_ms)}")
        conn.row_factory = sqlite3.Row
        # WAL 让并发的读/写更平滑；写互斥仍由 BEGIN IMMEDIATE 保证
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def init_schema(self) -> None:
        conn = self.connect()
        try:
            conn.executescript(SCHEMA)
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """开启 IMMEDIATE 写事务；提交或回滚都在这里完成。"""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # ---- 用户 ----------------------------------------------------------

    def upsert_user(self, user_id: str, display_name: str) -> None:
        conn = self.connect()
        try:
            conn.execute(
                "INSERT INTO users(user_id, display_name) VALUES (?, ?) "
                "ON CONFLICT(user_id) DO UPDATE SET display_name = excluded.display_name",
                (user_id, display_name),
            )
        finally:
            conn.close()

    def user_exists(self, conn: sqlite3.Connection, user_id: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        return row is not None

    # ---- 挑战 ----------------------------------------------------------

    def store_challenge(
        self, challenge: bytes, user_id: str, purpose: str
    ) -> None:
        conn = self.connect()
        try:
            conn.execute(
                "INSERT INTO challenges(challenge, user_id, purpose) VALUES (?, ?, ?)",
                (challenge, user_id, purpose),
            )
        finally:
            conn.close()

    def get_challenge(
        self, challenge: bytes
    ) -> Optional[tuple[str, str]]:
        """返回 (user_id, purpose)，不存在返回 None。"""
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT user_id, purpose FROM challenges WHERE challenge = ?",
                (challenge,),
            ).fetchone()
            return (row["user_id"], row["purpose"]) if row else None
        finally:
            conn.close()

    def challenge_exists(
        self, conn: sqlite3.Connection, challenge: bytes
    ) -> bool:
        row = conn.execute(
            "SELECT 1 FROM challenges WHERE challenge = ?", (challenge,)
        ).fetchone()
        return row is not None

    def delete_challenge(
        self, conn: sqlite3.Connection, challenge: bytes
    ) -> None:
        conn.execute("DELETE FROM challenges WHERE challenge = ?", (challenge,))

    # ---- 凭据 ----------------------------------------------------------

    def credential_exists(
        self, conn: sqlite3.Connection, credential_id: bytes
    ) -> bool:
        row = conn.execute(
            "SELECT 1 FROM credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone()
        return row is not None

    def insert_credential(
        self,
        conn: sqlite3.Connection,
        credential_id: bytes,
        user_id: str,
        public_key: bytes,
        sign_count: int,
    ) -> None:
        conn.execute(
            "INSERT INTO credentials(credential_id, user_id, public_key, sign_count) "
            "VALUES (?, ?, ?, ?)",
            (credential_id, user_id, public_key, sign_count),
        )

    def get_credential(
        self, credential_id: bytes
    ) -> Optional[sqlite3.Row]:
        conn = self.connect()
        try:
            return conn.execute(
                "SELECT credential_id, user_id, public_key, sign_count "
                "FROM credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
        finally:
            conn.close()

    def locked_get_credential(
        self, conn: sqlite3.Connection, credential_id: bytes
    ) -> Optional[sqlite3.Row]:
        """在写事务内读取；行锁在事务期间持续持有，保证计数检查不被插入。"""
        return conn.execute(
            "SELECT credential_id, user_id, public_key, sign_count "
            "FROM credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone()

    def update_sign_count(
        self, conn: sqlite3.Connection, credential_id: bytes, sign_count: int
    ) -> None:
        conn.execute(
            "UPDATE credentials SET sign_count = ? WHERE credential_id = ?",
            (sign_count, credential_id),
        )

    def list_credential_ids_for_user(
        self, conn: sqlite3.Connection, user_id: str
    ) -> list[bytes]:
        rows = conn.execute(
            "SELECT credential_id FROM credentials WHERE user_id = ?",
            (user_id,),
        ).fetchall()
        return [r["credential_id"] for r in rows]
