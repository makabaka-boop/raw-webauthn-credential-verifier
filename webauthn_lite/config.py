"""服务端固定配置。

origin 与 RP ID 只能在这里（或启动时的环境变量）配置，任何请求字段
都不能覆盖它们。
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    rp_id: str
    origin: str
    rp_name: str
    db_path: str
    host: str
    port: int


def load() -> Config:
    return Config(
        # 默认值指向本机测试服务；部署时用环境变量固定为真实站点。
        rp_id=os.environ.get("WA_RP_ID", "localhost"),
        origin=os.environ.get("WA_ORIGIN", "http://localhost:8080"),
        rp_name=os.environ.get("WA_RP_NAME", "WebAuthn Lite"),
        db_path=os.environ.get("WA_DB", os.path.abspath("webauthn_lite.db")),
        host=os.environ.get("WA_HOST", "127.0.0.1"),
        port=int(os.environ.get("WA_PORT", "8080")),
    )
