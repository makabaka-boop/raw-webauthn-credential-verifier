"""服务端固定配置。

RP ID 与 origin 只能来自服务端配置（环境变量），任何请求字段都不能覆盖。
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    rp_id: str
    rp_name: str
    origin: str
    db_path: str

    @classmethod
    def from_env(cls) -> "Config":
        rp_id = os.environ.get("WEBAUTHN_RP_ID", "example.test")
        return cls(
            rp_id=rp_id,
            rp_name=os.environ.get("WEBAUTHN_RP_NAME", "Limited WebAuthn RP"),
            # origin 默认与 RP ID 对应的 https 站点一致
            origin=os.environ.get("WEBAUTHN_ORIGIN", f"https://{rp_id}"),
            db_path=os.environ.get("WEBAUTHN_DB_PATH", "/tmp/webauthn_limited.db"),
        )
