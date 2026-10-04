"""限定范围的 WebAuthn 注册 / 认证服务。

只支持：
* ES256（ECDSA over P-256 + SHA-256）公钥凭据；
* ``none`` 与 ``packed``（自签名）证明；
* 无证书链、无扩展、不可备份凭据。
"""

from .config import Config
from .db import Database
from .errors import WebAuthnError
from .service import WebAuthnService


def create_app(config=None, db=None):
    # 延迟导入，避免 ``python -m webauthn_limited.app`` 时的 runpy 警告
    from .app import create_app as _create_app

    return _create_app(config, db)


__all__ = [
    "create_app",
    "Config",
    "Database",
    "WebAuthnError",
    "WebAuthnService",
]
