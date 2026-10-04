"""Base64url（无填充）编解码工具。"""

from __future__ import annotations

import base64

from .errors import InvalidRequest

_B64URL_ALPHABET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str | bytes) -> bytes:
    """解码无填充 base64url；非法字符或填充一律拒绝。"""
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise InvalidRequest("base64url 字段不是 ASCII 文本") from exc
    if not isinstance(value, str) or not value:
        raise InvalidRequest("base64url 字段为空或类型错误")
    if any(ch not in _B64URL_ALPHABET for ch in value):
        raise InvalidRequest("base64url 字段含非法字符")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:  # binascii.Error 等
        raise InvalidRequest("base64url 解码失败") from exc
