"""最小 CBOR 实现（RFC 8949），只覆盖本服务与测试需要的类型。

支持：无符号/负整数、字节串、文本串、数组、映射、true/false/null。
不支持标签、半精度/浮点、indefinite 长度——本场景不需要，遇到即报错，
避免解析出未验证的结构。
"""

from __future__ import annotations

from typing import Any

CBORError = ValueError


def _head(major: int, arg: int) -> bytes:
    out = bytes([major << 5])
    if arg < 24:
        return bytes([(major << 5) | arg])
    if arg < 0x100:
        return bytes([(major << 5) | 24, arg])
    if arg < 0x10000:
        return bytes([(major << 5) | 25]) + arg.to_bytes(2, "big")
    if arg < 0x100000000:
        return bytes([(major << 5) | 26]) + arg.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + arg.to_bytes(8, "big")


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise CBORError("CBOR 数据被截断")
        b = self.data[self.pos : self.pos + n]
        self.pos += n
        return b

    def head(self) -> tuple[int, int]:
        first = self.take(1)[0]
        major, info = first >> 5, first & 0x1F
        if info < 24:
            arg = info
        elif info == 24:
            arg = self.take(1)[0]
        elif info == 25:
            arg = int.from_bytes(self.take(2), "big")
        elif info == 26:
            arg = int.from_bytes(self.take(4), "big")
        elif info == 27:
            arg = int.from_bytes(self.take(8), "big")
        elif info == 31:
            raise CBORError("不支持 indefinite-length CBOR")
        else:
            raise CBORError("不支持的 CBOR 简单值/浮点")
        return major, arg

    def decode(self) -> Any:
        major, arg = self.head()
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            return self.take(arg)
        if major == 3:
            return self.take(arg).decode("utf-8")
        if major == 4:
            return [self.decode() for _ in range(arg)]
        if major == 5:
            return {self.decode(): self.decode() for _ in range(arg)}
        if major == 6:
            raise CBORError("不支持 CBOR 标签")
        if major == 7:
            if arg == 20:
                return False
            if arg == 21:
                return True
            if arg == 22:
                return None
            raise CBORError("不支持的 CBOR 简单值")
        raise CBORError("未知 CBOR major type")  # pragma: no cover


def loads(data: bytes) -> Any:
    r = _Reader(data)
    value = r.decode()
    if r.pos != len(data):
        raise CBORError("CBOR 数据后有多余字节")
    return value


_KEY_RANK = {bool: 0, int: 1, bytes: 2, str: 3}


def _encode(value: Any) -> bytes:
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _head(0, value)
        return _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(_encode(v) for v in value)
    if isinstance(value, dict):
        items = sorted(
            value.items(),
            key=lambda kv: (_KEY_RANK.get(type(kv[0]), 9), kv[0]),
        )
        return _head(5, len(items)) + b"".join(
            _encode(k) + _encode(v) for k, v in items
        )
    raise CBORError(f"无法编码类型 {type(value)!r}")


def dumps(value: Any) -> bytes:
    return _encode(value)
