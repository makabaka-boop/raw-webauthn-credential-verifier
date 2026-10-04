"""纯标准库 P-256 / ECDSA-SHA256（ES256）。

服务端只需要验签；随机生成与签名函数供测试夹具构造真实载荷。
不依赖 OpenSSL 绑定，部署机器有 hashlib 即可运行。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

# --- NIST P-256 域参数 (FIPS 186-4 / SEC2 secp256r1) ---
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

Point = tuple[int, int] | None
_G: Point = (_GX, _GY)

# WebAuthn 签名必须是严格的 IEEE P1363 r||s（各 32 字节）。
RAW_SIG_LEN = 64
FIELD_SIZE = 32


class CryptoError(ValueError):
    pass


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _inv_mod(a: int, m: int) -> int:
    return pow(a % m, -1, m)


def _point_add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1 + _A) * _inv_mod(2 * y1, _P) % _P
    else:
        lam = (y2 - y1) * _inv_mod(x2 - x1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return x3, y3


def _scalar_mul(k: int, point: Point) -> Point:
    k %= _N
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _on_curve(q: Point) -> bool:
    if q is None:
        return False
    x, y = q
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


@dataclass(frozen=True)
class PublicKey:
    x: int
    y: int

    def is_valid(self) -> bool:
        return _on_curve((self.x, self.y))

    def xy_bytes(self) -> tuple[bytes, bytes]:
        return self.x.to_bytes(FIELD_SIZE, "big"), self.y.to_bytes(FIELD_SIZE, "big")


@dataclass(frozen=True)
class PrivateKey:
    d: int
    public: PublicKey


def generate_key() -> PrivateKey:
    d = 1 + secrets.randbelow(_N - 1)
    x, y = _scalar_mul(d, _G)  # type: ignore[misc]
    return PrivateKey(d=d, public=PublicKey(x, y))


def _bits2int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _bits2octets(b: bytes) -> bytes:
    # E = hash；截断或左填充到 n 的字节长度。
    z1 = _bits2int(b)
    l = (_N.bit_length() + 7) // 8
    z2 = z1 % (2 ** (8 * l)) if len(b) * 8 > _N.bit_length() else z1
    return z2.to_bytes(l, "big")


def _rfc6979_k(priv: int, msg: bytes) -> int:
    qlen = _N.bit_length()
    holen = 32
    rolen = (qlen + 7) // 8
    bx = priv.to_bytes(rolen, "big") + _bits2octets(sha256(msg))
    V = b"\x01" * holen
    K = b"\x00" * holen
    K = hmac.new(K, V + b"\x00" + bx, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + bx, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        T = b""
        while len(T) < rolen:
            V = hmac.new(K, V, hashlib.sha256).digest()
            T += V
        k = _bits2int(T[:rolen])
        if 1 <= k < _N:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def _to_low_s(s: int) -> int:
    """BIP/CT 风格低 S 规范化，WebAuthn 验签拒绝高 S。"""
    if s > _N // 2:
        return _N - s

    return s


def raw_sign(priv: int, message: bytes) -> bytes:
    """返回 IEEE P1363 原始签名 r||s（低 S），与验证端格式一致。"""
    e = int.from_bytes(sha256(message), "big")
    k = _rfc6979_k(priv, message)
    r = _scalar_mul(k, _G)[0] % _N  # type: ignore[index]
    s = _inv_mod(k, _N) * (e + r * priv) % _N
    s = _to_low_s(s)
    if r == 0 or s == 0:  # 确定性 k 下实际不会发生
        raise CryptoError("签名退化")  # pragma: no cover
    return r.to_bytes(FIELD_SIZE, "big") + s.to_bytes(FIELD_SIZE, "big")


def raw_verify(pub: PublicKey, message: bytes, signature: bytes) -> None:
    """成功返回 None，失败抛 CryptoError。消息直接哈希，不做任何重编码。"""
    if not pub.is_valid():
        raise CryptoError("公钥不在 P-256 曲线上")
    if len(signature) != RAW_SIG_LEN:
        raise CryptoError("ES256 签名必须是 64 字节的 r||s")
    r = int.from_bytes(signature[:FIELD_SIZE], "big")
    s = int.from_bytes(signature[FIELD_SIZE:], "big")
    if not (1 <= r < _N and 1 <= s < _N):
        raise CryptoError("签名 r/s 越界")
    if s > _N // 2:
        raise CryptoError("签名 S 不是低 S 形式")
    e = int.from_bytes(sha256(message), "big")
    w = _inv_mod(s, _N)
    u1 = (e * w) % _N
    u2 = (r * w) % _N
    point = _point_add(_scalar_mul(u1, _G), _scalar_mul(u2, (pub.x, pub.y)))
    if point is None:
        raise CryptoError("ECDSA 签名无效（点为无穷远点）")
    if point[0] % _N != r:
        raise CryptoError("ECDSA 签名无效")
