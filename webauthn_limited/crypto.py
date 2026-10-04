"""CBOR / COSE / 认证数据 / 证明 的解析与 ES256 验证。

本模块只支持限定子集：
* ES256：ECDSA P-256 + SHA-256，签名为 ASN.1 DER 序列（CTAP 格式）；
* COSE EC2 公钥，crv=P-256；
* ``none`` 与 ``packed``（且仅自签名，禁止 x5c 证书链）证明；
* 认证数据不得声明扩展（ED=0）或备份能力（BE=BS=0）。
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
from dataclasses import dataclass

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)

from .errors import InvalidRequest, VerificationFailure

# WebAuthn 类型字符串
CLIENT_TYPE_CREATE = "webauthn.create"
CLIENT_TYPE_GET = "webauthn.get"

# authenticator data 标志位
FLAG_UP = 0x01
FLAG_RFU1 = 0x02
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_RFU5 = 0x20
FLAG_AT = 0x40
FLAG_ED = 0x80

# 本服务固定接受的标志集合
_ALLOWED_FLAGS_REGISTRATION = FLAG_UP | FLAG_UV | FLAG_AT
_ALLOWED_FLAGS_ASSERTION = FLAG_UP | FLAG_UV

# COSE 键 / 值
COSE_KTY = 1
COSE_ALG = 3
COSE_CRV = -1
COSE_X = -2
COSE_Y = -3
KTY_EC2 = 2
ALG_ES256 = -7
CRV_P256 = 1

_COSE_ALLOWED_KEYS = {COSE_KTY, COSE_ALG, COSE_CRV, COSE_X, COSE_Y}


@dataclass(frozen=True)
class ClientData:
    challenge: bytes
    type: str
    origin: str


@dataclass(frozen=True)
class AuthData:
    sign_count: int
    credential_id: bytes | None
    public_key: ec.EllipticCurvePublicKey | None


def client_data_hash(raw_client_data_json: bytes) -> bytes:
    """对收到的原始字节做 SHA-256。

    必须使用 HTTP 请求里收到的原始字节；绝不能先 json 解析再重新序列化，
    否则键序/空白差异会导致客户端数据哈希不一致。
    """
    return hashlib.sha256(raw_client_data_json).digest()


def parse_client_data(
    raw: bytes, expected_type: str, expected_origin: str
) -> ClientData:
    """解析并校验 clientDataJSON 的原始字节。

    精确检查 type、origin；challenge 返回给调用方与服务端记录做比较。
    拒绝 tokenBinding（本服务不支持）与未知顶层字段。
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) == 0:
        raise InvalidRequest("clientDataJSON 为空")
    try:
        obj = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise VerificationFailure("clientDataJSON 不是合法 UTF-8 JSON") from exc
    if not isinstance(obj, dict):
        raise VerificationFailure("clientDataJSON 顶层必须是对象")

    allowed = {"challenge", "origin", "type", "crossOrigin", "tokenBinding"}
    unknown = set(obj) - allowed
    if unknown:
        raise VerificationFailure(f"clientDataJSON 含未知字段: {sorted(unknown)}")
    if "tokenBinding" in obj:
        raise VerificationFailure("本服务不支持 tokenBinding")

    challenge = obj.get("challenge")
    origin = obj.get("origin")
    ctype = obj.get("type")
    cross_origin = obj.get("crossOrigin", False)
    if not isinstance(challenge, str) or not challenge:
        raise VerificationFailure("clientDataJSON.challenge 缺失或类型错误")
    if not isinstance(origin, str) or not origin:
        raise VerificationFailure("clientDataJSON.origin 缺失或类型错误")
    if not isinstance(ctype, str):
        raise VerificationFailure("clientDataJSON.type 缺失或类型错误")
    if not isinstance(cross_origin, bool):
        raise VerificationFailure("clientDataJSON.crossOrigin 必须为布尔值")
    if cross_origin:
        raise VerificationFailure("不允许 crossOrigin 请求")
    if ctype != expected_type:
        raise VerificationFailure(
            f"clientDataJSON.type 必须为 {expected_type}，实际为 {ctype!r}"
        )
    # 精确 origin 等值比较（不做后缀/子串匹配）
    if origin != expected_origin:
        raise VerificationFailure("origin 与服务端配置不一致")

    from .encoding import b64url_decode

    challenge_bytes = b64url_decode(challenge)
    return ClientData(challenge=challenge_bytes, type=ctype, origin=origin)


def _cbor_decode_exact(data: bytes, what: str) -> object:
    """解码单个 CBOR 值，且要求字节全部被消费（拒绝尾随数据）。"""
    stream = io.BytesIO(data)
    try:
        obj = cbor2.CBORDecoder(stream).decode()
    except (cbor2.CBORDecodeError, ValueError) as exc:
        raise VerificationFailure(f"{what} 不是合法 CBOR") from exc
    if stream.read(1) != b"":
        raise VerificationFailure(f"{what} 含尾随字节")
    return obj


def parse_cose_p256_key(data: bytes) -> ec.EllipticCurvePublicKey:
    """解析严格形态的 COSE_Key（EC2 / P-256 / ES256）。"""
    obj = _cbor_decode_exact(data, "COSE 公钥")
    if not isinstance(obj, dict):
        raise VerificationFailure("COSE 公钥必须是 map")
    if set(obj.keys()) != _COSE_ALLOWED_KEYS:
        raise VerificationFailure("COSE 公钥字段集合不符合限定的 EC2 公钥")
    if obj[COSE_KTY] != KTY_EC2:
        raise VerificationFailure("仅支持 EC2 公钥 (kty=2)")
    if obj[COSE_ALG] != ALG_ES256:
        raise VerificationFailure("仅支持 ES256 (alg=-7)")
    if obj[COSE_CRV] != CRV_P256:
        raise VerificationFailure("仅支持 P-256 曲线 (crv=1)")
    x, y = obj[COSE_X], obj[COSE_Y]
    if not isinstance(x, bytes) or not isinstance(y, bytes):
        raise VerificationFailure("COSE 公钥坐标必须是字节串")
    if len(x) != 32 or len(y) != 32:
        raise VerificationFailure("P-256 坐标长度必须各为 32 字节")
    point = b"\x04" + x + y  # SEC1 未压缩点
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    except ValueError as exc:
        raise VerificationFailure("P-256 公钥点无效") from exc


def parse_authenticator_data(
    raw: bytes,
    rp_id_hash_expected: bytes,
    attestation: bool,
) -> AuthData:
    """解析 authenticatorData 并校验 RP ID 摘要与标志位。

    attestation=True 时解析 attested credential data（注册）；
    attestation=False 时要求数据恰为 37 字节（认证）。
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise InvalidRequest("authenticatorData 不是字节串")
    raw = bytes(raw)
    if len(raw) < 37:
        raise VerificationFailure("authenticatorData 短于 37 字节（截断）")

    rp_id_hash = raw[0:32]
    flags = raw[32]
    sign_count = int.from_bytes(raw[33:37], "big")

    if not hmac.compare_digest(rp_id_hash, rp_id_hash_expected):
        raise VerificationFailure("RP ID 摘要不匹配")

    # 备份 / 扩展 / RFU 位一律拒绝
    forbidden = FLAG_BE | FLAG_BS | FLAG_ED | FLAG_RFU1 | FLAG_RFU5
    if flags & forbidden:
        raise VerificationFailure(
            "不支持的 authenticator 标志（扩展/可备份/RFU 位被置位）"
        )
    if attestation:
        expected_flags = _ALLOWED_FLAGS_REGISTRATION
    else:
        expected_flags = _ALLOWED_FLAGS_ASSERTION
    if flags != expected_flags:
        raise VerificationFailure(
            f"authenticator 标志组合不符合要求: 0x{flags:02x}"
        )
    # UP / UV 是强制要求
    if not (flags & FLAG_UP and flags & FLAG_UV):
        raise VerificationFailure("用户在场或用户验证标志缺失")

    credential_id = None
    public_key = None

    if attestation:
        if len(raw) < 55:  # 37 + 16(aaguid) + 2(credLen)
            raise VerificationFailure("attested credential data 截断")
        # aaguid raw[37:53] —— 不限制具体值，但必须存在
        cred_len = int.from_bytes(raw[53:55], "big")
        if cred_len == 0:
            raise VerificationFailure("credential ID 长度为 0")
        cred_id_end = 55 + cred_len
        if len(raw) < cred_id_end:
            raise VerificationFailure("credential ID 截断")
        credential_id = raw[55:cred_id_end]
        cose_bytes = raw[cred_id_end:]
        if not cose_bytes:
            raise VerificationFailure("缺少 COSE 公钥")
        public_key = parse_cose_p256_key(cose_bytes)
        # ED=0 已保证没有扩展数据；CBOR exact 已保证公钥后无尾随字节
    elif len(raw) != 37:
        # 认证断言里不允许 attested credential data 或扩展
        raise VerificationFailure(
            "认证用 authenticatorData 必须恰为 37 字节且无扩展"
        )

    return AuthData(
        sign_count=sign_count,
        credential_id=credential_id,
        public_key=public_key,
    )


def is_der_ecdsa_signature(sig: bytes) -> bool:
    """签名必须是 ASN.1 DER（CTAP authenticator 输出格式），拒绝裸 R||S。"""
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    try:
        r, s = decode_dss_signature(sig)
    except (ValueError, TypeError):
        return False
    # 再做一次 DER round-trip：若 sig 含有非最短编码等冗余字节则不相等
    return encode_dss_signature(r, s) == sig


def verify_es256(
    public_key: ec.EllipticCurvePublicKey,
    signed_data: bytes,
    signature: bytes,
) -> None:
    """用 ES256（对 signed_data 取 SHA-256 的 ECDSA）验签，失败抛异常。"""
    if not isinstance(signature, (bytes, bytearray)) or len(signature) == 0:
        raise VerificationFailure("签名为空或类型错误")
    signature = bytes(signature)
    if not is_der_ecdsa_signature(signature):
        raise VerificationFailure("签名不是合法的 ASN.1 DER ECDSA 签名")
    try:
        # cryptography 内部对 signed_data 做 SHA-256；
        # signed_data 即 authData || SHA-256(clientDataJSON)
        public_key.verify(
            signature,
            signed_data,
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise VerificationFailure("ES256 签名验证失败") from exc


def parse_attestation_object(raw: bytes) -> tuple[str, bytes, dict]:
    """解析 attestationObject CBOR，返回 (fmt, authData, attStmt)。

    只允许恰好三个键 fmt/authData/attStmt，类型严格。
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) == 0:
        raise InvalidRequest("attestationObject 为空")
    obj = _cbor_decode_exact(bytes(raw), "attestationObject")
    if not isinstance(obj, dict):
        raise VerificationFailure("attestationObject 必须是 map")
    if set(obj.keys()) != {"fmt", "authData", "attStmt"}:
        raise VerificationFailure("attestationObject 字段集合不合法")
    fmt, auth_data, att_stmt = obj["fmt"], obj["authData"], obj["attStmt"]
    if not isinstance(fmt, str):
        raise VerificationFailure("attestation fmt 必须是字符串")
    if not isinstance(auth_data, bytes):
        raise VerificationFailure("attestation authData 必须是字节串")
    if not isinstance(att_stmt, dict):
        raise VerificationFailure("attestation attStmt 必须是 map")
    return fmt, auth_data, att_stmt


def verify_attestation(
    fmt: str,
    att_stmt: dict,
    auth_data: bytes,
    public_key: ec.EllipticCurvePublicKey,
    client_data_raw: bytes,
) -> None:
    """按限定规则验证证明语句。

    * ``none``：attStmt 必须为空 map；
    * ``packed``：仅接受自签名（不得含 x5c 证书链），alg 必须为 -7，
      sig 由凭据自身公钥在 authData || hash(clientDataJSON) 上验证；
    * 其他格式（含 fido-u2f / tpm / android-* 等）一律拒绝。
    """
    signed_base = auth_data + client_data_hash(client_data_raw)

    if fmt == "none":
        if att_stmt != {}:
            raise VerificationFailure("none 证明的 attStmt 必须为空")
        return

    if fmt == "packed":
        if "x5c" in att_stmt:
            # 证书链 / 非自签名 packed 证明不在支持范围内
            raise VerificationFailure("不支持 packed x5c 证书链证明")
        if set(att_stmt.keys()) != {"alg", "sig"}:
            raise VerificationFailure(
                "packed 自签名证明的 attStmt 必须恰好包含 alg 与 sig"
            )
        if att_stmt["alg"] != ALG_ES256:
            raise VerificationFailure("packed 证明仅接受 alg=-7 (ES256)")
        sig = att_stmt["sig"]
        if not isinstance(sig, bytes):
            raise VerificationFailure("packed sig 必须是字节串")
        verify_es256(public_key, signed_base, sig)
        return

    raise VerificationFailure(f"不支持的证明格式: {fmt!r}")
