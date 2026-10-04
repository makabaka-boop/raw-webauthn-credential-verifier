"""WebAuthn 核心验证（刻意缩小的实现范围）。

只支持：
  * attestation: ``none`` 与 ``packed``（且仅 self attestation，无证书链）
  * 公钥参数: ES256 / COSE EC2 / P-256
  * 标志: UP=1、UV=1、BE=0、BS=0，无扩展
  * origin 与 RP ID 使用服务端固定配置

所有签名都对“收到的原始字节”计算：clientDataJSON 原样哈希，绝不重新
序列化 JSON。
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from . import cbor, crypto, store

ES256 = -7
FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40
FLAG_ED = 0x80
RP_ID_HASH_LEN = 32
MIN_CRED_ID = 16
MAX_CRED_ID = 1024


class WebAuthnError(Exception):
    pass


@dataclass(frozen=True)
class RegisterResult:
    credential_id: bytes
    user_id: str
    sign_count: int


@dataclass(frozen=True)
class AuthnResult:
    user_id: str
    credential_id: bytes
    sign_count: int


def b64url_decode(data: str | bytes) -> bytes:
    if isinstance(data, bytes):
        data = data.decode("ascii")
    pad = (-len(data)) % 4
    try:
        import base64

        return base64.urlsafe_b64decode(data + ("=" * pad))
    except Exception as exc:  # malformed base64
        raise WebAuthnError("base64url 解码失败") from exc


def b64url_encode(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _parse_client_json(raw: bytes, expected_type: str, cfg_origin: str, expected_challenge: bytes) -> None:
    """直接针对原始 clientDataJSON 字节校验。

    JSON 只用于读取字段，验签哈希仍然使用调用方收到的原字节，不重新
    dump，因此键序/空白差异只要客户端对同样字节签名就可通过。
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) == 0:
        raise WebAuthnError("clientDataJSON 必须是非空原始字节")
    raw = bytes(raw)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebAuthnError("clientDataJSON 不是合法 UTF-8 JSON") from exc
    if not isinstance(obj, dict):
        raise WebAuthnError("clientDataJSON 顶层必须是对象")

    c_type = obj.get("type")
    if c_type != expected_type:
        raise WebAuthnError(f"clientDataJSON.type 必须为 {expected_type!r}，实际为 {c_type!r}")

    raw_origin = obj.get("origin")
    # 精确字符串比较：不做尾斜杠归一化、不做后缀匹配（防止 example.com 后缀攻击）。
    if not isinstance(raw_origin, str) or raw_origin != cfg_origin:
        raise WebAuthnError(f"origin 与服务端固定值不符: {raw_origin!r}")

    raw_challenge = obj.get("challenge")
    if not isinstance(raw_challenge, str):
        raise WebAuthnError("clientDataJSON.challenge 必须是 base64url 字符串")
    decoded = b64url_decode(raw_challenge)
    if decoded != expected_challenge:
        raise WebAuthnError("clientDataJSON.challenge 与服务端发出的挑战不一致")

    # tokenBinding 若出现必须与服务端策略一致：本服务不支持，缺失即可。
    if "tokenBinding" in obj and obj["tokenBinding"] is not None:
        raise WebAuthnError("本服务不支持 tokenBinding")


def _parse_auth_data(auth_data: bytes, expect_attestation: bool, rp_id_hash: bytes):
    if len(auth_data) < RP_ID_HASH_LEN + 1 + 4:
        raise WebAuthnError("authenticatorData 被截断（不足 37 字节）")
    got_hash = auth_data[:RP_ID_HASH_LEN]
    if got_hash != rp_id_hash:
        raise WebAuthnError("RP ID 摘要不匹配")
    flags = auth_data[RP_ID_HASH_LEN]
    if not flags & FLAG_UP:
        raise WebAuthnError("用户在场标志 UP 必须置位")
    if not flags & FLAG_UV:
        raise WebAuthnError("用户验证标志 UV 必须置位")
    if flags & FLAG_BE:
        raise WebAuthnError("不支持可备份凭据（BE 必须为 0）")
    if flags & FLAG_BS:
        raise WebAuthnError("不支持可备份凭据（BS 必须为 0）")
    if expect_attestation and not flags & FLAG_AT:
        raise WebAuthnError("注册 authenticatorData 必须带 attested credential data")
    if not expect_attestation and flags & FLAG_AT:
        raise WebAuthnError("认证 authenticatorData 不得带 attested credential data")
    if flags & FLAG_ED:
        raise WebAuthnError("本服务不支持 authenticator 扩展（ED 必须为 0）")

    sign_count = int.from_bytes(auth_data[RP_ID_HASH_LEN + 1 : RP_ID_HASH_LEN + 5], "big")
    offset = RP_ID_HASH_LEN + 5

    attested = None
    if expect_attestation:
        if len(auth_data) < offset + 16 + 2:
            raise WebAuthnError("attested credential data 被截断")
        aaguid = auth_data[offset : offset + 16]
        if aaguid != b"\x00" * 16:
            raise WebAuthnError("AAGUID 必须为全零（测试夹具）")
        offset += 16
        cred_len = int.from_bytes(auth_data[offset : offset + 2], "big")
        offset += 2
        if not (MIN_CRED_ID <= cred_len <= MAX_CRED_ID):
            raise WebAuthnError("credential ID 长度超出允许范围")
        if len(auth_data) < offset + cred_len:
            raise WebAuthnError("credential ID 被截断")
        credential_id = auth_data[offset : offset + cred_len]
        offset += cred_len
        cose_bytes = auth_data[offset:]
        try:
            cose_key = cbor.loads(cose_bytes)
        except cbor.CBORError as exc:
            raise WebAuthnError(f"COSE 公钥解析失败: {exc}") from exc
        offset = len(auth_data)
        attested = (credential_id, cose_key, cose_bytes)

    if offset != len(auth_data):
        raise WebAuthnError("authenticatorData 尾部存在无法识别的多余字节")
    return flags, sign_count, attested


def _parse_cose_p256(cose_key: object) -> crypto.PublicKey:
    if not isinstance(cose_key, dict):
        raise WebAuthnError("COSE 公钥必须是 CBOR map")
    kty = cose_key.get(1)
    if kty != 2:
        raise WebAuthnError(f"仅支持 EC2 公钥 (kty=2)，实际 kty={kty!r}")
    alg = cose_key.get(3)
    if alg != ES256:
        raise WebAuthnError(f"仅支持 ES256 (alg=-7)，实际 alg={alg!r}")
    crv = cose_key.get(-1)
    if crv != 1:
        raise WebAuthnError(f"仅支持 P-256 (crv=1)，实际 crv={crv!r}")
    x = cose_key.get(-2)
    y = cose_key.get(-3)
    if not isinstance(x, bytes) or not isinstance(y, bytes):
        raise WebAuthnError("COSE 公钥 x/y 必须是字节串")
    if len(x) != 32 or len(y) != 32:
        raise WebAuthnError("P-256 坐标 x/y 必须各为 32 字节")
    # 拒绝多给出的未知 COSE 字段（防止把未验证扩展塞进公钥结构）。
    allowed = {1, 3, -1, -2, -3}
    extra = set(cose_key) - allowed
    if extra:
        raise WebAuthnError(f"COSE 公钥含未允许字段: {sorted(extra)}")
    pub = crypto.PublicKey(int.from_bytes(x, "big"), int.from_bytes(y, "big"))
    if not pub.is_valid():
        raise WebAuthnError("COSE 公钥坐标不在 P-256 曲线上")
    return pub


def verify_registration(
    conn: sqlite3.Connection,
    cfg,
    *,
    user_id: str,
    client_data_json: bytes,
    attestation_object: bytes,
) -> RegisterResult:
    if not isinstance(user_id, str) or not user_id:
        raise WebAuthnError("user_id 必须由测试夹具提供")
    if not isinstance(client_data_json, (bytes, bytearray)):
        raise WebAuthnError("clientDataJSON 必须以原始字节提交")
    if not isinstance(attestation_object, (bytes, bytearray)):
        raise WebAuthnError("attestationObject 必须以原始字节提交")
    client_data_json = bytes(client_data_json)
    attestation_object = bytes(attestation_object)

    # 先从原始 JSON 中取挑战（JSON 解析只用于读字段）。
    try:
        peek = json.loads(client_data_json.decode("utf-8"))
    except Exception as exc:
        raise WebAuthnError("clientDataJSON 不是合法 JSON") from exc
    challenge = b64url_decode(peek.get("challenge", "")) if isinstance(peek, dict) and isinstance(peek.get("challenge"), str) else None
    if challenge is None:
        raise WebAuthnError("clientDataJSON.challenge 缺失或格式错误")

    # 用途必须是 registration；认证挑战不能用于注册。
    owner = store.get_pending_challenge(conn, challenge, store.PURPOSE_REGISTRATION)
    if owner is None:
        # 已消费是其中最常见的子情况：单独给出与事务层一致的异常类型，
        # 便于调用方区分“挑战用过了”和“挑战根本不认识”。
        if challenge:
            row = conn.execute(
                "SELECT purpose, consumed FROM challenges WHERE challenge=?",
                (challenge,),
            ).fetchone()
            if row is not None and row[0] == store.PURPOSE_REGISTRATION and row[1] == 1:
                raise store.ChallengeAlreadyConsumed("注册挑战已被消费")
        raise WebAuthnError("没有匹配的、未消费的注册挑战（或挑战用途错误）")
    if owner != user_id:
        raise WebAuthnError("挑战归属用户与请求用户不一致")

    _parse_client_json(client_data_json, "webauthn.create", cfg.origin, challenge)

    try:
        att = cbor.loads(attestation_object)
    except cbor.CBORError as exc:
        raise WebAuthnError(f"attestationObject CBOR 解析失败: {exc}") from exc
    if not isinstance(att, dict):
        raise WebAuthnError("attestationObject 顶层必须是 CBOR map")
    if set(att.keys()) - {"fmt", "attStmt", "authData"}:
        raise WebAuthnError("attestationObject 含未识别字段")
    fmt = att.get("fmt")
    auth_data_raw = att.get("authData")
    stmt = att.get("attStmt")
    if not isinstance(fmt, str) or not isinstance(auth_data_raw, bytes) or not isinstance(stmt, dict):
        raise WebAuthnError("attestationObject 的 fmt/authData/attStmt 类型错误")

    rp_id_hash = crypto.sha256(cfg.rp_id.encode("utf-8"))
    _, sign_count, attested = _parse_auth_data(auth_data_raw, True, rp_id_hash)
    credential_id, cose_key, cose_bytes = attested  # type: ignore[misc]
    pub = _parse_cose_p256(cose_key)

    client_hash = crypto.sha256(client_data_json)
    signed = auth_data_raw + client_hash

    if fmt == "none":
        if stmt != {}:
            raise WebAuthnError("none 证明必须携带空 attStmt")
        # 按规范建议，none 证明仅允许签名计数为 0 的自证明场景。
        if sign_count != 0:
            raise WebAuthnError("none 证明要求签名计数为 0")
    elif fmt == "packed":
        alg = stmt.get("alg")
        sig = stmt.get("sig")
        if alg != ES256:
            raise WebAuthnError("packed 证明仅接受 alg=-7 (ES256)")
        if not isinstance(sig, bytes):
            raise WebAuthnError("packed attStmt.sig 必须是字节串")
        # 明确禁止证书链 / x5c，只允许 self attestation。
        if "x5c" in stmt:
            raise WebAuthnError("本服务不支持证书链证明（packed x5c）")
        if set(stmt.keys()) - {"alg", "sig"}:
            raise WebAuthnError("packed self attStmt 含未识别字段")
        # self attestation：用注册公钥本身验证 authData||hash(clientDataJSON)。
        try:
            crypto.raw_verify(pub, signed, sig)
        except crypto.CryptoError as exc:
            raise WebAuthnError(f"packed 自签名验证失败: {exc}") from exc
    else:
        raise WebAuthnError(f"不支持的证明格式: {fmt!r}（仅 none / packed self）")

    # 验证全部通过后，单次事务提交：消费挑战 + 写入凭据。
    store.commit_registration(
        conn,
        challenge=challenge,
        user_id=user_id,
        credential_id=credential_id,
        pub_cose=cose_bytes,
        sign_count=sign_count,
    )
    return RegisterResult(credential_id=credential_id, user_id=user_id, sign_count=sign_count)


def verify_authentication(
    conn: sqlite3.Connection,
    cfg,
    *,
    user_id: str,
    credential_id: bytes,
    client_data_json: bytes,
    authenticator_data: bytes,
    signature: bytes,
) -> AuthnResult:
    if not isinstance(credential_id, (bytes, bytearray)) or not credential_id:
        raise WebAuthnError("credential ID 必须是原始字节")
    credential_id = bytes(credential_id)
    if not isinstance(client_data_json, (bytes, bytearray)):
        raise WebAuthnError("clientDataJSON 必须以原始字节提交")
    if not isinstance(authenticator_data, (bytes, bytearray)):
        raise WebAuthnError("authenticatorData 必须以原始字节提交")
    if not isinstance(signature, (bytes, bytearray)):
        raise WebAuthnError("signature 必须以原始字节提交")
    client_data_json = bytes(client_data_json)
    authenticator_data = bytes(authenticator_data)
    signature = bytes(signature)

    cred = store.get_credential(conn, credential_id)
    if cred is None:
        raise WebAuthnError("凭据不存在")
    if cred.user_id != user_id:
        raise WebAuthnError("credential ID 不属于该用户")

    try:
        peek = json.loads(client_data_json.decode("utf-8"))
    except Exception as exc:
        raise WebAuthnError("clientDataJSON 不是合法 JSON") from exc
    if not isinstance(peek, dict) or not isinstance(peek.get("challenge"), str):
        raise WebAuthnError("clientDataJSON.challenge 缺失或格式错误")
    challenge = b64url_decode(peek["challenge"])

    owner = store.get_pending_challenge(conn, challenge, store.PURPOSE_AUTHENTICATION)
    if owner is None:
        if challenge:
            row = conn.execute(
                "SELECT purpose, consumed FROM challenges WHERE challenge=?",
                (challenge,),
            ).fetchone()
            if row is not None and row[0] == store.PURPOSE_AUTHENTICATION and row[1] == 1:
                raise store.ChallengeAlreadyConsumed("认证挑战已被消费")
        raise WebAuthnError("没有匹配的、未消费的认证挑战（或挑战用途错误）")
    if owner != user_id:
        raise WebAuthnError("挑战归属用户与凭据用户不一致")

    _parse_client_json(client_data_json, "webauthn.get", cfg.origin, challenge)
    rp_id_hash = crypto.sha256(cfg.rp_id.encode("utf-8"))
    _, sign_count, attested = _parse_auth_data(authenticator_data, False, rp_id_hash)
    if attested is not None:  # 防御性：解析器本身已拒绝
        raise WebAuthnError("认证响应不得包含 attested credential data")

    # 计数规则在事务里最终裁决；这里先按 WebAuthn 语义拒绝明显倒退。
    if sign_count < 0:
        raise WebAuthnError("签名计数不能为负")
    if cred.sign_count > 0 and sign_count <= cred.sign_count:
        # 签名验证前即可判定的计数违规；不验签也不消费挑战。
        # 与事务层使用同一异常类型，调用方无论拒绝点在哪都能稳定识别。
        raise store.CounterRejected(
            f"签名计数未严格增大（已记录 {cred.sign_count}，收到 {sign_count}）"
        )

    # 解析已保存的 COSE 公钥；签名内容固定为
    #   authenticatorData || SHA-256(clientDataJSON 原始字节)
    try:
        cose_key = cbor.loads(cred.pub_cose)
    except cbor.CBORError as exc:  # pragma: no cover - 入库时已验证
        raise WebAuthnError("已保存公钥无法解析") from exc
    pub = _parse_cose_p256(cose_key)
    signed = authenticator_data + crypto.sha256(client_data_json)
    try:
        crypto.raw_verify(pub, signed, signature)
    except crypto.CryptoError as exc:
        # 签名失败：到此为止没有任何写入，挑战保持未消费。
        raise WebAuthnError(f"认证签名验证失败: {exc}") from exc

    final_count = store.commit_authentication(
        conn,
        challenge=challenge,
        user_id=user_id,
        credential_id=credential_id,
        new_count=sign_count,
    )
    return AuthnResult(user_id=user_id, credential_id=credential_id, sign_count=final_count)
