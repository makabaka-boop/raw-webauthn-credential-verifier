"""WebAuthn 协议编排：挑战发放、注册与认证的完整校验与提交。

关键安全约束：
* origin / RP ID 只取自服务端 :class:`Config`；
* 所有验签都在 HTTP 收到的原始 clientDataJSON 字节上进行，绝不重新序列化；
* 成功路径的「挑战消耗 + 计数更新」在同一个 IMMEDIATE 事务中一次提交；
* 签名/证明验证在事务之外执行，失败时数据库不变，挑战不被消耗；
* 计数规则：记录值为 0 时允许持续返回 0；一旦记录为正数，只接受更大值。
"""

from __future__ import annotations

import hashlib
import hmac
import os

from .config import Config
from .crypto import (
    CLIENT_TYPE_CREATE,
    CLIENT_TYPE_GET,
    parse_attestation_object,
    parse_authenticator_data,
    parse_client_data,
    verify_attestation,
    verify_es256,
)
from .db import (
    PURPOSE_AUTHENTICATION,
    PURPOSE_REGISTRATION,
    Database,
)
from .encoding import b64url_decode, b64url_encode
from .errors import (
    ChallengeConsumed,
    CounterRejected,
    DuplicateCredential,
    InvalidRequest,
    VerificationFailure,
)

CHALLENGE_BYTES = 32
ES256 = -7
CREDENTIAL_TYPE = "public-key"
# CTAP 规范中 credential ID 最长 1023 字节
MAX_CREDENTIAL_ID_BYTES = 1023
# 顶层只接受标准 PublicKeyCredential 字段
_ALLOWED_BODY_KEYS = {
    "id", "rawId", "type", "response",
    "authenticatorAttachment", "getClientExtensionResults",
}


class WebAuthnService:
    def __init__(self, db: Database, config: Config):
        self.db = db
        self.config = config
        self._rp_id_hash = hashlib.sha256(config.rp_id.encode("utf-8")).digest()

    # ---- 挑战发放 ------------------------------------------------------

    def begin_registration(self, user_id: str) -> dict:
        self._require_user(user_id)
        challenge = self._new_challenge(user_id, PURPOSE_REGISTRATION)
        conn = self.db.connect()
        try:
            exclude = [
                {"type": CREDENTIAL_TYPE, "id": b64url_encode(cred_id)}
                for cred_id in self.db.list_credential_ids_for_user(conn, user_id)
            ]
        finally:
            conn.close()
        return {
            "challenge": b64url_encode(challenge),
            "rp": {"id": self.config.rp_id, "name": self.config.rp_name},
            "user": {
                "id": b64url_encode(user_id.encode("utf-8")),
                "name": user_id,
                "displayName": user_id,
            },
            "pubKeyCredParams": [{"type": CREDENTIAL_TYPE, "alg": ES256}],
            "timeout": 60000,
            # 要求用户验证；不允许可备份凭据
            "authenticatorSelection": {
                "requireResidentKey": True,
                "residentKey": "required",
                "userVerification": "required",
            },
            "attestation": "direct",
            "excludeCredentials": exclude,
        }

    def begin_authentication(self, user_id: str) -> dict:
        self._require_user(user_id)
        challenge = self._new_challenge(user_id, PURPOSE_AUTHENTICATION)
        conn = self.db.connect()
        try:
            allow = [
                {"type": CREDENTIAL_TYPE, "id": b64url_encode(cred_id)}
                for cred_id in self.db.list_credential_ids_for_user(conn, user_id)
            ]
        finally:
            conn.close()
        return {
            "challenge": b64url_encode(challenge),
            "timeout": 60000,
            "rpId": self.config.rp_id,
            "userVerification": "required",
            "allowCredentials": allow,
        }

    # ---- 注册完成 ------------------------------------------------------

    def finish_registration(self, user_id: str, body: dict) -> dict:
        self._check_body_shape(body)
        if body.get("type") != CREDENTIAL_TYPE:
            raise VerificationFailure("credential.type 必须为 public-key")
        credential_id = self._extract_credential_id(body)
        response = self._extract_response(body, "attestationObject")

        raw_cd = self._decode_field(response, "clientDataJSON")
        raw_att = self._decode_field(response, "attestationObject")

        # 1. clientDataJSON：原始字节、精确 origin、type
        cd = parse_client_data(raw_cd, CLIENT_TYPE_CREATE, self.config.origin)
        self._check_challenge(cd.challenge, user_id, PURPOSE_REGISTRATION)

        # 2. CBOR 证明对象 + 认证数据（含 RP ID 摘要 / UP / UV / 无扩展无备份）
        fmt, raw_auth, att_stmt = parse_attestation_object(raw_att)
        auth = parse_authenticator_data(
            raw_auth, self._rp_id_hash, attestation=True
        )
        if auth.credential_id is None or auth.public_key is None:
            raise VerificationFailure("注册认证数据缺少凭据信息")
        if not hmac.compare_digest(auth.credential_id, credential_id):
            raise VerificationFailure(
                "authenticatorData 中的 credential ID 与外层 id 不一致"
            )

        # 3. 证明：none 或 packed 自签名；packed 必须由该凭据公钥验证。
        #    验证数据使用 authData || SHA-256(收到的原始 clientDataJSON 字节)。
        verify_attestation(
            fmt, att_stmt, raw_auth, auth.public_key, raw_cd
        )

        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        public_point = auth.public_key.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

        # 4. 全部验证通过后，单事务完成：挑战消耗 + 凭据落库（含初始计数）
        with self.db.transaction() as conn:
            if not self.db.user_exists(conn, user_id):
                raise VerificationFailure("用户不存在")
            record = self._locked_challenge(
                conn, cd.challenge, user_id, PURPOSE_REGISTRATION
            )
            if record is None:
                # 已被并发的成功注册消耗
                raise ChallengeConsumed("挑战已被消耗")
            if self.db.credential_exists(conn, credential_id):
                raise DuplicateCredential("该 credential ID 已注册")
            self.db.insert_credential(
                conn,
                credential_id=credential_id,
                user_id=user_id,
                public_key=public_point,
                sign_count=auth.sign_count,
            )
            self.db.delete_challenge(conn, cd.challenge)

        return {
            "status": "ok",
            "credentialId": b64url_encode(credential_id),
            "signCount": auth.sign_count,
        }

    # ---- 认证完成 ------------------------------------------------------

    def finish_authentication(self, user_id: str, body: dict) -> dict:
        self._check_body_shape(body)
        if body.get("type") != CREDENTIAL_TYPE:
            raise VerificationFailure("credential.type 必须为 public-key")
        credential_id = self._extract_credential_id(body)
        response = self._extract_response(
            body, "authenticatorData", "signature"
        )

        raw_cd = self._decode_field(response, "clientDataJSON")
        raw_auth = self._decode_field(response, "authenticatorData")
        signature = self._decode_field(response, "signature")

        # 1. clientDataJSON：原始字节、精确 origin、type
        cd = parse_client_data(raw_cd, CLIENT_TYPE_GET, self.config.origin)
        self._check_challenge(cd.challenge, user_id, PURPOSE_AUTHENTICATION)

        # 2. 凭据归属（先在库外查一次，拿到验签公钥）
        row = self.db.get_credential(credential_id)
        if row is None:
            raise VerificationFailure("凭据不存在")
        if not hmac.compare_digest(row["user_id"], user_id):
            raise VerificationFailure("该 credential ID 不属于当前用户")
        public_key = self._load_public_key(row["public_key"])

        # 3. userHandle（若存在）必须与当前用户一致
        if "userHandle" in response and response["userHandle"] is not None:
            handle = self._decode_field(response, "userHandle")
            if not hmac.compare_digest(handle, user_id.encode("utf-8")):
                raise VerificationFailure("userHandle 与当前用户不一致")

        # 4. 认证数据：RP ID 摘要 / UP / UV / 无 attestedCredentialData / 无扩展
        auth = parse_authenticator_data(
            raw_auth, self._rp_id_hash, attestation=False
        )

        # 5. 规定的签名拼接：authenticatorData || SHA-256(clientDataJSON)，
        #    哈希输入是收到的原始字节，不重新序列化 JSON。
        signed_data = raw_auth + hashlib.sha256(raw_cd).digest()
        verify_es256(public_key, signed_data, signature)

        # 6. 验签通过后，单事务：行锁内复查计数 -> 更新计数 -> 消耗挑战。
        #    签名失败会在第 5 步抛出，根本不会进入这里，挑战保持可用。
        with self.db.transaction() as conn:
            if not self.db.user_exists(conn, user_id):
                raise VerificationFailure("用户不存在")
            record = self._locked_challenge(
                conn, cd.challenge, user_id, PURPOSE_AUTHENTICATION
            )
            if record is None:
                raise ChallengeConsumed("挑战已被消耗")
            locked = self.db.locked_get_credential(conn, credential_id)
            if locked is None or not hmac.compare_digest(
                locked["user_id"], user_id
            ):
                raise VerificationFailure("凭据归属校验失败")
            stored = locked["sign_count"]
            if stored > 0 and auth.sign_count <= stored:
                raise CounterRejected(
                    f"签名计数必须严格大于已记录的 {stored}，"
                    f"实际 {auth.sign_count}"
                )
            self.db.update_sign_count(conn, credential_id, auth.sign_count)
            self.db.delete_challenge(conn, cd.challenge)

        return {
            "status": "ok",
            "credentialId": b64url_encode(credential_id),
            "signCount": auth.sign_count,
        }

    # ---- 内部辅助 ------------------------------------------------------

    @staticmethod
    def _check_body_shape(body: object) -> None:
        if not isinstance(body, dict):
            raise InvalidRequest("请求体必须是 JSON 对象")
        unknown = set(body) - _ALLOWED_BODY_KEYS
        if unknown:
            raise InvalidRequest(f"请求体含未知字段: {sorted(unknown)}")
        exts = body.get("getClientExtensionResults")
        if exts is not None and exts != {}:
            raise VerificationFailure("本服务不支持任何凭据扩展")
        attachment = body.get("authenticatorAttachment")
        if attachment is not None and attachment not in ("platform", "cross-platform"):
            raise InvalidRequest("authenticatorAttachment 值非法")

    def _require_user(self, user_id: str) -> None:
        conn = self.db.connect()
        try:
            if not self.db.user_exists(conn, user_id):
                raise VerificationFailure("用户不存在")
        finally:
            conn.close()

    def _new_challenge(self, user_id: str, purpose: str) -> bytes:
        challenge = os.urandom(CHALLENGE_BYTES)
        self.db.store_challenge(challenge, user_id, purpose)
        return challenge

    def _check_challenge(
        self, challenge: bytes, user_id: str, purpose: str
    ) -> None:
        """库外快检：挑战必须存在、属于当前用户、用途匹配（不消耗）。"""
        record = self.db.get_challenge(challenge)
        if record is None:
            raise ChallengeConsumed("挑战不存在或已被消耗")
        rec_user, rec_purpose = record
        if rec_purpose != purpose:
            raise VerificationFailure(
                f"挑战用途错误：期望 {purpose}，实际 {rec_purpose}"
            )
        if not hmac.compare_digest(rec_user, user_id):
            raise VerificationFailure("挑战不属于当前用户")

    def _locked_challenge(
        self, conn, challenge: bytes, user_id: str, purpose: str
    ) -> tuple[str, str] | None:
        """事务内复查挑战（存在性 + 用户 + 用途）。"""
        row = conn.execute(
            "SELECT user_id, purpose FROM challenges WHERE challenge = ?",
            (challenge,),
        ).fetchone()
        if row is None:
            return None
        if row["purpose"] != purpose or not hmac.compare_digest(
            row["user_id"], user_id
        ):
            # 正常情况下库外快检已拦；并发或异常下在这里兜底
            raise VerificationFailure("挑战记录与当前操作不匹配")
        return row["user_id"], row["purpose"]

    @staticmethod
    def _extract_credential_id(body: dict) -> bytes:
        if "id" not in body:
            raise InvalidRequest("缺少 credential id")
        raw_id = body["id"]
        if not isinstance(raw_id, str):
            raise InvalidRequest("credential id 必须是 base64url 字符串")
        if "rawId" in body and body["rawId"] != raw_id:
            raise VerificationFailure("id 与 rawId 不一致")
        cred_id = b64url_decode(raw_id)
        if len(cred_id) == 0:
            raise VerificationFailure("credential ID 为空")
        if len(cred_id) > MAX_CREDENTIAL_ID_BYTES:
            raise InvalidRequest("credential ID 超过最大长度")
        return cred_id

    @staticmethod
    def _extract_response(body: dict, *required: str) -> dict:
        response = body.get("response")
        if not isinstance(response, dict):
            raise InvalidRequest("缺少 response 对象")
        for key in required:
            if key not in response:
                raise InvalidRequest(f"response 缺少 {key}")
            if not isinstance(response[key], str):
                raise InvalidRequest(f"response.{key} 必须是 base64url 字符串")
        allowed = {
            "clientDataJSON",
            "attestationObject",
            "authenticatorData",
            "signature",
            "userHandle",
            "transports",
            "publicKeyAlgorithm",
            "publicKey",
            "authenticatorAttachment",
        }
        unknown = set(response) - allowed
        if unknown:
            raise InvalidRequest(f"response 含未知字段: {sorted(unknown)}")
        return response

    @staticmethod
    def _decode_field(response: dict, key: str) -> bytes:
        return b64url_decode(response[key])

    @staticmethod
    def _load_public_key(point: bytes):
        from cryptography.hazmat.primitives.asymmetric import ec

        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), bytes(point)
            )
        except ValueError as exc:
            raise VerificationFailure("库内公钥无法加载") from exc
