"""测试用“真实”认证器：每次注册生成真实 P-256 密钥对，并用私钥
对真实拼接数据做 ECDSA-SHA256 签名（纯标准库实现）。

签名输出为 WebAuthn 规定的 IEEE P1363 r||s（各 32 字节）。
"""

from __future__ import annotations

import json
import os

from webauthn_lite import cbor, crypto
from webauthn_lite.webauthn import FLAG_UP, FLAG_UV, FLAG_AT, ES256, b64url_encode

AAGUID_ZERO = b"\x00" * 16


class Authenticator:
    """持有一个已注册凭据（真实私钥 + credential ID + 计数）。"""

    def __init__(self, rp_id: str, sign_count: int = 0, credential_id: bytes | None = None):
        self.rp_id = rp_id
        self.private = crypto.generate_key()
        self.credential_id = credential_id or os.urandom(32)
        self.sign_count = sign_count

    # ---- COSE ES256 公钥 ----
    def cose_public_key(self) -> bytes:
        x, y = self.private.public.xy_bytes()
        key = {
            1: 2,      # kty: EC2
            3: ES256,  # alg: ES256
            -1: 1,     # crv: P-256
            -2: x,
            -3: y,
        }
        return cbor.dumps(key)

    # ---- 可定制字节的 clientDataJSON ----
    @staticmethod
    def client_data_json(
        type_: str,
        challenge: bytes,
        origin: str,
        *,
        raw_bytes: bytes | None = None,
        extra_whitespace: bool = False,
        reordered: bool = False,
    ) -> bytes:
        if raw_bytes is not None:
            return raw_bytes
        challenge_b64 = b64url_encode(challenge)
        obj = {"type": type_, "challenge": challenge_b64, "origin": origin}
        if extra_whitespace:
            # 非规范但合法的 JSON；服务端必须按原样字节验签。
            text = (
                '{ "challenge": "' + challenge_b64 + '",\n'
                '  "origin": ' + json.dumps(origin) + ',\n'
                '  "type": ' + json.dumps(type_) + ' }'
            )
            return text.encode("utf-8")
        if reordered:
            text = json.dumps({"origin": origin, "challenge": challenge_b64, "type": type_})
            return text.encode("utf-8")
        return json.dumps(obj).encode("utf-8")

    def rp_id_hash(self) -> bytes:
        return crypto.sha256(self.rp_id.encode("utf-8"))

    def _auth_data_base(self, flags: int) -> bytes:
        return self.rp_id_hash() + bytes([flags]) + self.sign_count.to_bytes(4, "big")

    def make_attestation_auth_data(self, *, flags_override: int | None = None) -> bytes:
        flags = FLAG_UP | FLAG_UV | FLAG_AT if flags_override is None else flags_override
        return (
            self._auth_data_base(flags)
            + AAGUID_ZERO
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id
            + self.cose_public_key()
        )

    def make_assertion_auth_data(self, *, flags_override: int | None = None) -> bytes:
        flags = FLAG_UP | FLAG_UV if flags_override is None else flags_override
        return self._auth_data_base(flags)

    # ---- 注册响应 ----
    def register_response(
        self,
        challenge: bytes,
        origin: str,
        *,
        fmt: str = "packed",
        client_data_json: bytes | None = None,
        auth_data: bytes | None = None,
        att_stmt_overrides: dict | None = None,
    ) -> dict:
        cdj = client_data_json or self.client_data_json("webauthn.create", challenge, origin)
        ad = auth_data or self.make_attestation_auth_data()
        if fmt == "none":
            stmt: dict = {}
        elif fmt == "packed":
            sig = crypto.raw_sign(self.private.d, ad + crypto.sha256(cdj))
            stmt = {"alg": ES256, "sig": sig}
        else:
            raise ValueError(f"未知 fmt {fmt}")
        if att_stmt_overrides is not None:
            stmt = {**stmt, **att_stmt_overrides}
        att_obj = cbor.dumps({"fmt": fmt, "attStmt": stmt, "authData": ad})
        return {"clientDataJSON": cdj, "attestationObject": att_obj}

    # ---- 认证响应 ----
    def authenticate_response(
        self,
        challenge: bytes,
        origin: str,
        *,
        client_data_json: bytes | None = None,
        auth_data: bytes | None = None,
        sign_count: int | None = None,
        sign_with: "Authenticator | None" = None,
    ) -> dict:
        old_count = self.sign_count
        if sign_count is not None:
            self.sign_count = sign_count
        cdj = client_data_json or self.client_data_json("webauthn.get", challenge, origin)
        ad = auth_data or self.make_assertion_auth_data()
        self.sign_count = old_count
        signer = sign_with or self
        sig = crypto.raw_sign(signer.private.d, ad + crypto.sha256(cdj))
        return {
            "credential_id": self.credential_id,
            "clientDataJSON": cdj,
            "authenticatorData": ad,
            "signature": sig,
            "sign_count_used": int.from_bytes(ad[33:37], "big"),
        }
