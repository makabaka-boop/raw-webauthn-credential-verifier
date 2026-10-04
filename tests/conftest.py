"""共享 pytest 夹具。

``TestAuthenticator`` 用真实生成的 P-256 椭圆曲线密钥构造注册 / 认证载荷，
签名按 CTAP 规则输出 ASN.1 DER，证明对象用 CBOR 编码。
"""

from __future__ import annotations

import hashlib
import json
import os

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from webauthn_limited.app import create_app
from webauthn_limited.config import Config
from webauthn_limited.crypto import (
    FLAG_AT,
    FLAG_UP,
    FLAG_UV,
)
from webauthn_limited.db import Database
from webauthn_limited.encoding import b64url_encode
from webauthn_limited.service import WebAuthnService

RP_ID = "example.test"
ORIGIN = "https://example.test"
ALICE = "alice"
BOB = "bob"


class TestAuthenticator:
    """模拟一个真实 CTAP2 authenticator（ES256 / P-256）。"""

    # 避免 pytest 把本类当成测试用例收集
    __test__ = False

    def __init__(self, rp_id: str = RP_ID, origin: str = ORIGIN,
                 sign_count: int = 0, credential_id: bytes | None = None):
        self.rp_id = rp_id
        self.origin = origin
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.credential_id = credential_id or os.urandom(32)
        self.aaguid = b"\x00" * 16
        self.sign_count = sign_count

    # ---- 密钥与签名 ----------------------------------------------------

    def cose_key(self) -> bytes:
        nums = self.public_key.public_numbers()
        return cbor2.dumps({
            1: 2,      # kty: EC2
            3: -7,     # alg: ES256
            -1: 1,     # crv: P-256
            -2: nums.x.to_bytes(32, "big"),
            -3: nums.y.to_bytes(32, "big"),
        })

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def sign_raw_rs(self, data: bytes) -> bytes:
        """输出裸 R||S（64 字节），用于证明服务拒绝非 DER 签名。"""
        der = self.sign(data)
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    # ---- 数据构造 ------------------------------------------------------

    def client_data_json(
        self,
        challenge: bytes | str,
        ctype: str,
        *,
        origin: str | None = None,
        style: str = "canonical",
        cross_origin: bool = False,
        token_binding: object = None,
    ) -> bytes:
        if isinstance(challenge, bytes):
            challenge = b64url_encode(challenge)
        obj = {
            "challenge": challenge,
            "origin": origin or self.origin,
            "type": ctype,
        }
        if cross_origin:
            obj["crossOrigin"] = True
        if token_binding is not None:
            obj["tokenBinding"] = token_binding

        if style == "canonical":  # 紧凑、字典序
            return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
        if style == "spaces":  # 含空白，但字节完全合法
            return json.dumps(obj, indent=2).encode()
        if style == "reordered":  # 调换键序
            return json.dumps(
                {"type": obj["type"], "origin": obj["origin"],
                 "challenge": obj["challenge"]},
                separators=(",", ":"),
            ).encode()
        raise ValueError(f"未知 style: {style}")

    def auth_data(
        self,
        *,
        flags: int | None = None,
        sign_count: int | None = None,
        attested: bool = True,
        rp_id: str | None = None,
        aaguid: bytes | None = None,
        credential_id: bytes | None = None,
        cose: bytes | None = None,
        extension_bytes: bytes = b"",
    ) -> bytes:
        rp_id = rp_id or self.rp_id
        if flags is None:
            flags = FLAG_UP | FLAG_UV | (FLAG_AT if attested else 0)
        if sign_count is None:
            sign_count = self.sign_count
        raw = hashlib.sha256(rp_id.encode()).digest()
        raw += bytes([flags])
        raw += int(sign_count).to_bytes(4, "big")
        if attested:
            raw += aaguid if aaguid is not None else self.aaguid
            cid = credential_id if credential_id is not None else self.credential_id
            raw += len(cid).to_bytes(2, "big") + cid
            raw += cose if cose is not None else self.cose_key()
        raw += extension_bytes
        return raw

    def attestation_object(
        self,
        auth_data: bytes,
        client_data: bytes,
        *,
        fmt: str = "packed",
        signer: "TestAuthenticator | None" = None,
        alg: int = -7,
        x5c: list[bytes] | None = None,
        extra_stmt: dict | None = None,
    ) -> bytes:
        signed = auth_data + hashlib.sha256(client_data).digest()
        if fmt == "none":
            stmt: dict = {}
        elif fmt == "packed":
            stmt = {"alg": alg, "sig": (signer or self).sign(signed)}
            if x5c is not None:
                stmt["x5c"] = x5c
            if extra_stmt:
                stmt.update(extra_stmt)
        else:  # 不支持的格式，服务应拒绝
            stmt = {}
        return cbor2.dumps({"fmt": fmt, "authData": auth_data, "attStmt": stmt})

    # ---- 完整载荷 ------------------------------------------------------

    def registration_body(
        self,
        challenge: bytes | str,
        *,
        fmt: str = "packed",
        cd_style: str = "canonical",
        origin: str | None = None,
        ctype: str = "webauthn.create",
        flags: int | None = None,
        sign_count: int | None = None,
        signer: "TestAuthenticator | None" = None,
        auth_data: bytes | None = None,
        client_data: bytes | None = None,
        raw_id_override: bytes | None = None,
        x5c: list[bytes] | None = None,
        att_alg: int = -7,
        cross_origin: bool = False,
        token_binding: object = None,
        include_user_handle: bool = False,
    ) -> dict:
        cd = client_data or self.client_data_json(
            challenge, ctype, origin=origin, style=cd_style,
            cross_origin=cross_origin, token_binding=token_binding,
        )
        ad = auth_data or self.auth_data(flags=flags, sign_count=sign_count)
        att = self.attestation_object(
            ad, cd, fmt=fmt, signer=signer, alg=att_alg, x5c=x5c
        )
        rid = raw_id_override if raw_id_override is not None else self.credential_id
        response = {"clientDataJSON": b64url_encode(cd),
                    "attestationObject": b64url_encode(att)}
        if include_user_handle:
            response["userHandle"] = b64url_encode(ALICE.encode())
        return {
            "id": b64url_encode(rid),
            "rawId": b64url_encode(rid),
            "type": "public-key",
            "response": response,
        }

    def assertion_body(
        self,
        challenge: bytes | str,
        *,
        cd_style: str = "canonical",
        origin: str | None = None,
        ctype: str = "webauthn.get",
        flags: int | None = None,
        sign_count: int | None = None,
        auth_data: bytes | None = None,
        client_data: bytes | None = None,
        signature: bytes | None = None,
        raw_rs: bool = False,
        signer: "TestAuthenticator | None" = None,
        credential_id: bytes | None = None,
        user_handle: bytes | str | None = b"",
        cross_origin: bool = False,
    ) -> dict:
        cd = client_data or self.client_data_json(
            challenge, ctype, origin=origin, style=cd_style,
            cross_origin=cross_origin,
        )
        ad = auth_data or self.auth_data(
            attested=False, flags=flags, sign_count=sign_count
        )
        signed = ad + hashlib.sha256(cd).digest()
        if signature is None:
            signer = signer or self
            signature = signer.sign_raw_rs(signed) if raw_rs else signer.sign(signed)
        response = {
            "clientDataJSON": b64url_encode(cd),
            "authenticatorData": b64url_encode(ad),
            "signature": b64url_encode(signature),
        }
        if isinstance(user_handle, bytes):
            response["userHandle"] = b64url_encode(user_handle)
        elif isinstance(user_handle, str):
            response["userHandle"] = user_handle
        # user_handle=None 表示不带该字段；b"" 默认编码为空串
        cid = credential_id if credential_id is not None else self.credential_id
        return {
            "id": b64url_encode(cid),
            "rawId": b64url_encode(cid),
            "type": "public-key",
            "response": response,
        }


# ---------- fixtures ----------

@pytest.fixture
def config(tmp_path):
    return Config(
        rp_id=RP_ID,
        rp_name="Test RP",
        origin=ORIGIN,
        db_path=str(tmp_path / "test.db"),
    )


@pytest.fixture
def db(config):
    database = Database(config.db_path)
    database.upsert_user(ALICE, "Alice")
    database.upsert_user(BOB, "Bob")
    return database


@pytest.fixture
def service(db, config):
    return WebAuthnService(db, config)


@pytest.fixture
def app(db, config):
    application = create_app(config, db)
    application.testing = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth():
    return TestAuthenticator()


class ApiClient:
    """带固定测试夹具用户头的便捷调用器。"""

    def __init__(self, flask_client, user_id: str = ALICE):
        self.c = flask_client
        self.user_id = user_id

    def post(self, path: str, body=None):
        headers = {"X-Test-User": self.user_id}
        return self.c.post(path, json=body if body is not None else {}, headers=headers)

    def begin(self, kind: str) -> bytes:
        resp = self.post(f"/{kind}/begin")
        assert resp.status_code == 200, resp.get_json()
        from webauthn_limited.encoding import b64url_decode
        return b64url_decode(resp.get_json()["challenge"])

    def finish(self, kind: str, body: dict):
        return self.post(f"/{kind}/finish", body)


@pytest.fixture
def api(client):
    return ApiClient(client, ALICE)


@pytest.fixture
def register(api):
    """返回一个函数：用给定 authenticator 走完整注册，返回响应。"""

    def _register(authenticator: TestAuthenticator, *, fmt: str = "packed",
                  sign_count: int | None = None, cd_style: str = "canonical",
                  **kwargs):
        challenge = api.begin("register")
        body = authenticator.registration_body(
            challenge, fmt=fmt,
            sign_count=authenticator.sign_count if sign_count is None else sign_count,
            cd_style=cd_style, **kwargs,
        )
        return api.finish("register", body)

    return _register
