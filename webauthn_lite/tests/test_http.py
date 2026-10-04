"""HTTP 端到端：真实监听端口，请求不能更改 origin / RP ID。

运行：python3 -m unittest webauthn_lite.tests.test_http -v
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from webauthn_lite import config as config_mod
from webauthn_lite import store
from webauthn_lite.server import make_server
from webauthn_lite.webauthn import b64url_encode, b64url_decode

from .fake_authenticator import Authenticator

ORIGIN = "http://testrp.example:9999"
RP_ID = "testrp.example"
USER = "carol"


def b64(data: bytes) -> str:
    return b64url_encode(data)


class HttpTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cfg = config_mod.Config(
            rp_id=RP_ID,
            origin=ORIGIN,
            rp_name="HTTP Test",
            db_path=os.path.join(cls.tmp.name, "http.db"),
            host="127.0.0.1",
            port=0,
        )
        cls.httpd, cls.app = make_server(cfg)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.app.seed_user(USER, "Carol")
        cls.app.seed_user("carol-flow", "Carol Flow")
        cls.app.seed_user("carol-sig", "Carol Sig")
        cls.app.seed_user("carol-origin", "Carol Origin")

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.app.close()
        cls.tmp.cleanup()

    def request(self, path: str, payload: dict | None = None, method: str = "POST"):
        url = self.base + path
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_health_reports_fixed_values(self):
        status, body = self.request("/health", method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(body["rp_id"], RP_ID)
        self.assertEqual(body["origin"], ORIGIN)

    def test_full_register_and_authenticate_flow(self):
        user = "carol-flow"
        auth = Authenticator(RP_ID)

        status, body = self.request("/register/begin", {"user_id": user})
        self.assertEqual(status, 200)
        self.assertEqual(body["rp"]["id"], RP_ID)
        challenge = b64url_decode(body["challenge"])

        reg = auth.register_response(challenge, ORIGIN)
        status, body = self.request("/register/finish", {
            "user_id": user,
            "clientDataJSON": b64(reg["clientDataJSON"]),
            "attestationObject": b64(reg["attestationObject"]),
        })
        self.assertEqual(status, 200)
        self.assertTrue(body["verified"])

        status, body = self.request("/authenticate/begin", {"user_id": user})
        self.assertEqual(status, 200)
        challenge2 = b64url_decode(body["challenge"])
        self.assertEqual(len(body["allowCredentials"]), 1)

        auth.sign_count = 1
        assertion = auth.authenticate_response(challenge2, ORIGIN, sign_count=1)
        status, body = self.request("/authenticate/finish", {
            "user_id": user,
            "credential_id": b64(assertion["credential_id"]),
            "clientDataJSON": b64(assertion["clientDataJSON"]),
            "authenticatorData": b64(assertion["authenticatorData"]),
            "signature": b64(assertion["signature"]),
        })
        self.assertEqual(status, 200)
        self.assertTrue(body["verified"])
        self.assertEqual(body["sign_count"], 1)

        # 重放同一认证挑战：必须被拒绝。
        status, body = self.request("/authenticate/finish", {
            "user_id": user,
            "credential_id": b64(assertion["credential_id"]),
            "clientDataJSON": b64(assertion["clientDataJSON"]),
            "authenticatorData": b64(assertion["authenticatorData"]),
            "signature": b64(assertion["signature"]),
        })
        self.assertEqual(status, 400)
        self.assertIn("已被消费", body["error"])

    def test_request_cannot_override_origin_or_rpid(self):
        """即使请求里带上 origin/rp_id/rpId 字段，服务端也必须忽略。"""
        user = "carol-origin"
        auth = Authenticator(RP_ID)
        _, body = self.request("/register/begin", {"user_id": user})
        challenge = b64url_decode(body["challenge"])

        # 想借请求把 origin 改成攻击者站点：响应 JSON 内 origin 必须是固定值。
        reg = auth.register_response(challenge, "http://evil.example")
        status, body = self.request("/register/finish", {
            "user_id": user,
            "clientDataJSON": b64(reg["clientDataJSON"]),
            "attestationObject": b64(reg["attestationObject"]),
            "origin": "http://evil.example",   # 必须被忽略
            "rp_id": "evil.example",
        })
        self.assertEqual(status, 400)
        self.assertIn("origin", body["error"])

    def test_unknown_user_rejected(self):
        status, body = self.request("/register/begin", {"user_id": "nobody"})
        self.assertEqual(status, 400)

    def test_bad_signature_keeps_challenge_usable(self):
        user = "carol-sig"
        auth = Authenticator(RP_ID)
        _, body = self.request("/register/begin", {"user_id": user})
        ch = b64url_decode(body["challenge"])
        reg = auth.register_response(ch, ORIGIN)
        # 先完成注册
        self.assertEqual(200, self.request("/register/finish", {
            "user_id": user,
            "clientDataJSON": b64(reg["clientDataJSON"]),
            "attestationObject": b64(reg["attestationObject"]),
        })[0])

        _, body = self.request("/authenticate/begin", {"user_id": user})
        ch2 = b64url_decode(body["challenge"])
        stranger = Authenticator(RP_ID)
        bad = auth.authenticate_response(ch2, ORIGIN, sign_count=1, sign_with=stranger)
        status, body = self.request("/authenticate/finish", {
            "user_id": user,
            "credential_id": b64(bad["credential_id"]),
            "clientDataJSON": b64(bad["clientDataJSON"]),
            "authenticatorData": b64(bad["authenticatorData"]),
            "signature": b64(bad["signature"]),
        })
        self.assertEqual(status, 400)
        self.assertIn("签名", body["error"])

        # 同一挑战仍可成功使用。
        good = auth.authenticate_response(ch2, ORIGIN, sign_count=1)
        status, _ = self.request("/authenticate/finish", {
            "user_id": user,
            "credential_id": b64(good["credential_id"]),
            "clientDataJSON": b64(good["clientDataJSON"]),
            "authenticatorData": b64(good["authenticatorData"]),
            "signature": b64(good["signature"]),
        })
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
