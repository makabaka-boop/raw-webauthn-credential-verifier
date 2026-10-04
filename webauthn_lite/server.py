"""仅依赖标准库的 HTTP 服务。

接口（均为 POST JSON，二进制字段为无填充 base64url）：

  POST /register/begin       {"user_id": "..."}
  POST /register/finish      {"user_id", "clientDataJSON", "attestationObject"}
  POST /authenticate/begin   {"user_id": "..."}
  POST /authenticate/finish  {"user_id", "credential_id",
                              "clientDataJSON", "authenticatorData", "signature"}
  GET  /health

用户身份只能引用已由测试夹具写入 users 表的记录，没有注册账户接口，
origin / RP ID 也不出现在请求里。
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import config as config_mod
from . import store, webauthn

MAX_BODY = 1 << 20  # 1 MiB，足够测试夹具使用


def _b64_field(obj: dict, name: str) -> bytes:
    value = obj.get(name)
    if not isinstance(value, str):
        raise webauthn.WebAuthnError(f"{name} 必须是 base64url 字符串")
    return webauthn.b64url_decode(value)


class WebAuthnApp:
    def __init__(self, cfg: config_mod.Config):
        self.cfg = cfg
        self._local = threading.local()
        # 初始化建表只在构造时做一次。
        init_conn = store.connect(cfg.db_path)
        try:
            store.init_db(init_conn)
        finally:
            init_conn.close()

    @property
    def conn(self):
        # 每个 HTTP 工作线程持有自己的 SQLite 连接，避免事务状态跨请求交错。
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = store.connect(self.cfg.db_path)
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def seed_user(self, user_id: str, display_name: str) -> None:
        store.seed_user(self.conn, user_id, display_name)

    def handle(self, method: str, path: str, body: bytes) -> tuple[int, dict]:
        parsed = urlparse(path)
        route = parsed.path
        if method == "GET" and route == "/health":
            return 200, {"ok": True, "rp_id": self.cfg.rp_id, "origin": self.cfg.origin}
        if method != "POST":
            return 405, {"error": "method not allowed"}

        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
            if not isinstance(payload, dict):
                raise webauthn.WebAuthnError("请求体必须是 JSON 对象")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return 400, {"error": f"请求体不是合法 JSON: {exc}"}

        try:
            if route == "/register/begin":
                user_id = payload.get("user_id")
                if not isinstance(user_id, str) or not user_id:
                    raise webauthn.WebAuthnError("user_id 缺失")
                challenge = store.begin_registration(self.conn, user_id)
                return 200, {
                    "challenge": webauthn.b64url_encode(challenge),
                    "rp": {"id": self.cfg.rp_id, "name": self.cfg.rp_name},
                    "user": {"id": webauthn.b64url_encode(user_id.encode()), "name": user_id},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                    "timeout": 60000,
                    "authenticatorSelection": {
                        "residentKey": "discouraged",
                        "userVerification": "required",
                    },
                    # 明确告知：只允许 none 或 packed(self)。
                    "attestation": "indirect",
                }
            if route == "/register/finish":
                user_id = payload.get("user_id")
                result = webauthn.verify_registration(
                    self.conn,
                    self.cfg,
                    user_id=user_id,
                    client_data_json=_b64_field(payload, "clientDataJSON"),
                    attestation_object=_b64_field(payload, "attestationObject"),
                )
                return 200, {
                    "verified": True,
                    "credential_id": webauthn.b64url_encode(result.credential_id),
                    "sign_count": result.sign_count,
                }
            if route == "/authenticate/begin":
                user_id = payload.get("user_id")
                if not isinstance(user_id, str) or not user_id:
                    raise webauthn.WebAuthnError("user_id 缺失")
                challenge = store.begin_authentication(self.conn, user_id)
                return 200, {
                    "challenge": webauthn.b64url_encode(challenge),
                    "rpId": self.cfg.rp_id,
                    "userVerification": "required",
                    "timeout": 60000,
                    "allowCredentials": [
                        {
                            "id": webauthn.b64url_encode(row[0]),
                            "type": "public-key",
                            "transports": ["internal"],
                        }
                        for row in self.conn.execute(
                            "SELECT credential_id FROM credentials WHERE user_id=? "
                            "ORDER BY id",
                            (user_id,),
                        ).fetchall()
                    ],
                }
            if route == "/authenticate/finish":
                user_id = payload.get("user_id")
                result = webauthn.verify_authentication(
                    self.conn,
                    self.cfg,
                    user_id=user_id,
                    credential_id=_b64_field(payload, "credential_id"),
                    client_data_json=_b64_field(payload, "clientDataJSON"),
                    authenticator_data=_b64_field(payload, "authenticatorData"),
                    signature=_b64_field(payload, "signature"),
                )
                return 200, {"verified": True, "sign_count": result.sign_count}
            return 404, {"error": "not found"}
        except (store.StoreError, webauthn.WebAuthnError) as exc:
            return 400, {"error": str(exc)}
        except Exception as exc:  # 协议外错误也不得让连接崩溃
            return 500, {"error": f"服务器内部错误: {exc}"}


def make_server(cfg: config_mod.Config) -> tuple[ThreadingHTTPServer, WebAuthnApp]:
    app = WebAuthnApp(cfg)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # 测试环境保持安静
            pass

        def _reply(self, status: int, obj: dict) -> None:
            data = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            status, obj = app.handle("GET", self.path, b"")
            self._reply(status, obj)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_BODY:
                self._reply(413, {"error": "请求体过大"})
                return
            body = self.rfile.read(length) if length else b""
            status, obj = app.handle("POST", self.path, body)
            self._reply(status, obj)

    httpd = ThreadingHTTPServer((cfg.host, cfg.port), Handler)
    return httpd, app


def main() -> None:
    cfg = config_mod.load()
    httpd, _app = make_server(cfg)
    print(f"WebAuthn Lite listening on http://{cfg.host}:{cfg.port}")
    print(f"fixed rp_id={cfg.rp_id!r} origin={cfg.origin!r}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
