"""Flask HTTP 层。

用户身份不做账户系统，完全由测试夹具请求头 ``X-Test-User`` 提供；
用户必须已由 seed 脚本写入 users 表。origin 与 RP ID 来自服务端配置，
请求中的任何相关字段（rpId/origin 等）都不会被读取。
"""

from __future__ import annotations

import sys

from flask import Flask, jsonify, request

from .config import Config
from .db import Database
from .errors import WebAuthnError
from .service import WebAuthnService

TEST_USER_HEADER = "X-Test-User"


def create_app(config: Config | None = None, db: Database | None = None) -> Flask:
    app = Flask(__name__)
    config = config or Config.from_env()
    db = db or Database(config.db_path)
    svc = WebAuthnService(db, config)

    app.config["LIMITED_CONFIG"] = config

    def _require_user() -> str:
        from .errors import Unauthorized

        user_id = request.headers.get(TEST_USER_HEADER, "").strip()
        if not user_id or len(user_id) > 256:
            raise Unauthorized(f"缺少或非法的 {TEST_USER_HEADER} 请求头")
        return user_id

    @app.errorhandler(WebAuthnError)
    def _handle_webauthn_error(err: WebAuthnError):
        return jsonify({"error": err.__class__.__name__, "message": err.message}), err.status

    @app.errorhandler(404)
    def _handle_404(_err):
        return jsonify({"error": "NotFound", "message": "未知路径"}), 404

    @app.post("/register/begin")
    def register_begin():
        user_id = _require_user()
        return jsonify(svc.begin_registration(user_id))

    @app.post("/register/finish")
    def register_finish():
        user_id = _require_user()
        return jsonify(svc.finish_registration(user_id, request.get_json(silent=True)))

    @app.post("/login/begin")
    def login_begin():
        user_id = _require_user()
        return jsonify(svc.begin_authentication(user_id))

    @app.post("/login/finish")
    def login_finish():
        user_id = _require_user()
        return jsonify(svc.finish_authentication(user_id, request.get_json(silent=True)))

    return app


def seed_users(db: Database, users: list[tuple[str, str]]) -> None:
    for user_id, display_name in users:
        db.upsert_user(user_id, display_name)


def main(argv: list[str] | None = None) -> int:
    """简单入口：

    * ``python -m webauthn_limited.app seed alice Alice bob Bob`` 写入夹具用户；
    * ``python -m webauthn_limited.app serve`` 启动开发服务器。
    """
    argv = argv if argv is not None else sys.argv[1:]
    config = Config.from_env()
    db = Database(config.db_path)

    if not argv or argv[0] == "seed":
        args = argv[1:]
        if not args:
            args = ["alice", "Alice", "bob", "Bob", "carol", "Carol"]
        if len(args) % 2 != 0:
            print("seed 参数必须为成对的 user_id display_name", file=sys.stderr)
            return 2
        seed_users(db, list(zip(args[0::2], args[1::2])))
        print(f"已写入用户: {args[0::2]}")
        return 0

    if argv[0] == "serve":
        app = create_app(config, db)
        app.run(host="127.0.0.1", port=int(__import__("os").environ.get("PORT", "8080")))
        return 0

    print(f"未知子命令: {argv[0]}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
