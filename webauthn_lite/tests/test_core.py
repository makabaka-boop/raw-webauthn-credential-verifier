"""直接针对验证核心与 SQLite 并发语义的测试（真实椭圆曲线密钥）。

运行：python3 -m unittest webauthn_lite.tests.test_core -v
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest

from webauthn_lite import config as config_mod
from webauthn_lite import cbor, crypto, store, webauthn
from webauthn_lite.webauthn import (
    FLAG_UP,
    FLAG_UV,
    FLAG_AT,
    FLAG_BE,
    FLAG_ED,
)

from .fake_authenticator import Authenticator

USER_A = "user-alice"
USER_B = "user-bob"


def make_cfg(db_path: str) -> config_mod.Config:
    return config_mod.Config(
        rp_id="localhost",
        origin="http://localhost:8080",
        rp_name="Test RP",
        db_path=db_path,
        host="127.0.0.1",
        port=0,
    )


class CoreTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "test.db")
        self.cfg = make_cfg(self.db)
        self.conn = store.connect(self.db)
        store.init_db(self.conn)
        store.seed_user(self.conn, USER_A, "Alice")
        store.seed_user(self.conn, USER_B, "Bob")
        self.auth = Authenticator("localhost")

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    # ----- 注册 helper -----
    def begin_reg(self, user=USER_A):
        return store.begin_registration(self.conn, user)

    def finish_reg(self, challenge, *, auth=None, user=USER_A, origin=None, **kwargs):
        auth = auth or self.auth
        resp = auth.register_response(
            challenge, origin or self.cfg.origin, **kwargs
        )
        return webauthn.verify_registration(
            self.conn,
            self.cfg,
            user_id=user,
            client_data_json=resp["clientDataJSON"],
            attestation_object=resp["attestationObject"],
        ), resp

    # ---------- 注册基本路径 ----------
    def test_register_packed_self_ok(self):
        ch = self.begin_reg()
        result, _ = self.finish_reg(ch)
        self.assertEqual(result.credential_id, self.auth.credential_id)
        self.assertEqual(result.sign_count, 0)
        # 挑战已消费，不能再次使用。
        with self.assertRaises(store.ChallengeAlreadyConsumed):
            self.finish_reg(ch)

    def test_register_none_ok(self):
        ch = self.begin_reg()
        result, _ = self.finish_reg(ch, fmt="none")
        self.assertEqual(result.sign_count, 0)

    def test_register_packed_with_positive_initial_count(self):
        ch = self.begin_reg()
        self.auth.sign_count = 5
        result, _ = self.finish_reg(ch)
        self.assertEqual(result.sign_count, 5)

    def test_none_attestation_with_nonempty_stmt_rejected(self):
        ch = self.begin_reg()
        with self.assertRaises(webauthn.WebAuthnError):
            self.finish_reg(ch, fmt="none", att_stmt_overrides={"sig": b"x"})

    # ---------- 原始 clientDataJSON 字节 ----------
    def test_json_byte_differences_whitespace_and_key_order_accepted(self):
        """非规范空白/键序只要签名覆盖相同原字节，就必须通过。

        服务端绝不重新序列化 JSON 后再验签。
        """
        # 每次注册使用新生成的密钥（credential ID 唯一约束），但验证重点
        # 是：同一套载荷用非规范 JSON 字节也能通过，证明没有重序列化。
        for kw in ({"extra_whitespace": True}, {"reordered": True}):
            auth = Authenticator("localhost")
            ch = self.begin_reg()
            cdj = Authenticator.client_data_json(
                "webauthn.create", ch, self.cfg.origin, **kw
            )
            result, _ = self.finish_reg(ch, auth=auth, client_data_json=cdj)
            self.assertEqual(result.credential_id, auth.credential_id)

    def test_tampered_json_bytes_after_signing_rejected(self):
        # 签名覆盖原始 JSON；服务端若对同字节验签，单字节篡改必然失败。
        ch = self.begin_reg()
        resp = self.auth.register_response(ch, self.cfg.origin, fmt="packed")
        tampered = resp["clientDataJSON"].replace(b"webauthn.create", b"webauthn.create", 1)
        self.assertEqual(tampered, resp["clientDataJSON"])  # 基线
        bad = resp["clientDataJSON"] + b" "
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_registration(
                self.conn, self.cfg,
                user_id=USER_A,
                client_data_json=bad,  # 尾部空格 -> JSON 相同但签名不匹配
                attestation_object=resp["attestationObject"],
            )
        # 签名失败不消费挑战：用原字节立刻重试应成功。
        result = webauthn.verify_registration(
            self.conn, self.cfg,
            user_id=USER_A,
            client_data_json=resp["clientDataJSON"],
            attestation_object=resp["attestationObject"],
        )
        self.assertEqual(result.credential_id, self.auth.credential_id)

    def test_reserialized_json_verifies_when_bytes_differ_but_signature_is_over_reserialized(self):
        """明确锁死语义：验证只认收到的字节。

        用紧凑 JSON 计算签名，但服务端重新格式化成带空格 JSON 提交，
        签名必须失败（防止“重新序列化 JSON 后验签”的实现）。
        """
        ch = self.begin_reg()
        compact = Authenticator.client_data_json("webauthn.create", ch, self.cfg.origin)
        pretty = json.dumps(json.loads(compact), indent=2).encode()
        self.assertNotEqual(compact, pretty)
        # 对 pretty 字节构造签名 → 提交 compact，必须失败；反之亦然。
        resp = self.auth.register_response(ch, self.cfg.origin, client_data_json=pretty)
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_registration(
                self.conn, self.cfg,
                user_id=USER_A,
                client_data_json=compact,
                attestation_object=resp["attestationObject"],
            )

    # ---------- 挑战、origin、RP ID ----------
    def test_wrong_challenge_rejected(self):
        ch = self.begin_reg()
        other = os.urandom(32)
        resp = self.auth.register_response(other, self.cfg.origin)
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_registration(
                self.conn, self.cfg, user_id=USER_A,
                client_data_json=resp["clientDataJSON"],
                attestation_object=resp["attestationObject"],
            )

    def test_wrong_purpose_rejected(self):
        """注册载荷不能消费认证挑战，反之亦然。"""
        authn_ch = store.begin_authentication(self.conn, USER_A)
        resp = self.auth.register_response(authn_ch, self.cfg.origin)
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_registration(
                self.conn, self.cfg, user_id=USER_A,
                client_data_json=resp["clientDataJSON"],
                attestation_object=resp["attestationObject"],
            )
        # 认证挑战仍然可用（未被误消费）。
        self.assertIsNotNone(
            store.get_pending_challenge(self.conn, authn_ch, store.PURPOSE_AUTHENTICATION)
        )

    def test_exact_origin_check(self):
        ch = self.begin_reg()
        # 尾斜杠 / 大小写 / 来源前缀都必须被精确比较拒绝。
        for bad_origin in (
            "http://localhost:8080/",
            "http://LOCALHOST:8080",
            "http://localhost:8080.evil.example",
            "https://localhost:8080",
        ):
            resp = self.auth.register_response(ch, bad_origin)
            with self.assertRaises(webauthn.WebAuthnError):
                webauthn.verify_registration(
                    self.conn, self.cfg, user_id=USER_A,
                    client_data_json=resp["clientDataJSON"],
                    attestation_object=resp["attestationObject"],
                )

    def test_rp_id_hash_mismatch_rejected(self):
        evil = Authenticator("evil.example")
        ch = self.begin_reg()
        resp = evil.register_response(ch, self.cfg.origin)
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_registration(
                self.conn, self.cfg, user_id=USER_A,
                client_data_json=resp["clientDataJSON"],
                attestation_object=resp["attestationObject"],
            )

    def test_challenge_owner_mismatch_rejected(self):
        ch = self.begin_reg(USER_A)
        with self.assertRaises(webauthn.WebAuthnError):
            self.finish_reg(ch, user=USER_B)

    # ---------- 标志与扩展 ----------
    def test_flags_up_uv_required_be_ed_rejected(self):
        ch = self.begin_reg()
        base = FLAG_AT
        for bad_flags in (
            base | FLAG_UV | FLAG_AT,                 # 缺 UP
            base | FLAG_UP | FLAG_AT,                 # 缺 UV
            base | FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BE,  # 可备份
            base | FLAG_UP | FLAG_UV | FLAG_AT | FLAG_ED,  # 扩展
        ):
            # 去掉重复 AT 位
            ad = self.auth.make_attestation_auth_data(flags_override=bad_flags)
            with self.assertRaises(webauthn.WebAuthnError):
                self.finish_reg(ch, auth_data=ad)

    # ---------- 截断 / COSE ----------
    def test_truncated_credential_id_rejected(self):
        ch = self.begin_reg()
        ad = self.auth.make_attestation_auth_data()
        # authData: 37 固定头 + 16 aaguid + 2 长度 + 32 id + cose
        # 声明完整长度但把凭据 ID 截掉一半。
        head = ad[: 37 + 16]
        truncated = head + (16).to_bytes(2, "big") + self.auth.credential_id[:8]
        # 长度声称 16 但实际给 8，COSE 部分错位/缺失
        resp = self.auth.register_response(ch, self.cfg.origin, auth_data=truncated)
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_registration(
                self.conn, self.cfg, user_id=USER_A,
                client_data_json=resp["clientDataJSON"],
                attestation_object=resp["attestationObject"],
            )

    def test_short_credential_id_length_declared_rejected(self):
        ch = self.begin_reg()
        ad = (
            self.auth._auth_data_base(FLAG_UP | FLAG_UV | FLAG_AT)
            + b"\x00" * 16
            + (4).to_bytes(2, "big")  # 小于 16 字节下限
            + self.auth.credential_id[:4]
            + self.auth.cose_public_key()
        )
        with self.assertRaises(webauthn.WebAuthnError):
            self.finish_reg(ch, auth_data=ad)

    def test_non_es256_cose_rejected(self):
        ch = self.begin_reg()
        x, y = self.auth.private.public.xy_bytes()
        bad_keys = [
            {1: 2, 3: -35, -1: 1, -2: x, -3: y},        # alg ES384
            {1: 1, 3: -7, -1: 1, -2: x, -3: y},         # kty OKP/RSA-ish
            {1: 2, 3: -7, -1: 2, -2: x, -3: y},         # crv P-384
            {1: 2, 3: -7, -1: 1, -2: x[:16], -3: y},    # x 截断
            {1: 2, 3: -7, -1: 1, -2: x, -3: y, 2: b""}, # 未知 COSE 字段
        ]
        for bad in bad_keys:
            ad = (
                self.auth._auth_data_base(FLAG_UP | FLAG_UV | FLAG_AT)
                + b"\x00" * 16
                + len(self.auth.credential_id).to_bytes(2, "big")
                + self.auth.credential_id
                + cbor.dumps(bad)
            )
            with self.assertRaises(webauthn.WebAuthnError):
                self.finish_reg(ch, auth_data=ad)

    def test_invalid_point_rejected(self):
        # x=1, y=1 不在 P-256 曲线上。
        bad_key = {1: 2, 3: -7, -1: 1, -2: (1).to_bytes(32, "big"), -3: (1).to_bytes(32, "big")}
        ad = (
            self.auth._auth_data_base(FLAG_UP | FLAG_UV | FLAG_AT)
            + b"\x00" * 16
            + len(self.auth.credential_id).to_bytes(2, "big")
            + self.auth.credential_id
            + cbor.dumps(bad_key)
        )
        ch = self.begin_reg()
        with self.assertRaises(webauthn.WebAuthnError):
            self.finish_reg(ch, auth_data=ad)

    def test_packed_x5c_certificate_chain_rejected(self):
        ch = self.begin_reg()
        dummy_der = b"\x30\x03\x02\x01\x01"
        with self.assertRaises(webauthn.WebAuthnError):
            self.finish_reg(ch, att_stmt_overrides={"x5c": [dummy_der]})

    def test_unknown_fmt_rejected(self):
        ch = self.begin_reg()
        cdj = Authenticator.client_data_json("webauthn.create", ch, self.cfg.origin)
        ad = self.auth.make_attestation_auth_data()
        att_obj = cbor.dumps({"fmt": "android-key", "attStmt": {}, "authData": ad})
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_registration(
                self.conn, self.cfg, user_id=USER_A,
                client_data_json=cdj,
                attestation_object=att_obj,
            )

    # ---------- 认证基本路径 ----------
    def register_one(self, initial_count=0, auth=None, user=USER_A):
        auth = auth or self.auth
        auth.sign_count = initial_count
        ch = store.begin_registration(self.conn, user)
        resp = auth.register_response(ch, self.cfg.origin)
        result = webauthn.verify_registration(
            self.conn, self.cfg, user_id=user,
            client_data_json=resp["clientDataJSON"],
            attestation_object=resp["attestationObject"],
        )
        return result

    def authn_finish(self, ch, *, auth=None, user=USER_A, sign_count=None, **kw):
        auth = auth or self.auth
        resp = auth.authenticate_response(ch, self.cfg.origin, sign_count=sign_count, **kw)
        used_count = resp.pop("sign_count_used")
        result = webauthn.verify_authentication(
            self.conn, self.cfg, user_id=user,
            credential_id=resp["credential_id"],
            client_data_json=resp["clientDataJSON"],
            authenticator_data=resp["authenticatorData"],
            signature=resp["signature"],
        )
        return result, used_count, resp

    def test_authenticate_ok_and_challenge_consumed(self):
        self.register_one()
        ch = store.begin_authentication(self.conn, USER_A)
        result, used, _ = self.authn_finish(ch, sign_count=1)
        self.assertEqual(result.sign_count, 1)
        # 同一挑战不可二次提交。
        with self.assertRaises(store.ChallengeAlreadyConsumed):
            self.authn_finish(ch, sign_count=2)

    def test_zero_count_credential_returns_zero_repeatedly(self):
        self.register_one(initial_count=0)
        for _ in range(3):
            ch = store.begin_authentication(self.conn, USER_A)
            result, _, _ = self.authn_finish(ch, sign_count=0)
            self.assertEqual(result.sign_count, 0)

    def test_zero_can_upgrade_then_must_increase(self):
        self.register_one()
        ch = store.begin_authentication(self.conn, USER_A)
        self.authn_finish(ch, sign_count=10)
        ch = store.begin_authentication(self.conn, USER_A)
        with self.assertRaises(store.CounterRejected):
            self.authn_finish(ch, sign_count=10)   # 相等不行
        ch = store.begin_authentication(self.conn, USER_A)
        with self.assertRaises(store.CounterRejected):
            self.authn_finish(ch, sign_count=3)    # 倒退不行
        ch = store.begin_authentication(self.conn, USER_A)
        result, _, _ = self.authn_finish(ch, sign_count=11)
        self.assertEqual(result.sign_count, 11)

    def test_credential_must_belong_to_user(self):
        self.register_one()
        ch = store.begin_authentication(self.conn, USER_B)  # Bob 用 Alice 的凭据
        with self.assertRaises(webauthn.WebAuthnError):
            self.authn_finish(ch, user=USER_B)

    def test_unknown_credential_id_rejected(self):
        ch = store.begin_authentication(self.conn, USER_A)
        resp = self.auth.authenticate_response(ch, self.cfg.origin)
        resp["credential_id"] = os.urandom(32)
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_authentication(
                self.conn, self.cfg, user_id=USER_A,
                credential_id=resp["credential_id"],
                client_data_json=resp["clientDataJSON"],
                authenticator_data=resp["authenticatorData"],
                signature=resp["signature"],
            )

    def test_bad_signature_does_not_consume_challenge(self):
        self.register_one()
        ch = store.begin_authentication(self.conn, USER_A)
        # 用另一把密钥签同一个拼接数据。
        stranger = Authenticator("localhost")
        with self.assertRaises(webauthn.WebAuthnError):
            self.authn_finish(ch, sign_count=1, sign_with=stranger)
        # 挑战还在；用真凭据重放成功。
        self.assertIsNotNone(
            store.get_pending_challenge(self.conn, ch, store.PURPOSE_AUTHENTICATION)
        )
        result, _, _ = self.authn_finish(ch, sign_count=1)
        self.assertEqual(result.sign_count, 1)

    def test_signature_over_reserialized_json_rejected(self):
        self.register_one()
        ch = store.begin_authentication(self.conn, USER_A)
        compact = Authenticator.client_data_json("webauthn.get", ch, self.cfg.origin)
        pretty = json.dumps(json.loads(compact), indent=2).encode()
        # 签名针对 pretty，提交 compact -> 必须失败。
        resp = self.auth.authenticate_response(
            ch, self.cfg.origin, client_data_json=pretty, sign_count=1
        )
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_authentication(
                self.conn, self.cfg, user_id=USER_A,
                credential_id=self.auth.credential_id,
                client_data_json=compact,
                authenticator_data=resp["authenticatorData"],
                signature=resp["signature"],
            )

    def test_truncated_signature_rejected(self):
        self.register_one()
        ch = store.begin_authentication(self.conn, USER_A)
        resp = self.auth.authenticate_response(ch, self.cfg.origin, sign_count=1)
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_authentication(
                self.conn, self.cfg, user_id=USER_A,
                credential_id=resp["credential_id"],
                client_data_json=resp["clientDataJSON"],
                authenticator_data=resp["authenticatorData"],
                signature=resp["signature"][:-1],
            )
        # 挑战未消耗，完整签名可成功。
        result = webauthn.verify_authentication(
            self.conn, self.cfg, user_id=USER_A,
            credential_id=resp["credential_id"],
            client_data_json=resp["clientDataJSON"],
            authenticator_data=resp["authenticatorData"],
            signature=resp["signature"],
        )
        self.assertEqual(result.sign_count, 1)

    def test_authn_wrong_purpose_rejected(self):
        self.register_one()
        reg_ch = store.begin_registration(self.conn, USER_A)
        resp = self.auth.authenticate_response(reg_ch, self.cfg.origin, sign_count=1)
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_authentication(
                self.conn, self.cfg, user_id=USER_A,
                credential_id=resp["credential_id"],
                client_data_json=resp["clientDataJSON"],
                authenticator_data=resp["authenticatorData"],
                signature=resp["signature"],
            )

    def test_authn_flags_check(self):
        self.register_one()
        ch = store.begin_authentication(self.conn, USER_A)
        for bad_flags in (FLAG_UV, FLAG_UP, FLAG_UP | FLAG_UV | FLAG_BE, FLAG_UP | FLAG_UV | FLAG_ED):
            ad = self.auth.make_assertion_auth_data(flags_override=bad_flags)
            with self.assertRaises(webauthn.WebAuthnError):
                self.authn_finish(ch, sign_count=1, auth_data=ad)

    # ---------- 并发：同一挑战至多一次成功 ----------
    def test_concurrent_same_registration_challenge_only_one_commits(self):
        ch = store.begin_registration(self.conn, USER_A)

        conn1 = store.connect(self.db)
        conn2 = store.connect(self.db)
        self.addCleanup(conn1.close)
        self.addCleanup(conn2.close)
        results: list[str] = []
        barrier = threading.Barrier(2)

        def attempt(ok_conn, tag):
            barrier.wait()
            resp = self.auth.register_response(ch, self.cfg.origin)
            try:
                webauthn.verify_registration(
                    ok_conn, self.cfg, user_id=USER_A,
                    client_data_json=resp["clientDataJSON"],
                    attestation_object=resp["attestationObject"],
                )
                results.append(f"{tag}:ok")
            except Exception:
                results.append(f"{tag}:fail")

        t1 = threading.Thread(target=attempt, args=(conn1, "t1"))
        t2 = threading.Thread(target=attempt, args=(conn2, "t2"))
        t1.start(); t2.start(); t1.join(); t2.join()

        self.assertEqual(sum(1 for r in results if r.endswith(":ok")), 1)
        rows = self.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        self.assertEqual(rows, 1)

    def test_concurrent_same_authentication_challenge_only_one_commits(self):
        self.register_one()  # 保持零计数，避免计数干扰本用例
        ch = store.begin_authentication(self.conn, USER_A)
        conn1 = store.connect(self.db)
        conn2 = store.connect(self.db)
        self.addCleanup(conn1.close)
        self.addCleanup(conn2.close)
        results: list[Exception | str] = []
        barrier = threading.Barrier(2)

        def attempt(ok_conn, tag):
            barrier.wait()
            resp = self.auth.authenticate_response(ch, self.cfg.origin, sign_count=0)
            try:
                webauthn.verify_authentication(
                    ok_conn, self.cfg, user_id=USER_A,
                    credential_id=resp["credential_id"],
                    client_data_json=resp["clientDataJSON"],
                    authenticator_data=resp["authenticatorData"],
                    signature=resp["signature"],
                )
                results.append("ok")
            except Exception as exc:
                results.append(exc)

        t1 = threading.Thread(target=attempt, args=(conn1, "t1"))
        t2 = threading.Thread(target=attempt, args=(conn2, "t2"))
        t1.start(); t2.start(); t1.join(); t2.join()

        self.assertEqual(sum(1 for r in results if r == "ok"), 1)
        self.assertTrue(any(isinstance(r, store.ChallengeAlreadyConsumed) for r in results))

    # ---------- 两次计数提交交错 ----------
    def test_interleaved_counter_commits(self):
        """两个不同的认证挑战交错提交不同计数，串行化结果必须合法。

        合法序列要求“已记录正数后只接受更大值”，最终计数为两者最大值，
        低计数的晚提交必须失败。
        """
        self.register_one()
        ch_low = store.begin_authentication(self.conn, USER_A)   # 带计数 100
        ch_high = store.begin_authentication(self.conn, USER_A)  # 带计数 101
        resp_low = self.auth.authenticate_response(ch_low, self.cfg.origin, sign_count=100)
        resp_high = self.auth.authenticate_response(ch_high, self.cfg.origin, sign_count=101)

        def finish(resp):
            return webauthn.verify_authentication(
                self.conn, self.cfg, user_id=USER_A,
                credential_id=resp["credential_id"],
                client_data_json=resp["clientDataJSON"],
                authenticator_data=resp["authenticatorData"],
                signature=resp["signature"],
            )

        # 故意交错：先把高计数提交，再尝试低计数。
        r_high = finish(resp_high)
        self.assertEqual(r_high.sign_count, 101)
        with self.assertRaises(store.CounterRejected):
            finish(resp_low)
        final = self.conn.execute(
            "SELECT sign_count FROM credentials WHERE credential_id=?",
            (self.auth.credential_id,),
        ).fetchone()[0]
        self.assertEqual(final, 101)

    def test_interleaved_counter_commits_other_order_both_ok(self):
        """同样的两笔，低->高顺序提交则都成功，证明失败完全来自交错顺序。"""
        self.register_one()
        ch_low = store.begin_authentication(self.conn, USER_A)
        ch_high = store.begin_authentication(self.conn, USER_A)
        resp_low = self.auth.authenticate_response(ch_low, self.cfg.origin, sign_count=100)
        resp_high = self.auth.authenticate_response(ch_high, self.cfg.origin, sign_count=101)

        def finish(resp):
            return webauthn.verify_authentication(
                self.conn, self.cfg, user_id=USER_A,
                credential_id=resp["credential_id"],
                client_data_json=resp["clientDataJSON"],
                authenticator_data=resp["authenticatorData"],
                signature=resp["signature"],
            )

        self.assertEqual(finish(resp_low).sign_count, 100)
        self.assertEqual(finish(resp_high).sign_count, 101)

    def test_concurrent_interleaved_counter_race(self):
        """线程级交错：两个挑战分别带 50/51 同时提交，结果必须串行化安全。"""
        self.register_one()
        c1 = store.begin_authentication(self.conn, USER_A)
        c2 = store.begin_authentication(self.conn, USER_A)
        r1 = self.auth.authenticate_response(c1, self.cfg.origin, sign_count=50)
        r2 = self.auth.authenticate_response(c2, self.cfg.origin, sign_count=51)
        conn1 = store.connect(self.db)
        conn2 = store.connect(self.db)
        self.addCleanup(conn1.close)
        self.addCleanup(conn2.close)
        outcomes = []
        barrier = threading.Barrier(2)

        def finish(ok_conn, resp, tag):
            barrier.wait()
            try:
                webauthn.verify_authentication(
                    ok_conn, self.cfg, user_id=USER_A,
                    credential_id=resp["credential_id"],
                    client_data_json=resp["clientDataJSON"],
                    authenticator_data=resp["authenticatorData"],
                    signature=resp["signature"],
                )
                outcomes.append((tag, "ok"))
            except store.CounterRejected:
                outcomes.append((tag, "counter"))
            except Exception as exc:
                outcomes.append((tag, f"other:{type(exc).__name__}"))

        t1 = threading.Thread(target=finish, args=(conn1, r1, "50"))
        t2 = threading.Thread(target=finish, args=(conn2, r2, "51"))
        t1.start(); t2.start(); t1.join(); t2.join()

        # 用新连接读最终状态，避免读到旧事务快照。
        with store.connect(self.db) as fresh:
            final = fresh.execute(
                "SELECT sign_count FROM credentials WHERE credential_id=?",
                (self.auth.credential_id,),
            ).fetchone()[0]
        self.assertEqual(final, 51)
        ok = {tag for tag, state in outcomes if state == "ok"}
        # 高计数必成功；低计数只有在高计数先落地时才会被拒。
        self.assertIn("51", ok)
        self.assertNotIn(("50", "other:ChallengeAlreadyConsumed"), outcomes)


if __name__ == "__main__":
    unittest.main()
