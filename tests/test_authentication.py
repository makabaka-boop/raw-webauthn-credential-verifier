"""认证（assertion）相关测试：归属、签名拼接、计数规则、并发交错。"""

from __future__ import annotations

import threading

from webauthn_limited.encoding import b64url_encode
from conftest import ALICE, BOB, TestAuthenticator


def _registered(api, auth: TestAuthenticator, *, count: int = 0):
    resp = api.finish(
        "register",
        auth.registration_body(api.begin("register"), sign_count=count),
    )
    assert resp.status_code == 200, resp.get_json()
    return auth


def _assert(api, auth, challenge, **kw):
    # 默认 userHandle = 当前夹具用户（空用户 ID 不会出现）
    kw.setdefault("user_handle", ALICE.encode())
    return api.finish("login", auth.assertion_body(challenge, **kw))


# ---------- 成功路径 ----------

def test_authentication_success(api, auth):
    _registered(api, auth)
    challenge = api.begin("login")
    resp = _assert(api, auth, challenge, sign_count=1)
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()["signCount"] == 1


def test_authentication_json_byte_variants(api, auth):
    """spaces / reorder 形态的原始字节同样可验（签名各对各的字节）。"""
    _registered(api, auth)
    for i, style in enumerate(("canonical", "spaces", "reordered"), start=1):
        challenge = api.begin("login")
        resp = _assert(api, auth, challenge, sign_count=i, cd_style=style)
        assert resp.status_code == 200, (style, resp.get_json())


# ---------- 挑战与用途 ----------

def test_authentication_wrong_purpose_challenge_rejected(api, auth):
    _registered(api, auth)
    reg_challenge = api.begin("register")
    resp = _assert(api, auth, reg_challenge, sign_count=1)
    assert resp.status_code == 400
    assert "用途" in resp.get_json()["message"]


def test_bad_signature_keeps_challenge_usable(api, auth):
    """签名失败不消耗挑战。"""
    _registered(api, auth)
    challenge = api.begin("login")
    other = TestAuthenticator()
    resp = _assert(api, auth, challenge, signer=other, sign_count=1)
    assert resp.status_code == 400
    # 用正确私钥、同一挑战再来一次 —— 成功
    resp = _assert(api, auth, challenge, sign_count=1)
    assert resp.status_code == 200


def test_consumed_challenge_cannot_be_used_again(api, auth):
    _registered(api, auth)
    challenge = api.begin("login")
    assert _assert(api, auth, challenge, sign_count=1).status_code == 200
    resp = _assert(api, auth, challenge, sign_count=2)
    assert resp.status_code == 409
    assert resp.get_json()["error"] == "ChallengeConsumed"


# ---------- 凭据归属 ----------

def test_unknown_credential_id_rejected(api, auth):
    _registered(api, auth)
    stranger = TestAuthenticator()
    challenge = api.begin("login")
    resp = _assert(api, auth, challenge,
                   credential_id=stranger.credential_id, sign_count=1)
    assert resp.status_code == 400


def test_credential_of_other_user_rejected(api, auth):
    _registered(api, auth)
    bob_auth = TestAuthenticator()
    from conftest import ApiClient
    bob_api = ApiClient(api.c, BOB)
    assert bob_api.finish(
        "register",
        bob_auth.registration_body(bob_api.begin("register"))
    ).status_code == 200
    # Alice 的登录挑战 + Bob 的凭据；userHandle 也伪装成 Alice，
    # 失败点应是「credential ID 不属于当前用户」
    challenge = api.begin("login")
    resp = _assert(api, auth, challenge,
                   credential_id=bob_auth.credential_id, sign_count=1)
    assert resp.status_code == 400
    assert "不属于" in resp.get_json()["message"]


def test_user_handle_mismatch_rejected(api, auth):
    _registered(api, auth)
    challenge = api.begin("login")
    resp = _assert(api, auth, challenge, sign_count=1,
                   user_handle=b64url_encode(BOB.encode()))
    assert resp.status_code == 400


# ---------- 签名拼接 / 原始字节 ----------

def test_assertion_signature_must_cover_raw_cd_bytes(api, auth):
    """对 canonical 字节签名，却发送 reordered 字节 —— 必须失败，
    即使服务端重新序列化能得到相同 JSON。"""
    _registered(api, auth)
    challenge = api.begin("login")
    canonical = auth.client_data_json(challenge, "webauthn.get")
    reordered = auth.client_data_json(challenge, "webauthn.get",
                                      style="reordered")
    import hashlib
    ad = auth.auth_data(attested=False, sign_count=1)
    sig = auth.sign(ad + hashlib.sha256(canonical).digest())
    body = auth.assertion_body(
        challenge, auth_data=ad, client_data=reordered,
        signature=sig, sign_count=1, user_handle=ALICE.encode(),
    )
    resp = api.finish("login", body)
    assert resp.status_code == 400


def test_assertion_raw_rs_signature_rejected(api, auth):
    _registered(api, auth)
    challenge = api.begin("login")
    resp = _assert(api, auth, challenge, sign_count=1, raw_rs=True)
    assert resp.status_code == 400


def test_assertion_authdata_with_attested_credential_rejected(api, auth):
    """认证用 authData 夹带 attestedCredentialData（长度>37）必须拒绝。"""
    _registered(api, auth)
    challenge = api.begin("login")
    ad = auth.auth_data(attested=True, sign_count=1)
    resp = _assert(api, auth, challenge, auth_data=ad)
    assert resp.status_code == 400


def test_assertion_backup_flags_rejected(api, auth):
    _registered(api, auth)
    challenge = api.begin("login")
    from webauthn_limited.crypto import FLAG_BE, FLAG_UP, FLAG_UV
    ad = auth.auth_data(attested=False,
                        flags=FLAG_UP | FLAG_UV | FLAG_BE, sign_count=1)
    assert _assert(api, auth, challenge, auth_data=ad).status_code == 400


def test_assertion_truncated_authdata_rejected(api, auth):
    _registered(api, auth)
    challenge = api.begin("login")
    ad = auth.auth_data(attested=False, sign_count=1)[:30]
    resp = _assert(api, auth, challenge, auth_data=ad)
    assert resp.status_code == 400


def test_assertion_wrong_type_origin_rejected(api, auth):
    _registered(api, auth)
    challenge = api.begin("login")
    body = auth.assertion_body(challenge, ctype="webauthn.create", sign_count=1)
    assert api.finish("login", body).status_code == 400
    body = auth.assertion_body(challenge, origin="https://evil.example",
                               sign_count=1)
    assert api.finish("login", body).status_code == 400


# ---------- 签名计数规则 ----------

def test_zero_counter_may_stay_zero(api, auth):
    _registered(api, auth, count=0)
    for _ in range(3):
        challenge = api.begin("login")
        resp = _assert(api, auth, challenge, sign_count=0)
        assert resp.status_code == 200, resp.get_json()


def test_zero_counter_can_become_positive(api, auth):
    _registered(api, auth, count=0)
    challenge = api.begin("login")
    assert _assert(api, auth, challenge, sign_count=5).status_code == 200
    challenge = api.begin("login")
    assert _assert(api, auth, challenge, sign_count=6).status_code == 200


def test_positive_counter_must_strictly_increase(api, auth):
    _registered(api, auth, count=10)
    challenge = api.begin("login")
    resp = _assert(api, auth, challenge, sign_count=10)  # 相等
    assert resp.status_code == 409
    assert resp.get_json()["error"] == "CounterRejected"
    challenge = api.begin("login")
    resp = _assert(api, auth, challenge, sign_count=9)  # 回退
    assert resp.status_code == 409
    # 计数失败不消耗挑战（原挑战仍可用更大的值成功）
    resp = _assert(api, auth, challenge, sign_count=11)
    assert resp.status_code == 200


def test_registered_zero_then_positive_then_zero_rejected(api, auth):
    _registered(api, auth, count=0)
    c1 = api.begin("login")
    assert _assert(api, auth, c1, sign_count=3).status_code == 200
    c2 = api.begin("login")
    assert _assert(api, auth, c2, sign_count=0).status_code == 409


# ---------- 并发 ----------

class _BarrierDb:
    """包装 Database：进入写事务时在 barrier 上同步，用于强制交错。"""

    def __init__(self, real_db, barrier):
        self._real = real_db
        self._barrier = barrier

    def __getattr__(self, name):
        return getattr(self._real, name)

    def transaction(self):
        self._barrier.wait(timeout=10)
        return self._real.transaction()


def test_same_challenge_concurrent_success_at_most_one(service, api, auth):
    """同一挑战的并发成功至多一个。

    两个线程使用同一认证挑战、相同的合法签名载荷，通过 barrier 在进入
    写事务时强制同时竞争；无论 SQLite 以何种顺序授予写锁，只能有一个
    提交，另一个收到 ChallengeConsumed。重复 20 轮消除调度偶然性。
    """
    _registered(api, auth, count=1)

    for round_no in range(20):
        challenge = api.begin("login")
        body = auth.assertion_body(challenge, sign_count=50 + round_no,
                                    user_handle=ALICE.encode())

        barrier = threading.Barrier(2)
        service.db = _BarrierDb(service.db, barrier)  # type: ignore[assignment]
        outcomes: list[str] = []
        lock = threading.Lock()

        def worker():
            try:
                service.finish_authentication(ALICE, body)
                result = "ok"
            except Exception as exc:  # noqa: BLE001
                result = type(exc).__name__
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        service.db = service.db._real  # type: ignore[assignment]
        assert sorted(outcomes) == ["ChallengeConsumed", "ok"], (
            round_no, outcomes)
        row = service.db.get_credential(auth.credential_id)
        assert row["sign_count"] == 50 + round_no


def test_two_counter_submissions_interleaved(service, api, auth):
    """两次计数提交交错（各自不同挑战，库外验签均已完成后同时进事务）。

    两个线程提交 c=12 与 c=15，barrier 保证它们在事务入口同时竞争写锁，
    从而强制「先读计数 -> 检查 -> 更新」的所有交错：
      * 15 先提交：12 的事务随后发现 12 < 15，计数检查失败并整体回滚，
        其挑战不被消耗；
      * 12 先提交：15 的事务随后成功（15>12），其挑战被消耗。
    任何交错下，最终计数都必须是较大值 15；较小值绝不落在较大值之后。
    """
    _registered(api, auth, count=1)
    c_lo = api.begin("login")
    c_hi = api.begin("login")
    body_lo = auth.assertion_body(c_lo, sign_count=12,
                                 user_handle=ALICE.encode())
    body_hi = auth.assertion_body(c_hi, sign_count=15,
                                 user_handle=ALICE.encode())

    barrier = threading.Barrier(2)
    service.db = _BarrierDb(service.db, barrier)  # type: ignore[assignment]
    results: dict[str, str] = {}

    def worker(tag, body):
        try:
            out = service.finish_authentication(ALICE, body)
            results[tag] = f"ok:{out['signCount']}"
        except Exception as exc:  # noqa: BLE001
            results[tag] = f"err:{type(exc).__name__}"

    t_lo = threading.Thread(target=worker, args=("lo", body_lo))
    t_hi = threading.Thread(target=worker, args=("hi", body_hi))
    t_lo.start(); t_hi.start()
    t_lo.join(timeout=30); t_hi.join(timeout=30)
    service.db = service.db._real  # type: ignore[assignment]

    assert results["hi"] == "ok:15", results
    # lo 要么成功（先于 hi 提交），要么被计数规则拒绝（hi 先提交）
    assert results["lo"] in {"ok:12", "err:CounterRejected"}
    if results["lo"] == "err:CounterRejected":
        # lo 的事务整体回滚：其挑战仍可被使用
        assert service.db.get_challenge(c_lo) is not None
    else:
        assert service.db.get_challenge(c_lo) is None
    row = service.db.get_credential(auth.credential_id)
    assert row["sign_count"] == 15


def test_interleaved_many_counters_final_is_max(service, api, auth):
    """N 个不同挑战、不同计数同时交错提交，最终计数必须等于最大值。"""
    _registered(api, auth, count=1)
    n = 8
    counters = list(range(50, 50 + n))  # 50..57
    challenges = [api.begin("login") for _ in counters]
    bodies = [auth.assertion_body(c, sign_count=v, user_handle=ALICE.encode())
              for c, v in zip(challenges, counters)]

    barrier = threading.Barrier(n)
    service.db = _BarrierDb(service.db, barrier)  # type: ignore[assignment]
    accepted: list[int] = []
    rejected: list[str] = []
    results_lock = threading.Lock()

    def worker(body):
        try:
            out = service.finish_authentication(ALICE, body)
            with results_lock:
                accepted.append(out["signCount"])
        except Exception as exc:  # noqa: BLE001
            with results_lock:
                rejected.append(type(exc).__name__)

    threads = [threading.Thread(target=worker, args=(b,)) for b in bodies]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    service.db = service.db._real  # type: ignore[assignment]

    # 接受序列必须严格递增（每个提交者都基于前一个已提交值做检查）
    assert accepted == sorted(accepted)
    assert accepted[-1] == 57
    # 被拒只能是计数回退；被拒事务不得消耗对应挑战
    assert set(rejected) <= {"CounterRejected"}
    row = service.db.get_credential(auth.credential_id)
    assert row["sign_count"] == 57
    # 被拒者对应的挑战仍保留，可用更大计数再认证成功
    for c, v in zip(challenges, counters):
        if service.db.get_challenge(c) is not None:
            body = auth.assertion_body(c, sign_count=58, user_handle=ALICE.encode())
            out = service.finish_authentication(ALICE, body)
            assert out["signCount"] == 58
            break
    else:  # 全部成功也合法
        assert service.db.get_credential(auth.credential_id)["signCount"] >= 57
