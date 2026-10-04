"""注册（attestation）相关测试。"""

from __future__ import annotations

from webauthn_limited.crypto import FLAG_AT, FLAG_UP
from webauthn_limited.encoding import b64url_decode, b64url_encode
from conftest import ALICE, BOB, ORIGIN, RP_ID, TestAuthenticator


# ---------- 成功路径 ----------

def test_register_packed_success(api, auth):
    challenge = api.begin("register")
    resp = api.finish("register", auth.registration_body(challenge))
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()["credentialId"] == b64url_encode(auth.credential_id)
    assert resp.get_json()["signCount"] == 0


def test_register_none_success(api, auth):
    challenge = api.begin("register")
    resp = api.finish("register", auth.registration_body(challenge, fmt="none"))
    assert resp.status_code == 200, resp.get_json()


def test_register_json_byte_variants(api, auth):
    """键序 / 空白不同但内容相同的原始 JSON 字节都必须可用。

    签名由 authenticator 对各自原始字节计算，服务端不得重新序列化。
    """
    for style in ("canonical", "spaces", "reordered"):
        # 每种字节形态用一把新凭据（避免 credential ID 重复）
        device = TestAuthenticator()
        challenge = api.begin("register")
        body = device.registration_body(challenge, cd_style=style)
        resp = api.finish("register", body)
        assert resp.status_code == 200, (style, resp.get_json())


def test_register_initial_positive_count_stored(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(challenge, sign_count=42)
    resp = api.finish("register", body)
    assert resp.status_code == 200
    assert resp.get_json()["signCount"] == 42


# ---------- 挑战与用途 ----------

def test_register_wrong_purpose_challenge_rejected(api, auth):
    """用认证用途的挑战做注册必须被拒（错误用途），且挑战不被消耗。"""
    login_challenge = api.begin("login")
    body = auth.registration_body(login_challenge)
    resp = api.finish("register", body)
    assert resp.status_code == 400
    assert "用途" in resp.get_json()["message"]
    # 再次以错误用途使用同一挑战，仍被拒 —— 说明记录未被删除
    again = api.finish("register", auth.registration_body(login_challenge))
    assert again.status_code == 400


def test_register_unknown_challenge_rejected(api, auth):
    api.begin("register")  # 真实挑战不取
    body = auth.registration_body(b"x" * 32)
    resp = api.finish("register", body)
    assert resp.status_code == 409


def test_bad_signature_does_not_consume_challenge(api, auth):
    """签名验证失败不消耗挑战：同一挑战修正后可成功。"""
    challenge = api.begin("register")
    other = TestAuthenticator()
    bad = auth.registration_body(challenge, signer=other)  # 用别人的私钥签
    resp = api.finish("register", bad)
    assert resp.status_code == 400
    good = auth.registration_body(challenge)
    resp = api.finish("register", good)
    assert resp.status_code == 200, resp.get_json()


# ---------- 证明格式限制 ----------

def test_register_unsupported_fmt_rejected(api, auth):
    challenge = api.begin("register")
    resp = api.finish("register", auth.registration_body(challenge, fmt="fido-u2f"))
    assert resp.status_code == 400
    assert "不支持的证明格式" in resp.get_json()["message"]


def test_register_packed_x5c_chain_rejected(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(challenge, x5c=[b"\x30\x82" + b"\x00" * 40])
    resp = api.finish("register", body)
    assert resp.status_code == 400
    assert "x5c" in resp.get_json()["message"]


def test_register_packed_wrong_alg_rejected(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(challenge, att_alg=-257)  # RS256
    resp = api.finish("register", body)
    assert resp.status_code == 400


def test_register_none_with_nonempty_stmt_rejected(api, auth):
    challenge = api.begin("register")
    cd = auth.client_data_json(challenge, "webauthn.create")
    ad = auth.auth_data()
    import cbor2
    bad_att = cbor2.dumps({
        "fmt": "none", "authData": ad, "attStmt": {"x5c": []},
    })
    body = {
        "id": b64url_encode(auth.credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64url_encode(cd),
            "attestationObject": b64url_encode(bad_att),
        },
    }
    resp = api.finish("register", body)
    assert resp.status_code == 400


def test_register_raw_rs_signature_rejected(api, auth):
    """裸 R||S 签名不是 DER，必须拒绝。"""
    challenge = api.begin("register")
    cd = auth.client_data_json(challenge, "webauthn.create")
    ad = auth.auth_data()
    import hashlib
    signed = ad + hashlib.sha256(cd).digest()
    raw = auth.sign_raw_rs(signed)
    import cbor2
    att = cbor2.dumps({
        "fmt": "packed", "authData": ad,
        "attStmt": {"alg": -7, "sig": raw},
    })
    body = {
        "id": b64url_encode(auth.credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64url_encode(cd),
            "attestationObject": b64url_encode(att),
        },
    }
    resp = api.finish("register", body)
    assert resp.status_code == 400


def test_register_cbor_trailing_bytes_rejected(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(challenge)
    att = b64url_decode(body["response"]["attestationObject"]) + b"\x00"
    body["response"]["attestationObject"] = b64url_encode(att)
    resp = api.finish("register", body)
    assert resp.status_code == 400


# ---------- COSE / 曲线 / 算法限制 ----------

def test_register_non_p256_cose_rejected(api, auth):
    import cbor2
    challenge = api.begin("register")
    # crv=3 是 P-521，坐标长度仍伪造为 32 字节，必须在曲线检查处被拒
    bad_cose = cbor2.dumps({1: 2, 3: -7, -1: 3,
                            -2: b"\x00" * 32, -3: b"\x00" * 32})
    ad = auth.auth_data(cose=bad_cose)
    body = auth.registration_body(challenge, auth_data=ad)
    resp = api.finish("register", body)
    assert resp.status_code == 400


def test_register_non_es256_alg_in_cose_rejected(api, auth):
    import cbor2
    challenge = api.begin("register")
    nums = auth.public_key.public_numbers()
    bad_cose = cbor2.dumps({
        1: 2, 3: -35, -1: 1,  # ES384
        -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big"),
    })
    ad = auth.auth_data(cose=bad_cose)
    body = auth.registration_body(challenge, auth_data=ad)
    resp = api.finish("register", body)
    assert resp.status_code == 400


def test_register_extra_cose_key_field_rejected(api, auth):
    import cbor2
    challenge = api.begin("register")
    nums = auth.public_key.public_numbers()
    cose = cbor2.dumps({
        1: 2, 3: -7, -1: 1,
        -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big"),
        2: b"kid",  # kid 不被接受
    })
    ad = auth.auth_data(cose=cose)
    body = auth.registration_body(challenge, auth_data=ad)
    resp = api.finish("register", body)
    assert resp.status_code == 400


# ---------- authenticatorData 检查 ----------

def test_register_rp_id_mismatch_rejected(api, auth):
    challenge = api.begin("register")
    ad = auth.auth_data(rp_id="evil.example")
    body = auth.registration_body(challenge, auth_data=ad)
    resp = api.finish("register", body)
    assert resp.status_code == 400
    assert "RP ID" in resp.get_json()["message"]


def test_register_backup_flags_rejected(api, auth):
    challenge = api.begin("register")
    from webauthn_limited.crypto import FLAG_BE, FLAG_BS, FLAG_AT, FLAG_UP, FLAG_UV
    body = auth.registration_body(
        challenge, flags=FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BE)
    assert api.finish("register", body).status_code == 400
    body = auth.registration_body(
        challenge, flags=FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BS)
    assert api.finish("register", body).status_code == 400


def test_register_extension_flag_rejected(api, auth):
    challenge = api.begin("register")
    from webauthn_limited.crypto import FLAG_AT, FLAG_UP, FLAG_UV
    ad = auth.auth_data(
        flags=FLAG_UP | FLAG_UV | FLAG_AT | 0x80,
        extension_bytes=b"\xa0",
    )
    body = auth.registration_body(challenge, auth_data=ad)
    assert api.finish("register", body).status_code == 400


def test_register_without_uv_rejected(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(challenge, flags=FLAG_AT | FLAG_UP)
    assert api.finish("register", body).status_code == 400


def test_register_truncated_authdata_rejected(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(challenge)
    att = b64url_decode(body["response"]["attestationObject"])
    # 在 CBOR 层把 authData 替换为截断字节串
    import cbor2
    ad = auth.auth_data()[:60]
    rebuilt = cbor2.dumps({"fmt": "none", "authData": ad, "attStmt": {}})
    body["response"]["attestationObject"] = b64url_encode(rebuilt)
    resp = api.finish("register", body)
    assert resp.status_code == 400


def test_register_credential_id_mismatch_rejected(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(challenge, raw_id_override=b"z" * 32)
    resp = api.finish("register", body)
    assert resp.status_code == 400


def test_register_truncated_credential_id_rejected(api, auth):
    """credential ID 声明长度大于实际数据 —— 截断凭据。"""
    challenge = api.begin("register")
    # 手工构造：长度字段写 64，实际只给 10 字节
    import hashlib
    raw = hashlib.sha256(RP_ID.encode()).digest()
    raw += bytes([0x01 | 0x04 | 0x40]) + (0).to_bytes(4, "big")
    raw += auth.aaguid + (64).to_bytes(2, "big") + b"\xaa" * 10
    body = auth.registration_body(challenge, auth_data=raw, fmt="none")
    resp = api.finish("register", body)
    assert resp.status_code == 400


# ---------- clientDataJSON 检查 ----------

def test_register_wrong_type_rejected(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(challenge, ctype="webauthn.get")
    resp = api.finish("register", body)
    assert resp.status_code == 400


def test_register_wrong_origin_rejected(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(challenge, origin="https://evil.example")
    resp = api.finish("register", body)
    assert resp.status_code == 400
    assert "origin" in resp.get_json()["message"]


def test_register_cross_origin_rejected(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(challenge, cross_origin=True)
    assert api.finish("register", body).status_code == 400


def test_register_token_binding_rejected(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(
        challenge, token_binding={"status": "supported"})
    assert api.finish("register", body).status_code == 400


def test_register_no_reserialization_signature_bound_to_raw_bytes(api, auth):
    """签名绑定原始 JSON 字节：发送与签名时不同的字节形态必须验签失败。"""
    challenge = api.begin("register")
    canonical = auth.client_data_json(challenge, "webauthn.create")
    reordered = auth.client_data_json(challenge, "webauthn.create",
                                      style="reordered")
    # 证明签名是对 canonical 字节算的，但发送 reordered 字节
    ad = auth.auth_data()
    att = auth.attestation_object(ad, canonical)
    body = {
        "id": b64url_encode(auth.credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64url_encode(reordered),
            "attestationObject": b64url_encode(att),
        },
    }
    resp = api.finish("register", body)
    assert resp.status_code == 400  # 重新解析成相同 JSON 也救不回签名


# ---------- 其他 ----------

def test_duplicate_credential_id_rejected(api, register, auth):
    assert register(auth).status_code == 200
    resp = register(auth)  # 新挑战、同一 credential ID
    assert resp.status_code == 409
    assert resp.get_json()["error"] == "DuplicateCredential"


def test_register_missing_auth_header_rejected(client, auth):
    challenge = client.post("/register/begin", json={})
    assert challenge.status_code == 401


def test_register_unknown_user_rejected(client, auth):
    resp = client.post(
        "/register/begin", json={}, headers={"X-Test-User": "ghost"})
    assert resp.status_code == 400


def test_register_extension_results_rejected(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(challenge)
    body["getClientExtensionResults"] = {"credProps": {"rk": True}}
    assert api.finish("register", body).status_code == 400


def test_register_unknown_top_level_field_rejected(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(challenge)
    body["rpId"] = "evil.example"  # 试图通过请求体更改 RP ID —— 直接拒绝
    resp = api.finish("register", body)
    assert resp.status_code == 400


def test_register_origin_supplied_in_body_is_ignored_strictness(api, auth):
    """请求里的任何 origin/rpId 字段都不能影响服务端固定配置。"""
    challenge = api.begin("register")
    body = auth.registration_body(challenge, origin="https://evil.example")
    # 连合法的 origin 篡改都在 clientDataJSON 精确比对处被拦
    resp = api.finish("register", body)
    assert resp.status_code == 400


def test_register_oversized_credential_id_rejected(api, auth):
    challenge = api.begin("register")
    body = auth.registration_body(
        challenge, raw_id_override=b"\xaa" * 1100)
    assert api.finish("register", body).status_code == 400
