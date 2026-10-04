# 限定 WebAuthn 注册与认证服务

一个功能子集刻意收窄的 WebAuthn Relying Party 服务，用于验证「最小且严格」的
注册 / 认证流程。用户身份由测试夹具（`X-Test-User` 请求头 + 预置 users 表）
提供，不包含任何账户系统。

## 支持范围（白名单）

| 项目 | 只接受 |
| --- | --- |
| 公钥算法 | **ES256**（ECDSA P-256 + SHA-256，ASN.1 DER 签名） |
| 凭据类型 | `public-key` |
| 证明格式 | `none`、`packed`（仅**自签名**，出现 `x5c` 即拒） |
| 证书链 | 不支持（packed x5c / tpm / fido-u2f / android-* 全拒） |
| 扩展 | 不支持（ED 位必须 0，`getClientExtensionResults` 必须空） |
| 可备份凭据 | 不支持（BE / BS 位必须 0） |
| 用户验证 | **强制** UP=1 且 UV=1 |
| RP ID / origin | 仅来自**服务端配置**，请求任何字段都不能更改 |

不支持的字段（`tokenBinding`、`crossOrigin:true`、裸 R‖S 签名、非 P-256 的
COSE 键、多余 COSE 键、CBOR 尾随字节等）在校验阶段直接拒绝。

## 关键安全语义

1. **原始字节验签**：对 `clientDataJSON` 的 SHA-256 一律作用于 HTTP 收到的
   原始字节；服务端只用 JSON 解析来检查 `type` / `origin` / `challenge`，
   绝不重新序列化后再算哈希。
2. **精确 origin 比对**：字符串全等匹配配置值，不做后缀/子串匹配。
3. **挑战用途隔离**：注册挑战与认证挑战分用途存储，交叉使用被拒。
4. **失败不消耗挑战**：证明/断言签名验证发生在数据库事务**之外**；验签
   失败等密码学失败都不删除挑战。
5. **单次提交**：成功路径的「挑战消耗 + 凭据写入/计数更新」在同一个
   `BEGIN IMMEDIATE` 事务内一次提交或整体回滚。
6. **同一挑战并发至多一个成功**：事务内复查挑战是否仍存在；输家得到
   `409 ChallengeConsumed`。
7. **签名计数（§6.1.1 克隆检测子集）**：
   * 已记录计数为 0 时，允许凭据持续返回 0；
   * 一旦记录为正数，新计数必须**严格更大**，否则
     `409 CounterRejected` 且事务回滚（挑战保留）。
8. **认证归属**：按 credential ID 查库并核对属于当前夹具用户；
   `userHandle` 若出现必须与该用户一致。
9. **签名拼接**：断言验签数据严格为
   `authenticatorData || SHA-256(rawClientDataJSON)`。

## 目录结构

```
webauthn_limited/
  config.py     # 服务端固定配置（RP ID / origin / DB 路径，环境变量注入）
  db.py         # SQLite：users / credentials / challenges（含用途）
  encoding.py   # base64url（无填充、严格字母表）
  crypto.py     # clientDataJSON / CBOR / COSE P-256 / authData / 证明 / ES256
  service.py    # 协议编排：校验顺序、事务边界、计数规则
  app.py        # Flask 路由 + 夹具用户头 + seed/serve 入口
tests/
  conftest.py   # TestAuthenticator：真实生成的 P-256 密钥构造载荷
  test_registration.py
  test_authentication.py
```

## 运行

```bash
pip install -r requirements.txt

# 1) 写入测试夹具用户（默认 alice/bob/carol）
WEBAUTHN_DB_PATH=/tmp/wa.db python -m webauthn_limited.app seed

# 2) 启动
WEBAUTHN_RP_ID=example.test \
WEBAUTHN_ORIGIN=https://example.test \
WEBAUTHN_DB_PATH=/tmp/wa.db \
PORT=8080 python -m webauthn_limited.app serve
```

| 环境变量 | 默认值 |
| --- | --- |
| `WEBAUTHN_RP_ID` | `example.test` |
| `WEBAUTHN_ORIGIN` | `https://<RP_ID>` |
| `WEBAUTHN_RP_NAME` | `Limited WebAuthn RP` |
| `WEBAUTHN_DB_PATH` | `/tmp/webauthn_limited.db` |

### HTTP 接口

所有接口需带 `X-Test-User: <已预置 user_id>`。

* `POST /register/begin` → `PublicKeyCredentialCreationOptions`
* `POST /register/finish`，body：`PublicKeyCredential`（attestation 响应）
* `POST /login/begin` → `PublicKeyCredentialRequestOptions`
* `POST /login/finish`，body：`PublicKeyCredential`（assertion 响应）

二进制字段（`clientDataJSON` / `attestationObject` / `authenticatorData` /
`signature` / 凭据 `id`）使用无填充 base64url 字符串。

错误响应：`{"error": "<异常类名>", "message": "..."}`，
400 为协议/校验失败，401 为缺少夹具用户头，409 为挑战已消耗 / 计数被拒 /
凭据重复。

## 测试

```bash
python -m pytest
```

测试夹具 `TestAuthenticator` 使用 `cryptography` **真实生成** P-256 密钥，
对各自原始 JSON 字节计算 ECDSA SHA-256 签名，用 `cbor2` 编码证明对象与
COSE 公钥。覆盖要点：

* packed / none 成功注册；错误证明格式、x5c 链、错误 alg、非空 none stmt、
  裸 R‖S、CBOR 尾随字节均被拒；
* COSE：非 P-256、非 ES256、多余键、坏点被拒；
* **JSON 字节差异**：紧凑 / 带空白 / 键序重排三种形态各自签名均成功；
  对 canonical 签名却发送 reordered 字节（重新序列化后 JSON 相同）被拒；
* **错误用途**：注册挑战用于认证（及反向）被拒，且挑战不被消耗；
* RP ID 摘要不符、BE/BS/ED 位、缺 UV、截断 authData、**截断 credential ID**、
  外层 id 与 attested id 不符均被拒；
* origin 精确比对、`crossOrigin`、`tokenBinding` 拒绝；
* 认证：未知 credential ID、**跨用户 credential ID**、userHandle 不符；
* 签名失败不消耗挑战，成功后挑战不可复用；
* 零计数可连续为零、可升正；正计数后相等/回退被拒（`409`），
  且计数失败不消耗挑战；
* **并发**（线程 + barrier 强制事务入口同时竞争，多轮重复）：
  同一挑战并发成功至多一个；
  两次计数提交交错（12 与 15）最终计数恒为 15，被拒事务回滚且挑战保留；
  N 路不同挑战交错提交最终计数为最大值，接受序列严格递增。
