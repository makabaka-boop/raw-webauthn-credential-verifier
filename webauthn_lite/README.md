# WebAuthn Lite

一个**刻意限定范围**的 WebAuthn 注册/认证 Python 服务。仅使用 Python 标准库
（ECDSA P-256 为纯 Python 实现），SQLite 持久化，无需 `pip install`。

## 支持范围（白名单，其余一律拒绝）

| 项目 | 允许值 |
|---|---|
| 公钥类型 | `public-key` |
| 算法 | **ES256**（`alg=-7`，ECDSA-SHA256，P-256 / COSE EC2 / crv=1） |
| 证明格式 | `none`，或 `packed` **自签名**（无 `x5c`、无证书链、无 AAGUID 以外信息） |
| 标志 | `UP=1`、`UV=1`、`BE=0`、`BS=0`、`ED=0` |
| 扩展 | 不支持（`ED` 位置位或 clientData 中 `tokenBinding` 均拒绝） |
| 可备份凭据 | 不支持（BE/BS 置位即拒绝） |
| origin / RP ID | **服务端固定配置**，请求中的同名字段一律忽略 |

## 验签规则

* 全程使用**收到的原始 `clientDataJSON` 字节**做 SHA-256，绝不重新序列化 JSON。
  非规范空白、键序变化只要客户端对同样字节签名即可通过；服务端若把 JSON 重排
  再验签会导致的不匹配，由 `test_reserialized_json_*` 两个用例锁死。
* 注册校验：挑战、`type=webauthn.create`、精确 origin、`SHA-256(RP ID)`、
  UP/UV、AAGUID 全零、credential ID 长度（16–1024）、COSE P-256 公钥。
  `packed` 自签名内容为 `authenticatorData || SHA256(clientDataJSON)`，
  由**注册响应里的同一把公钥**验证。
* 认证校验：credential ID 必须存在且**属于该用户**；挑战必须是未消费的
  `webauthn.get` 用途挑战；签名内容同样是
  `authenticatorData || SHA256(clientDataJSON 原始字节)`，用入库公钥验证。

## 签名计数（signature counter）语义

* 库里计数为 **0** 的凭据：可无限次继续提交 0，也可以一次性升级为正数。
* 一旦记录过**正数**：之后只接受**严格更大**的值；相等或倒退直接拒绝
  （不验签、不消费挑战）。
* 成功路径上「挑战条件消费 + 计数更新」在同一个 `BEGIN IMMEDIATE` 事务中
  一次提交；任何失败回滚。因此：
  * 签名失败 → 挑战**不消耗**，可立刻用正确签名重试；
  * 同一挑战的并发成功 → **至多一个**提交，另一个收到“已被消费”；
  * 两个不同挑战的计数提交交错（如 100 与 101）时，最终状态等价于某种
    串行执行，低计数晚到会被 `CounterRejected` 拒绝。

## 数据模型（SQLite）

* `users(id, display_name)` —— 只由测试夹具 `seed_users.py` 写入，无账户系统接口。
* `credentials(user_id, credential_id UNIQUE, pub_cose, sign_count, created_at)`
* `challenges(challenge PK, purpose ∈ {registration, authentication}, user_id,
  consumed, created_at)` —— 挑战表同时记录“用途”，注册载荷不能消费认证挑战。

## HTTP 接口

所有二进制字段使用无填充 base64url，请求/响应均为 JSON。

| 路径 | 说明 |
|---|---|
| `POST /register/begin` | `{ "user_id": "alice" }` → 返回固定 `rp`、挑战、仅含 ES256 的 `pubKeyCredParams` |
| `POST /register/finish` | `{user_id, clientDataJSON, attestationObject}` |
| `POST /authenticate/begin` | `{ "user_id": "alice" }` → 挑战 + 该用户自己的 allowCredentials |
| `POST /authenticate/finish` | `{user_id, credential_id, clientDataJSON, authenticatorData, signature}` |
| `GET /health` | 回报服务端固定的 rp_id / origin |

## 运行

```bash
# 固定配置（默认值已指向本机）
export WA_RP_ID="localhost"
export WA_ORIGIN="http://localhost:8080"
export WA_DB="/tmp/webauthn.db"

# 1) 写入测试夹具用户
python3 -m webauthn_lite.seed_users alice "Alice Tester"

# 2) 启动服务
python3 -m webauthn_lite.server

# 3) 运行全部测试（39 个用例，纯标准库）
python3 -m unittest webauthn_lite.tests.test_core webauthn_lite.tests.test_http -v
```

## 目录

```
webauthn_lite/
├── config.py           # 服务端固定配置（env 覆盖默认值，请求不能覆盖）
├── cbor.py             # 最小 CBOR 编解码（无标签/浮点/indefinite）
├── crypto.py           # 纯标准库 P-256 / ECDSA-SHA256（含低 S、RFC6979 测试签名）
├── store.py            # SQLite：users/credentials/challenges + 原子提交
├── webauthn.py         # 注册/认证验证核心
├── server.py           # 标准库 http.server 包装（每线程独立 DB 连接）
├── seed_users.py       # 测试夹具：用户身份入口
└── tests/
    ├── fake_authenticator.py  # 每次生成真实 P-256 密钥的测试认证器
    ├── test_core.py           # 验证逻辑 + 计数交错 + 并发挑战
    └── test_http.py           # 真实端口端到端
```

## 测试覆盖的关键场景

* 真实椭圆曲线密钥构造的注册/认证载荷（`packed` 与 `none`）。
* **JSON 字节差异**：额外空白、键序重排通过；对一种字节签名却提交另一种
  （紧凑 ↔ 缩进）必须失败。
* **错误用途**：注册/认证挑战互换拒绝，且失败方不被误消费。
* **截断凭据**：credential ID 长度声明与实际不符、声明长度低于下限、
  认证签名截断一个字节。
* **两次计数提交交错**：顺序执行（100→101 都成功）与反序（101 先落地、
  100 被拒，最终计数 101），以及线程级 50/51 竞态。
* 同一注册/认证挑战的两个并发线程只有一个提交成功。
* origin 精确匹配（尾斜杠、大小写、后缀攻击、scheme 差异）、RP ID 摘要、
  UP/UV/BE/ED 标志、非 ES256 / 非 P-256 / 曲线外点 COSE、`x5c` 证书链、
  未知证明格式、凭据跨用户、他人密钥签名等拒绝路径。
