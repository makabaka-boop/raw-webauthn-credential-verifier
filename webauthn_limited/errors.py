"""服务端错误类型。

所有协议校验失败都抛出 :class:`WebAuthnError` 的子类，由 Flask 层转成
JSON 响应。``status`` 是对应的 HTTP 状态码。
"""


class WebAuthnError(Exception):
    status = 400

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class InvalidRequest(WebAuthnError):
    """请求结构 / 编码不合法（400）。"""


class VerificationFailure(WebAuthnError):
    """密码学或协议验证失败（400）。"""


class Unauthorized(WebAuthnError):
    """测试夹具未提供有效用户身份（401）。"""

    status = 401


class ChallengeConsumed(WebAuthnError):
    """挑战已被成功的请求消耗（409）。"""

    status = 409


class CounterRejected(WebAuthnError):
    """签名计数不满足单调约束（409）。"""

    status = 409


class DuplicateCredential(WebAuthnError):
    """credential ID 已注册（409）。"""

    status = 409
