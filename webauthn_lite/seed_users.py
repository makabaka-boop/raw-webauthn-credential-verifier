"""测试夹具：写入/更新用户身份。

用法：
    python3 -m webauthn_lite.seed_users alice "Alice Tester" bob "Bob Tester"

用户身份只通过这个夹具维护，HTTP 层没有注册账户的接口。
"""

from __future__ import annotations

import sys

from . import config as config_mod
from . import store


def main(argv: list[str]) -> int:
    args = argv[1:]
    if not args or len(args) % 2:
        print(__doc__)
        return 2
    cfg = config_mod.load()
    conn = store.connect(cfg.db_path)
    store.init_db(conn)
    for i in range(0, len(args), 2):
        user_id, display_name = args[i], args[i + 1]
        store.seed_user(conn, user_id, display_name)
        print(f"seeded user id={user_id!r} name={display_name!r}")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
