# -*- coding: utf-8 -*-
"""vendored 漂移自检：比对本地 skill_package.py 与 VENDORED.md pinned 上游的 sha256。

只读校验，不修改任何文件。上游变更后应重新复制副本并更新 VENDORED.md。
用法：python scripts/check_vendored.py
"""
import hashlib
import pathlib
import re
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCAL = ROOT / "skill_package.py"
MANIFEST = ROOT / "VENDORED.md"


def main():
    text = MANIFEST.read_text(encoding="utf-8")
    m_url = re.search(r"upstream-raw:\s*`([^`]+)`", text)
    m_sha = re.search(r"sha256:\s*`([0-9A-Fa-f]{64})`", text)
    if not m_url or not m_sha:
        print("VENDORED.md 缺少 upstream-raw / sha256 字段")
        return 1
    expect = m_sha.group(1).lower()
    local = hashlib.sha256(LOCAL.read_bytes()).hexdigest()
    if local != expect:
        print(f"本地副本与 VENDORED.md 记录不一致: local={local} recorded={expect}")
        return 1
    try:
        with urllib.request.urlopen(m_url.group(1), timeout=30) as r:
            upstream = hashlib.sha256(r.read()).hexdigest()
    except OSError as e:
        print(f"无法拉取上游（离线？）: {e}；本地与记录一致={local == expect}")
        return 0 if local == expect else 1
    if upstream != local:
        print(f"漂移: local={local} upstream={upstream}")
        return 1
    print(f"OK: 本地副本与上游 pinned commit 逐字一致 sha256={local}")
    return 0


if __name__ == "__main__":
    sys.exit(main())