"""install_skill（AI 自主安装 skill）逻辑与安全测试。"""
import asyncio
import gzip
import http.server
import os
import shutil
import threading
import zipfile
from pathlib import Path

import plugin.plugins.skill_compat as sc
import pytest
from plugin.plugins.skill_compat import SkillCompatPlugin, _as_bool, _safe_name
from plugin.sdk.plugin import Err, Ok


def _make_plugin(target_root: Path) -> SkillCompatPlugin:
    p = SkillCompatPlugin.__new__(SkillCompatPlugin)
    p._idx = {}
    p._lock = threading.Lock()
    p._skill_dirs = [str(target_root)]
    p._follow_symlinks = True
    p._scan_status = "未扫描"
    return p


def _make_skill(root: Path, name: str) -> Path:
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(f"---\nname: {name}\ndescription: 测试技能\n---\n# {name}\n", encoding="utf-8")
    return d


def _ok(result) -> dict:
    assert isinstance(result, dict), result
    assert result.get("is_error") is False, result
    return result["output"]


def _err(result) -> dict:
    assert isinstance(result, dict), result
    assert result.get("is_error") is True, result
    return result


# ---------- _safe_name ----------

def test_safe_name_keeps_valid():
    assert _safe_name("my-skill") == "my-skill"
    assert _safe_name("中文技能") == "中文技能"
    assert _safe_name("a.b-c_d") == "a.b-c_d"


def test_safe_name_strips_path():
    assert _safe_name("C:\\Users\\a\\hello-skill") == "hello-skill"
    assert _safe_name("https://x/y/skill.zip") == "skill.zip"


def test_safe_name_rejects_dotdot():
    assert _safe_name("..") is None
    assert _safe_name("...") is None


# ---------- install_skill：本地目录 ----------

def test_install_from_dir(tmp_path):
    src = _make_skill(tmp_path, "hello-skill")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = _ok(asyncio.run(p.install_skill(source=str(src))))
    assert result["installed"] is True
    assert result["name"] == "hello-skill"
    assert (target / "hello-skill" / "SKILL.md").is_file()


def test_install_duplicate_fails_without_overwrite(tmp_path):
    src = _make_skill(tmp_path, "hello-skill")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    assert _ok(asyncio.run(p.install_skill(source=str(src))))
    result = _err(asyncio.run(p.install_skill(source=str(src))))
    assert "已存在" in result["output"]


def test_install_overwrite(tmp_path):
    src = _make_skill(tmp_path, "hello-skill")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    assert _ok(asyncio.run(p.install_skill(source=str(src))))
    result = _ok(asyncio.run(p.install_skill(source=str(src), name="hello-skill", overwrite=True)))
    assert result["installed"] is True


def test_install_bad_source(tmp_path):
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    assert _err(asyncio.run(p.install_skill(source=str(tmp_path / "not-exist"))))
    assert _err(asyncio.run(p.install_skill(source="")))


def test_install_dir_without_skillmd(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    assert _err(asyncio.run(p.install_skill(source=str(empty))))


# ---------- install_skill：本地 zip ----------

def test_install_from_zip(tmp_path):
    src = _make_skill(tmp_path, "zip-skill")
    zpath = tmp_path / "zip-skill.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.write(src / "SKILL.md", "zip-skill/SKILL.md")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    _ok(asyncio.run(p.install_skill(source=str(zpath))))
    assert (target / "zip-skill" / "SKILL.md").is_file()


def test_install_zip_traversal_rejected(tmp_path):
    zpath = tmp_path / "evil.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("../evil/SKILL.md", "---\nname: evil\n---\n")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    assert _err(asyncio.run(p.install_skill(source=str(zpath))))
    assert not (target / "evil").exists()


def test_install_zip_without_skillmd(tmp_path):
    zpath = tmp_path / "nope.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.txt", "no skill here")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    assert _err(asyncio.run(p.install_skill(source=str(zpath))))


def test_install_into_missing_root(tmp_path):
    src = _make_skill(tmp_path, "hello-skill")
    p = _make_plugin(tmp_path / "no-such-root")
    result = _err(asyncio.run(p.install_skill(source=str(src))))
    assert "可写" in result["output"]


# ---------- 超限 → 询问确认（而不是直接禁止） ----------

def test_oversized_zip_asks_confirmation(tmp_path, monkeypatch):
    monkeypatch.setattr(sc, "_MAX_PACKAGE_BYTES", 100)
    zpath = tmp_path / "big.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("big-skill/SKILL.md", "x" * 500)
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = asyncio.run(p.install_skill(source=str(zpath)))
    assert isinstance(result, dict) and result.get("is_error") is False, result
    out = result["output"]
    assert out.get("need_confirmation") is True
    assert "超过默认上限" in out["reason"]
    assert "confirm_large=true" in out["how_to_proceed"]
    # 未确认前不落地
    assert not (target / "big-skill").exists()


def test_oversized_zip_installs_after_confirmation(tmp_path, monkeypatch):
    monkeypatch.setattr(sc, "_MAX_PACKAGE_BYTES", 100)
    zpath = tmp_path / "big.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("big-skill/SKILL.md", "x" * 500)
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = _ok(asyncio.run(p.install_skill(source=str(zpath), confirm_large=True)))
    assert result["installed"] is True
    assert (target / "big-skill" / "SKILL.md").is_file()


def test_too_many_entries_asks_confirmation(tmp_path, monkeypatch):
    monkeypatch.setattr(sc, "_MAX_ARCHIVE_ENTRIES", 3)
    zpath = tmp_path / "many.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        for i in range(4):
            zf.writestr(f"many-skill/file{i}.txt", f"content {i}")
        zf.writestr("many-skill/SKILL.md", "---\nname: many\n---\n")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = asyncio.run(p.install_skill(source=str(zpath)))
    out = result["output"]
    assert out.get("need_confirmation") is True
    assert "条目" in out["reason"]
    # 用户确认后可装
    result2 = _ok(asyncio.run(p.install_skill(source=str(zpath), confirm_large=True)))
    assert result2["installed"] is True


# ---------- URL 安全（SSRF 预筛选） ----------

def test_safe_url_rejects_private_targets(tmp_path):
    p = _make_plugin(tmp_path)
    for bad in ("http://127.0.0.1/x.zip", "http://localhost/x.zip",
                "http://169.254.169.254/latest/meta-data/", "http://100.100.100.200/",
                "http://metadata.google.internal/x", "http://2130706433/x.zip"):
        assert p._is_safe_url(bad) is False, bad


def test_safe_url_accepts_public_https(tmp_path):
    p = _make_plugin(tmp_path)
    assert p._is_safe_url("https://example.com/skill/archive/main.zip") is True


def test_install_unsafe_url_rejected(tmp_path):
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = _err(asyncio.run(p.install_skill(source="http://127.0.0.1/evil.zip")))
    assert "不安全" in result["output"]


def test_ipv4_mapped_ipv6_rejected():
    """IPv4-mapped IPv6（::ffff:127.0.0.1 实为 127.0.0.1）不得绕过 SSRF 预筛选。"""
    assert sc._ip_is_safe("::ffff:127.0.0.1") is False
    assert sc._ip_is_safe("::ffff:169.254.169.254") is False
    assert sc._ip_is_safe("::ffff:0.0.0.0") is False
    assert sc._ip_is_safe("::ffff:1.2.3.4") is True
    assert sc._url_safe("http://[::ffff:127.0.0.1]/x.zip") is False
    assert sc._url_safe("http://[::ffff:169.254.169.254]/latest/meta-data/") is False


def test_redirect_to_private_rejected(tmp_path, monkeypatch):
    """重定向目标是内网时必须拒绝（防 302 跳内网 = SSRF）。"""
    import pytest

    class _Redirector(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/evil.zip")
            self.end_headers()

        def log_message(self, *args):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _Redirector)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        # 源 URL 形如公网（local 别名），放行；重定向到 127.0.0.1 需被拒
        with pytest.raises(ValueError, match="已拒绝"):
            sc._download_url_with_redirects(
                f"http://localhost:{srv.server_port}/src.zip", 1024, False)
    finally:
        srv.shutdown()
        t.join()


def test_zip_symlink_entry_rejected(tmp_path):
    """zip 内含符号链接条目必须拒绝（解压后指向外部路径，copytree 会跟随复制）。"""
    zpath = tmp_path / "symlink.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zi = zipfile.ZipInfo("link-skill/SKILL.md")
        zi.create_system = 3  # Unix
        zi.external_attr = (0o120000 << 16)  # symlink
        zf.writestr(zi, "---\nname: link-skill\n---\n")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = _err(asyncio.run(p.install_skill(source=str(zpath))))
    assert "符号链接" in result["output"]
    assert not (target / "link-skill").exists()


def test_zip_drive_letter_entry_rejected(tmp_path):
    """zip 内含 Windows 盘符绝对路径条目必须拒绝。"""
    zpath = tmp_path / "drive.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("C:/evil/SKILL.md", "---\nname: evil\n---\n")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = _err(asyncio.run(p.install_skill(source=str(zpath))))
    assert "盘符" in result["output"]
    assert not (target / "evil").exists()


# ---------- 可靠性：布尔解析 / gzip / 索引重建 ----------

def test_as_bool_string_forms():
    assert _as_bool(True) is True
    assert _as_bool(False) is False
    assert _as_bool("true") is True
    assert _as_bool("1") is True
    assert _as_bool("false") is False
    assert _as_bool("0") is False
    assert _as_bool("no") is False
    assert _as_bool("") is False


def test_overwrite_string_false_does_not_overwrite(tmp_path):
    """LLM 若把 overwrite 传成字符串 'false'，不得被 bool() 误判为 True 而覆盖。"""
    src = _make_skill(tmp_path, "hello-skill")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    assert _ok(asyncio.run(p.install_skill(source=str(src))))
    result = _err(asyncio.run(p.install_skill(source=str(src), overwrite="false")))
    assert "已存在" in result["output"]


def test_download_gzip_decoded(tmp_path, monkeypatch):
    """CDN 返回 Content-Encoding: gzip 的 zip 时应解压后返回 PK 数据。"""
    zip_bytes = b"PK\x03\x04" + b"fake-zip-body"

    class _GzipHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = gzip.compress(zip_bytes)
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _GzipHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    monkeypatch.setattr(sc, "_url_safe", lambda u: True)
    try:
        data = sc._download_url_with_redirects(
            f"http://localhost:{srv.server_port}/skill.zip", 1024, False)
        assert data == zip_bytes
    finally:
        srv.shutdown()
        t.join()


def test_invalid_port_url_rejected_cleanly():
    """非法端口 URL（:abc）不得导致裸异常，应返回友好错误。"""
    import pytest

    with pytest.raises(ValueError, match="端口非法"):
        sc._download_url_with_redirects("https://example.com:abc/x.zip", 1024, False)


def test_scan_rebuilds_index_after_delete(tmp_path):
    """skill 目录被删除后重新扫描，索引不应残留失效条目。"""
    src = _make_skill(tmp_path, "gone-skill")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    assert _ok(asyncio.run(p.install_skill(source=str(src))))
    assert any("gone-skill" in k for k in p._idx)
    shutil.rmtree(target / "gone-skill")
    asyncio.run(p._scan_all())
    assert not any("gone-skill" in k for k in p._idx)
    assert p._scan_status.startswith("已加载")


def test_list_filters_deleted_skill_without_rescan(tmp_path):
    """目录被删除后（不重扫）list_skills 不应再返回失效条目。"""
    src = _make_skill(tmp_path, "doomed-skill")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    assert _ok(asyncio.run(p.install_skill(source=str(src))))
    # 删除磁盘目录，但保持索引状态为"已扫描"（模拟外部删除后直接查询）
    shutil.rmtree(target / "doomed-skill")
    p._scan_status = "已加载 1 个 skill"
    res = asyncio.run(p.list_skills())
    assert isinstance(res, Ok)
    assert all("doomed-skill" not in (s["name"] or "") for s in res.value["skills"])


def test_load_skill_removed_entry_hint(tmp_path):
    """load 一个目录已被删除的 skill 时应给出提示并从索引移除。"""
    src = _make_skill(tmp_path, "vanished-skill")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    assert _ok(asyncio.run(p.install_skill(source=str(src))))
    shutil.rmtree(target / "vanished-skill")
    p._scan_status = "已加载 1 个 skill"
    result = asyncio.run(p.load_skill(name="vanished-skill"))
    assert isinstance(result, Err)
    assert "已不存在" in str(result.error)
    assert not any("vanished-skill" in k for k in p._idx)


# ---------- 终审：扫描失败兜底 / gzip 超限 / tmp 清理 ----------

def test_on_scan_done_failure_resets_to_unscanned(tmp_path):
    """后台扫描失败后应置回"未扫描"，让下次查询惰性补扫，而不是卡在失败状态。"""
    p = _make_plugin(tmp_path / "root")

    async def _boom():
        raise RuntimeError("scan exploded")

    async def _run():
        task = asyncio.create_task(_boom())
        try:
            await task
        except RuntimeError:
            pass
        p._on_scan_done(task)

    asyncio.run(_run())
    assert p._scan_status == "未扫描"


def test_gzip_oversize_asks_confirmation(tmp_path, monkeypatch):
    """gzip 解压后超过上限应转询问确认，而不是直接返回超大内容。"""
    max_bytes = 1024
    # 用重复数据压缩出高压缩比内容（解压后 > max_bytes）
    big = b"PK\x03\x04" + (b"A" * (max_bytes * 4))
    enc = gzip.compress(big)

    class _BigGzipHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(enc)))
            self.end_headers()
            self.wfile.write(enc)

        def log_message(self, *args):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _BigGzipHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    monkeypatch.setattr(sc, "_url_safe", lambda u: True)
    try:
        with pytest.raises(sc._NeedConfirmation):
            sc._download_url_with_redirects(
                f"http://localhost:{srv.server_port}/big.zip", max_bytes, False)
    finally:
        srv.shutdown()
        t.join()


def test_zip_failure_cleans_tmp(tmp_path, monkeypatch):
    """zip 校验失败（路径穿越）后不应残留临时解压目录。"""
    zpath = tmp_path / "evil.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("../evil/SKILL.md", "---\nname: evil\n---\n")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    created = []

    orig = sc.tempfile.mkdtemp

    def fake_mkdtemp(*a, **k):
        d = orig(*a, **k)
        created.append(d)
        return d

    monkeypatch.setattr(sc.tempfile, "mkdtemp", fake_mkdtemp)
    result = _err(asyncio.run(p.install_skill(source=str(zpath))))
    assert "非法路径" in result["output"]
    assert len(created) == 1
    assert not os.path.exists(created[0])


def test_install_https_zip_fails_on_unreachable(tmp_path):
    """公网 https zip 下载：目标不可达/非 zip 时返回 is_error（不依赖具体网络环境结果，只验证不会崩）。"""
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = asyncio.run(p.install_skill(source="https://github.com/1-dcjiang/n.e.k.o_plugin_skill_compat/archive/refs/tags/v0.1.1.zip"))
    assert isinstance(result, dict), result
    assert result.get("is_error") is True or result.get("is_error") is False, result
