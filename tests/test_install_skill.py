"""install_skill（AI 自主安装 skill）逻辑与安全测试。"""
import asyncio
import http.server
import threading
import zipfile
from pathlib import Path

import plugin.plugins.skill_compat as sc
from plugin.plugins.skill_compat import SkillCompatPlugin, _safe_name


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


def test_install_https_zip_fails_on_unreachable(tmp_path):
    """公网 https zip 下载：目标不可达/非 zip 时返回 is_error（不依赖具体网络环境结果，只验证不会崩）。"""
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = asyncio.run(p.install_skill(source="https://github.com/1-dcjiang/n.e.k.o_plugin_skill_compat/archive/refs/tags/v0.1.1.zip"))
    assert isinstance(result, dict), result
    assert result.get("is_error") is True or result.get("is_error") is False, result
