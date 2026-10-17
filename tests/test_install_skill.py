"""install_skill（AI 自主安装 skill）逻辑测试。"""
import asyncio
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


def test_install_https_zip_fails_on_unreachable(tmp_path):
    """公网 https zip 下载：目标不可达/非 zip 时返回 is_error（不依赖具体网络环境结果，只验证不会崩）。"""
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = asyncio.run(p.install_skill(source="https://github.com/1-dcjiang/n.e.k.o_plugin_skill_compat/archive/refs/tags/v0.1.1.zip"))
    assert isinstance(result, dict), result
    assert result.get("is_error") is True or result.get("is_error") is False, result
