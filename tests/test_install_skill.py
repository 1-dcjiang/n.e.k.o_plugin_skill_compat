"""install_skill（AI 自主安装 skill）逻辑测试。"""
import asyncio
import threading
import zipfile
from pathlib import Path

from plugin.plugins.skill_compat import SkillCompatPlugin, _safe_name
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
    result = asyncio.run(p.install_skill(source=str(src)))
    assert isinstance(result, Ok), result
    value = result.value
    assert value["installed"] is True
    assert value["name"] == "hello-skill"
    assert (target / "hello-skill" / "SKILL.md").is_file()


def test_install_duplicate_fails_without_overwrite(tmp_path):
    src = _make_skill(tmp_path, "hello-skill")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    assert isinstance(asyncio.run(p.install_skill(source=str(src))), Ok)
    result = asyncio.run(p.install_skill(source=str(src)))
    assert isinstance(result, Err), result
    assert "已存在" in str(result.error)


def test_install_overwrite(tmp_path):
    src = _make_skill(tmp_path, "hello-skill")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    assert isinstance(asyncio.run(p.install_skill(source=str(src))), Ok)
    result = asyncio.run(p.install_skill(source=str(src), name="hello-skill", overwrite=True))
    assert isinstance(result, Ok), result


def test_install_bad_source(tmp_path):
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = asyncio.run(p.install_skill(source=str(tmp_path / "not-exist")))
    assert isinstance(result, Err), result
    result = asyncio.run(p.install_skill(source=""))
    assert isinstance(result, Err), result


def test_install_dir_without_skillmd(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = asyncio.run(p.install_skill(source=str(empty)))
    assert isinstance(result, Err), result


# ---------- install_skill：本地 zip ----------

def test_install_from_zip(tmp_path):
    src = _make_skill(tmp_path, "zip-skill")
    zpath = tmp_path / "zip-skill.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.write(src / "SKILL.md", "zip-skill/SKILL.md")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = asyncio.run(p.install_skill(source=str(zpath)))
    assert isinstance(result, Ok), result
    assert (target / "zip-skill" / "SKILL.md").is_file()


def test_install_zip_traversal_rejected(tmp_path):
    zpath = tmp_path / "evil.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("../evil/SKILL.md", "---\nname: evil\n---\n")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = asyncio.run(p.install_skill(source=str(zpath)))
    assert isinstance(result, Err), result
    assert not (target / "evil").exists()


def test_install_zip_without_skillmd(tmp_path):
    zpath = tmp_path / "nope.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.txt", "no skill here")
    target = tmp_path / "root"
    target.mkdir()
    p = _make_plugin(target)
    result = asyncio.run(p.install_skill(source=str(zpath)))
    assert isinstance(result, Err), result


def test_install_into_missing_root(tmp_path):
    src = _make_skill(tmp_path, "hello-skill")
    p = _make_plugin(tmp_path / "no-such-root")
    result = asyncio.run(p.install_skill(source=str(src)))
    assert isinstance(result, Err), result
    assert "可写" in str(result.error)
