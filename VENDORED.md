# vendored 溯源：skill_package.py

- 单一来源（上游）：`HorizonCloudy/plugin-forge` 仓 `skills/plugin-forge/scripts/skill_package.py`
  （PR #6 分支 fork：`1-dcjiang/plugin-forge` @ `feat/skill-package-core`）。
- 本仓 `skill_package.py` 为**逐字副本**，与上游 SHA256 一致。
- 规则：**只改上游，副本不手改**。上游变更后重新复制并更新下方 commit 与哈希。
- 漂移自检：`python scripts/check_vendored.py`（比对本地副本与上游 pinned commit 的 sha256）。拉不到上游时 **fail-closed 判失败**（防分支被删/离线静默失去检测）；仅显式 `--allow-offline` 才接受本地与记录一致的离线兜底。
- 副本中的 `# forge-declared: ...` 行是上游 forge 自扫豁免注释，在本仓属注释噪音（本仓不跑 forge 自扫），保留以维持逐字一致。

## 当前 pinned 来源

- upstream-commit: `fc3fc1ca32794b792d20f1697911761d14acd5ec`
- upstream-raw: `https://raw.githubusercontent.com/1-dcjiang/plugin-forge/fc3fc1ca32794b792d20f1697911761d14acd5ec/skills/plugin-forge/scripts/skill_package.py`
- sha256: `9EBF4DAF732F8F29A6474B59B34DED9FB19071B7C173D66F59535F9D08A2B2B0`（LF 行尾，与上游 git blob 一致）