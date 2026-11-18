# vendored 溯源：skill_package.py

- 单一来源（上游）：`HorizonCloudy/plugin-forge` 仓 `skills/plugin-forge/scripts/skill_package.py`
  （PR #6 分支 fork：`1-dcjiang/plugin-forge` @ `feat/skill-package-core`）。
- 本仓 `skill_package.py` 为**逐字副本**，与上游 SHA256 一致。
- 规则：**只改上游，副本不手改**。上游变更后重新复制并更新下方 commit 与哈希。
- 漂移自检：`python scripts/check_vendored.py`（比对本地副本与上游 pinned commit 的 sha256）。拉不到上游时 **fail-closed 判失败**（防分支被删/离线静默失去检测）；仅显式 `--allow-offline` 才接受本地与记录一致的离线兜底。
- 副本中的 `# forge-declared: ...` 行是上游 forge 自扫豁免注释，在本仓属注释噪音（本仓不跑 forge 自扫），保留以维持逐字一致。

## 当前 pinned 来源

- upstream-commit: `c08fe0a2943ab2e96954c2250dd4d8df6face2a0`
- upstream-raw: `https://raw.githubusercontent.com/1-dcjiang/plugin-forge/c08fe0a2943ab2e96954c2250dd4d8df6face2a0/skills/plugin-forge/scripts/skill_package.py`
- sha256: `4D6F541A65D677F0F1A4807F98A42BA4D43BD866BDBDDC8BAD66EFAE647FF46C`（LF 行尾，与上游 git blob 一致）