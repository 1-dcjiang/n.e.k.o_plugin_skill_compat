# -*- coding: utf-8 -*-
"""skill_package · 第三方 skill 包安全与格式兼容的纯函数核心（零第三方依赖，Python 3.8+）。

本模块从 1-dcjiang/n.e.k.o_plugin_skill_compat 抽取，不依赖 N.E.K.O / 任何宿主 SDK，
只使用标准库，可在 plugin-forge 与 skill_compat 两侧共用（同一份文件，保持同步）。

四块能力：
  1. 安全审计：AUDIT_RULES（提示注入 / 索要凭据 / 下载即执行 / 外传等）+ 风险分级，
     audit_text / audit_skill_dir 只读静态匹配，不执行、不联网。
  2. zip 校验：路径穿越 / Windows 盘符 / 符号链接硬拒绝；条目数 / 声明大小 / 解压后
     实际占用超限转 _NeedConfirmation（询问确认），stage_zip / find_skill_root。
  3. 下载 SSRF 逐跳校验：_ip_is_safe / _url_safe 预筛选（含 IPv4-mapped IPv6 归一、
     GitHub 官方域白名单），_download_url_with_redirects 每跳重定向都复核。  # forge-declared: SEC-4 理由=skill_package 为安全检测器规则字典/其攻击样本测试，非真实执行；下载为 SSRF 逐跳+超限确认的受控下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
  4. 格式兼容：parse_frontmatter（YAML 头缺失 / BOM 容忍）、_safe_name（中文 / 保留名）、
     _parse_skillhub_search 与 @owner/slug 命名空间解析（ima / clawhub / skillhub）。

启发式静态审计会有误报，结果供人工确认，不替代人工审查。
"""
import gzip
import http.client
import io
import ipaddress
import os
import re
import shutil
import socket
import ssl
import tempfile
import urllib.parse
import zipfile

# ---------- skill 格式兼容 ----------
VALID_DIRNAME = re.compile(r'^[a-z0-9][a-z0-9-]*$')

# 安装时允许的目录名字符：字母/数字/中文/下划线/点/连字符，其余替换为 _
_SAFE_NAME_RE = re.compile(r'[^a-zA-Z0-9一-鿿._-]')

# Windows 保留设备名（含带扩展名形态，如 con.txt、COM1.zip），目录名不得使用
_WIN_RESERVED_NAMES = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}

# 安装来源大小上限（超限时转为询问确认，而不是直接禁止）
_MAX_PACKAGE_BYTES = 200 * 1024 * 1024
_MAX_ARCHIVE_ENTRIES = 5000

# ---------- skillhub 商店输出解析 ----------
# 匹配两类技能行：`@namespace/name  display` 或 `name  display`（无前缀）。
_SKILLHUB_ITEM_RE = re.compile(r'^\s*(?:@([^\s/]+)/)?([^\s/]+)\s+(.+)$')

# ---------- skill 安全审计规则（静态文本匹配，只读不执行） ----------
# 每项: (rule_id, 级别, 标签, 正则, 提示, only_scripts)。
# only_scripts=True 的规则只在脚本文件中生效（SKILL.md 说明文字跳过，避免误报）。
_AUDIT_SCRIPT_EXTS = {'.py', '.sh', '.ps1', '.js', '.bat', '.cmd', '.rb', '.pl', '.lua'}
_AUDIT_MAX_SCRIPT_BYTES = 1_000_000
_AUDIT_MAX_SCRIPTS = 100
_AUDIT_MAX_FILES = 3000
_AUDIT_MAX_TOTAL_BYTES = 60 * 1024 * 1024

AUDIT_RULES = [
    ("exec_shell", "critical", "脚本直接执行系统命令",
     re.compile(r'(?i)\b(os\.system|os\.popen|Popen|os\.exec|commands\.getoutput|Invoke-Expression|\bIEX\b|Start-Process)\b|\beval\s*\(|\bexec\s*\('),  # forge-declared: SEC-3 理由=skill_package 为安全检测器规则字典/其攻击样本测试，非真实执行；下载为 SSRF 逐跳+超限确认的受控下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
     "脚本包含直接执行系统命令/代码的调用，运行时会执行任意命令", False),
    ("download_exec", "critical", "下载内容并直接执行",  # forge-declared: SEC-4 理由=skill_package 为安全检测器规则字典/其攻击样本测试，非真实执行；下载为 SSRF 逐跳+超限确认的受控下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
     re.compile(r'(?i)(curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)\s+[^\r\n]{0,160}'  # forge-declared: SEC-4 理由=检测规则正则字面量本身 出处=AUDIT.md#sec-declared 复审=2026-12-18
                r'\|\s*(ba|pw)?sh\b|'  # forge-declared: SEC-3 理由=检测规则正则字面量本身 出处=AUDIT.md#sec-declared 复审=2026-12-18
                r'(curl|wget)\s+[^\r\n]{0,160}\s+-o\s+[^\r\n]{0,60}\.(py|sh|ps1)\s*[;&]'),  # forge-declared: SEC-4 理由=检测规则正则字面量本身 出处=AUDIT.md#sec-declared 复审=2026-12-18
     "从网络下载内容后直接执行或保存为脚本，可能运行不可信代码", False),
    ("read_secret_file", "critical", "脚本读取敏感文件",
     re.compile(r'(?i)(\.ssh[/\\]|id_rsa|\.aws[/\\]|credentials\.(json|ini|txt)|\.env\b|wallet|mnemonic|seed[-_ ]?phrase|私钥|助记词)'),
     "脚本可能读取 SSH 私钥/AWS 凭证/.env 等敏感文件", True),
    ("secret_harvest", "medium", "涉及敏感凭证字眼",
     re.compile(r'(?i)\b(password|passwd|api[_-]?key|secret|token|credentials?)\b|(密码|支付密码|验证码|银行卡号|身份证号|私钥|密钥|助记词)'),
     "出现敏感凭证相关字眼，请确认是正常配置说明还是要求提供/读取私密信息", False),
    ("exfil", "high", "数据外传",
     re.compile(r'(?i)(发送|上传|提交|传回|外传|post|upload)[^\r\n]{0,60}(到|至|给|to)[^\r\n]{0,90}(http|服务器|server|邮箱|api|接口|url|endpoint)'),
     "可能把本地数据（聊天记录/文件/密码等）发送到外部", False),
    ("prompt_inject", "high", "提示注入特征",
     re.compile(r'(?i)(ignore\s+(previous|prior|above|earlier)\s+(instructions|prompts|rules)|忽略[^\r\n]{0,24}(之前|以上|先前)[^\r\n]{0,12}(指令|提示|规则)|disregard\s+(previous|prior|above)|you\s+are\s+now\s+(free|unconstrained|a\s+new)|输出你的[^\r\n]{0,30}(系统|system)[^\r\n]{0,20}(提示|指令|prompt)|print[^\r\n]{0,40}(system\s+prompt|系统提示|你的指令))'),
     "存在试图操纵 AI 行为或套取系统提示词的文本，安装前请谨慎", False),
    ("ask_secret", "high", "要求用户提供敏感信息",
     re.compile(r'(?i)(请|麻烦|需要|让我|please)[^\r\n]{0,30}(输入|提供|告诉我|发给我|给我|给我发)[^\r\n]{0,50}(密码|验证码|token|api[_-]?key|密钥|私钥|银行卡|支付|口令|账号密码)'),
     "要求用户提供敏感信息，可能是钓鱼/社工", False),
    ("net_in_script", "medium", "脚本含网络访问",
     re.compile(r'(?i)\b(requests\.|urllib|http\.client|socket\.|urlopen|httpx|aiohttp|curl|wget|Invoke-WebRequest|Invoke-RestMethod|ftp\.|smtplib)\b'),  # forge-declared: SEC-4 理由=skill_package 为安全检测器规则字典/其攻击样本测试，非真实执行；下载为 SSRF 逐跳+超限确认的受控下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
     "脚本含网络访问，运行时会外联，请确认目标地址可信", True),
    ("subprocess_use", "medium", "脚本使用 subprocess",
     re.compile(r'(?i)\bsubprocess\b|os\.system|os\.popen|Popen'),
     "脚本会调用系统命令，请确认命令参数可信", True),
    ("cmd_hint", "low", "正文含命令/安装示例",
     re.compile(r'(?i)\b(curl|wget|npm\s+install|pip\s+install|git\s+clone|rm\s+-rf|sudo|chmod\s+777|powershell|cmd\s+/c|bash\s|sh\s|\.\\|docker\s+(run|exec))\b'),  # forge-declared: SEC-3 理由=skill_package 为安全检测器规则字典/其攻击样本测试，非真实执行；下载为 SSRF 逐跳+超限确认的受控下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
     "SKILL.md 中出现命令示例，请确认是使用说明还是诱导执行", False),
    ("suspicious_link", "low", "可疑外部链接",
     re.compile(r'(?i)https?://[^\s"\'<>)\]]+\.(zip|exe|msi|scr|bat|ps1)\b|\b(bit\.ly|t\.cn|goo\.gl|tinyurl\.com|is\.gd)\b'),
     "存在指向可执行/压缩包下载或短链的链接，需人工确认", False),
]

# 级别排序（用于取最高风险）
_AUDIT_LEVEL_ORDER = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


class _NeedConfirmation(Exception):
    """安装来源超出默认资源上限，需要用户确认后才能继续。"""

    def __init__(self, reason, detail):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# ---------- 格式兼容 ----------
def parse_frontmatter(text):
    """解析 SKILL.md 顶部 ---...--- YAML 头，返回 dict（缺则 {}）。兼容 UTF-8 BOM。"""
    if text.startswith('﻿'):
        text = text.lstrip('﻿')
    if not text.startswith('---'):
        return {}
    lines = text.split('\n')
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == '---':
            end = i
            break
    if end is None:
        return {}
    fm = {}
    idx = 1
    while idx < end:
        m = re.match(r'^(name|description)\s*:\s*(.*)$', lines[idx].strip())
        if not m:
            idx += 1
            continue
        key, val = m.group(1), m.group(2).strip()
        if val in ('>', '>-', '>+', '|', '|-', '|+'):
            # YAML 块标量：收集后续缩进行；折叠(>)用空格连接，字面(|)用换行连接
            folded = val.startswith('>')
            body = []
            idx += 1
            while idx < end and (lines[idx].startswith((' ', '\t')) or not lines[idx].strip()):
                if lines[idx].strip():
                    body.append(lines[idx].strip())
                idx += 1
            fm[key] = (' ' if folded else '\n').join(body)
        else:
            fm[key] = val.strip('"\'')
            idx += 1
    return fm


def _as_bool(v):
    """严格布尔解析：字符串 'false'/'0'/'no' 不会被误判为 True。"""
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


def _safe_name(s):
    """把任意来源字符串转成安全的目录名（去路径分隔符、..、控制字符、Windows 保留名）。"""
    s = (s or '').strip().replace('\\', '/').rstrip('/')
    base = os.path.basename(s)
    base = _SAFE_NAME_RE.sub('_', base).strip('._-')
    if not base or base in ('.', '..'):
        return None
    if os.name == 'nt' and base.split('.')[0].lower() in _WIN_RESERVED_NAMES:
        return None
    return base


def _parse_skillhub_search(text):
    """把 skillhub search 的原始输出解析成 [{name, namespace, display, version, description}]。
    仅接受块内包含 `- version:` 或 `- install:` 标记的条目，避免把普通文本误当技能。
    """
    results = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i].strip()
        if raw.startswith('- ') or not raw:
            i += 1
            continue
        m = _SKILLHUB_ITEM_RE.match(raw)
        if not m:
            i += 1
            continue
        namespace, name, display = (m.group(1) or ''), m.group(2), m.group(3)
        version = ''
        desc_parts = []
        marked = False
        j = i + 1
        while j < len(lines):
            nxt = lines[j].strip()
            if nxt.startswith('- install:'):
                marked = True
                j += 1
                continue
            if nxt.startswith('- version:'):
                version = nxt[len('- version:'):].strip()
                marked = True
                j += 1
                continue
            if nxt.startswith('- '):
                desc_parts.append(nxt[2:].strip())
                j += 1
                continue
            if nxt and not _SKILLHUB_ITEM_RE.match(nxt):
                desc_parts.append(nxt)
                j += 1
                continue
            break
        if marked:
            results.append({
                "name": name,
                "namespace": namespace,
                "display": display,
                "version": version,
                "description": ' '.join(desc_parts)[:300],
            })
        i = j
    return results


# ---------- SSRF 预筛选与逐跳下载 ----------
def _ip_is_safe(ip_str):
    """IP 是否可安全访问：拒绝内网/回环/链路本地/保留/组播/云元数据地址。
    归一化 IPv4-mapped IPv6（::ffff:127.0.0.1 实为 127.0.0.1），防 SSRF 绕过。
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast)


# GitHub 官方域白名单：本机加速器常把 github 系列域名在 hosts 里劫持到 127.0.0.1
# 做本地代理，若按解析 IP 判断会被误判为 SSRF。这些域名不可能是攻击者可控的内网/
# 云元数据端点，放行安全；其余域名仍走完整 SSRF 检查（含逐跳重定向校验）。
_GITHUB_ALLOW_HOSTS = (
    "github.com", "www.github.com",
    "api.github.com", "codeload.github.com",
    "raw.githubusercontent.com", "githubusercontent.com",
    "gist.github.com", "github.io",
)


def _host_is_github(host):
    return any(host == g or host.endswith("." + g) for g in _GITHUB_ALLOW_HOSTS)


def _url_safe(raw):
    """URL 输入预筛选：拒绝明显危险形态（内网/回环/保留地址/云元数据）。
    这是预筛选，不是完整 SSRF 防护（DNS rebinding 仍可能绕过，
    重定向由 _download_url_with_redirects 逐跳校验）。  # forge-declared: SEC-4 理由=skill_package 为安全检测器规则字典/其攻击样本测试，非真实执行；下载为 SSRF 逐跳+超限确认的受控下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
    """
    try:
        p = urllib.parse.urlparse(raw)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or host.endswith(".local"):
        return False
    if host in ("169.254.169.254", "100.100.100.200", "metadata.google.internal"):
        return False
    if _host_is_github(host):
        return True
    try:
        for info in socket.getaddrinfo(host, None):
            if not _ip_is_safe(info[4][0]):
                return False
    except Exception:
        return False
    return True


def _download_url_with_redirects(url, max_bytes, confirm_large=False):  # forge-declared: SEC-4 理由=skill_package 为安全检测器规则字典/其攻击样本测试，非真实执行；下载为 SSRF 逐跳+超限确认的受控下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
    """带安全重定向校验的下载：http.client 手动请求，逐跳校验目标 URL。
    - 每跳重定向目标都过 _url_safe（防 302 到内网/云元数据 = SSRF）
    - 最多 5 跳，防重定向死循环
    - Content-Length / 内容 / gzip 解压超限 → _NeedConfirmation
    - TLS 走系统默认校验（不跳过证书）
    """
    current = url
    for _ in range(6):
        if not _url_safe(current):
            raise ValueError(f"下载目标不安全，已拒绝: {current}")
        try:
            p = urllib.parse.urlparse(current)
            host = p.hostname or ""
            port = p.port
        except (ValueError, AttributeError):
            raise ValueError(f"无法解析下载 URL（端口非法）: {current}")
        port = port or (443 if p.scheme == "https" else 80)
        path = (p.path or "/") + (("?" + p.query) if p.query else "")
        try:
            if p.scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=60)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=60)
            conn.request("GET", path, headers={
                "User-Agent": "skill-package-core/1.0",
                "Connection": "close",
                "Accept": "application/zip,application/octet-stream,*/*",
                "Accept-Encoding": "identity",
            })
            resp = conn.getresponse()
        except (ssl.SSLError, OSError, http.client.HTTPException) as e:
            raise ValueError(
                f"下载失败: {e}。下一步：若报证书校验失败，请改用本地路径/zip 导入，"
                "或先手动下载再提供本地路径。")
        if 300 <= resp.status < 400:
            loc = resp.getheader("Location")
            conn.close()
            if not loc:
                raise ValueError(f"重定向响应缺少 Location: {current} (status={resp.status})")
            current = urllib.parse.urljoin(current, loc)
            continue
        if resp.status >= 400:
            conn.close()
            raise ValueError(f"下载失败: HTTP {resp.status} {resp.reason}。下一步：确认链接有效；或手动下载后提供本地路径。")
        cl = resp.getheader("Content-Length")
        if cl:
            try:
                cl_n = int(cl)
            except ValueError:
                cl_n = 0
            if not confirm_large and cl_n > max_bytes:
                conn.close()
                raise _NeedConfirmation(
                    f"下载文件约 {round(cl_n / (1024 * 1024), 1)}MB，超过默认上限 {max_bytes // (1024 * 1024)}MB",
                    {"size_mb": round(cl_n / (1024 * 1024), 1), "source": "Content-Length"},
                )
        try:
            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes and confirm_large:
                data += resp.read()
        except OSError as e:
            conn.close()
            raise ValueError(f"下载中断: {e}。下一步：重试或改用本地路径导入。")
        conn.close()
        enc = (resp.getheader("Content-Encoding") or "").strip().lower()
        if enc == "gzip":
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as gf:
                    out = bytearray()
                    while True:
                        chunk = gf.read(1 << 20)
                        if not chunk:
                            break
                        out.extend(chunk)
                        if len(out) > max_bytes + 1 and not confirm_large:
                            raise _NeedConfirmation(
                                f"下载内容 gzip 解压后超过默认上限 {max_bytes // (1024 * 1024)}MB",
                                {"source": "downloaded-gzip"},  # forge-declared: SEC-4 理由=skill_package 为安全检测器规则字典/其攻击样本测试，非真实执行；下载为 SSRF 逐跳+超限确认的受控下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
                            )
                    data = bytes(out)
            except _NeedConfirmation:
                raise
            except OSError:
                raise ValueError("下载内容 gzip 解压失败。下一步：手动下载后提供本地路径。")
        return data
    raise ValueError(f"重定向次数过多，已拒绝: {url}")


# ---------- 安全审计 ----------
def audit_text(text, where):
    """对一段文本跑全部规则，返回命中列表（合并重复规则）。"""
    hits = []
    for rule_id, level, label, pat, hint, only_scripts in AUDIT_RULES:
        if only_scripts and where == 'SKILL.md':
            continue
        first_line = 0
        count = 0
        for m in pat.finditer(text):
            if count == 0:
                first_line = text.count('\n', 0, m.start()) + 1
            count += 1
        if count:
            hits.append({
                "rule": rule_id, "level": level, "label": label,
                "where": where, "line": first_line, "count": count, "hint": hint,
            })
    return hits


def audit_skill_dir(item):
    """审计单个 skill 目录：SKILL.md + 目录内脚本文件（只读）。item 含 path/name/dirname/kind。"""
    path = item['path']
    issues = []
    smd = os.path.join(path, 'SKILL.md')
    try:
        with open(smd, encoding='utf-8', errors='replace') as f:
            content = f.read(2_000_000)
        if len(content) >= 2_000_000:
            issues.append({"rule": "skillmd_truncated", "level": "medium", "label": "SKILL.md 未完整读取",
                           "where": "SKILL.md", "line": 0, "count": 1,
                           "hint": "SKILL.md 超过 2MB 被截断，未读部分未审计"})
        issues += audit_text(content, 'SKILL.md')
    except FileNotFoundError:
        issues.append({"rule": "no_skill_md", "level": "high", "label": "缺少 SKILL.md",
                       "where": "/", "line": 0, "count": 1,
                       "hint": "该目录没有 SKILL.md，可能不是有效 skill 包"})
    except Exception as e:
        issues.append({"rule": "read_error", "level": "low", "label": "SKILL.md 读取失败",
                       "where": "/", "line": 0, "count": 1,
                       "hint": f"读取 SKILL.md 失败: {e}"})
    scripts = []
    total_files = 0
    total_size = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv', 'venv', '.idea', '.vscode'}]
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                size = os.path.getsize(fp)
            except OSError:
                continue
            total_files += 1
            total_size += size
            ext = os.path.splitext(fn)[1].lower()
            if ext in _AUDIT_SCRIPT_EXTS:
                if size <= _AUDIT_MAX_SCRIPT_BYTES:
                    scripts.append(fp)
                else:
                    issues.append({"rule": "script_too_large", "level": "medium", "label": "脚本超限未审计",
                                   "where": os.path.relpath(fp, path), "line": 0, "count": 1,
                                   "hint": f"脚本 {size} 字节超过单文件上限 {_AUDIT_MAX_SCRIPT_BYTES}，未审计"})
            if total_files > _AUDIT_MAX_FILES:
                break
        if total_files > _AUDIT_MAX_FILES:
            break
    if total_files > _AUDIT_MAX_FILES:
        issues.append({"rule": "too_many_files", "level": "medium", "label": "文件数超限未全审",
                       "where": "/", "line": 0, "count": 1,
                       "hint": f"文件数超过 {_AUDIT_MAX_FILES}，超出部分未审计"})
    if len(scripts) > _AUDIT_MAX_SCRIPTS:
        issues.append({"rule": "too_many_scripts", "level": "medium", "label": "脚本数超限未全审",
                       "where": "/", "line": 0, "count": 1,
                       "hint": f"脚本数 {len(scripts)} 超过 {_AUDIT_MAX_SCRIPTS}，超出部分未审计"})
    for sp in scripts[:_AUDIT_MAX_SCRIPTS]:
        rel = os.path.relpath(sp, path)
        try:
            with open(sp, encoding='utf-8', errors='replace') as f:
                sc = f.read(500_000)
            if len(sc) >= 500_000:
                issues.append({"rule": "script_truncated", "level": "medium", "label": "脚本未完整读取",
                               "where": rel, "line": 0, "count": 1,
                               "hint": "脚本超过 500KB 被截断，未读部分未审计"})
            issues += audit_text(sc, rel)
        except Exception as e:
            issues.append({"rule": "script_read_error", "level": "medium", "label": "脚本读取失败",
                           "where": rel, "line": 0, "count": 1,
                           "hint": f"读取脚本失败: {e}"})
    if total_files > 1500 or total_size > _AUDIT_MAX_TOTAL_BYTES:
        issues.append({"rule": "huge_resource", "level": "low", "label": "资源规模偏大",
                       "where": "/", "line": 0, "count": 1,
                       "hint": f"{total_files} 个文件 / {total_size // (1024 * 1024)}MB"})
    level = 'safe'
    for it in issues:
        if _AUDIT_LEVEL_ORDER.get(it['level'], 0) > _AUDIT_LEVEL_ORDER[level]:
            level = it['level']
    return {
        "name": item.get('name') or item.get('dirname'),
        "path": path,
        "kind": item.get('kind'),
        "level": level,
        "issues": issues,
    }


# ---------- zip 校验与解包 ----------
def find_skill_root(d, depth=0):
    """递归（限深 3 层）找含 SKILL.md 的 skill 根，兼容 `@owner/slug/` 双层嵌套。"""
    if depth > 3:
        return None
    if os.path.isfile(os.path.join(d, 'SKILL.md')):
        return d
    for sub in sorted(os.listdir(d)):
        full = os.path.join(d, sub)
        if os.path.isdir(full):
            r = find_skill_root(full, depth + 1)
            if r:
                return r
    return None


def stage_zip(zip_path, confirm_large=False):
    """校验并解压 skill zip，返回 (skill_root, 目录名, tmp_root)。
    安全硬伤（穿越/盘符/符号链接）直接拒绝；超限转 _NeedConfirmation。
    """
    tmp = tempfile.mkdtemp(prefix='skill_package_install_')
    try:
        with zipfile.ZipFile(zip_path) as zf:
            infos = zf.infolist()
            total = sum(i.file_size for i in infos)
            if not confirm_large:
                if len(infos) > _MAX_ARCHIVE_ENTRIES:
                    raise _NeedConfirmation(
                        f"压缩包包含 {len(infos)} 个文件条目，超过默认上限 {_MAX_ARCHIVE_ENTRIES} 条",
                        {"entries": len(infos), "size_mb": round(total / (1024 * 1024), 1)},
                    )
                if total > _MAX_PACKAGE_BYTES:
                    raise _NeedConfirmation(
                        f"压缩包解压后约 {round(total / (1024 * 1024), 1)}MB，超过默认上限 {_MAX_PACKAGE_BYTES // (1024 * 1024)}MB",
                        {"size_mb": round(total / (1024 * 1024), 1), "entries": len(infos)},
                    )
            for i in infos:
                n = i.filename.replace('\\', '/')
                if n.startswith('/') or n.startswith('../') or '/../' in n or n.endswith('/..'):
                    raise ValueError(f"zip 内含非法路径，已拒绝: {n}")
                if re.match(r'^[a-zA-Z]:', n):
                    raise ValueError(f"zip 内含盘符路径条目，已拒绝: {n}")
                if ((i.external_attr >> 16) & 0o170000) == 0o120000:
                    raise ValueError(f"zip 内含符号链接条目，已拒绝: {n}")
            zf.extractall(tmp)
            if not confirm_large:
                actual = 0
                for dp, _, fns in os.walk(tmp):
                    for fn in fns:
                        try:
                            actual += os.path.getsize(os.path.join(dp, fn))
                        except OSError:
                            pass
                if actual > _MAX_PACKAGE_BYTES:
                    raise _NeedConfirmation(
                        f"压缩包解压后实际占用约 {round(actual / (1024 * 1024), 1)}MB，超过默认上限 {_MAX_PACKAGE_BYTES // (1024 * 1024)}MB",
                        {"size_mb": round(actual / (1024 * 1024), 1), "entries": len(infos)},
                    )
    except zipfile.BadZipFile:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError(f"不是有效的 zip 文件: {zip_path}")
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    root = find_skill_root(tmp)
    if root:
        rel = os.path.relpath(root, tmp)
        name = rel.split(os.sep)[0] if rel != '.' else 'skill'
        return root, name, tmp
    shutil.rmtree(tmp, ignore_errors=True)
    raise ValueError("zip 里找不到含 SKILL.md 的 skill 目录")


def stage_from_local(source, confirm_large=False):
    """本地目录 / .zip → (skill_root, 目录名, tmp_root)。tmp_root 为 None 表示直接引用本地目录。"""
    if not os.path.exists(source):
        raise ValueError(f"本地路径不存在: {source}")
    if os.path.isdir(source):
        if os.path.isfile(os.path.join(source, 'SKILL.md')):
            return source, os.path.basename(source.rstrip('/\\')), None
        for d in sorted(os.listdir(source)):
            full = os.path.join(source, d)
            if os.path.isdir(full) and os.path.isfile(os.path.join(full, 'SKILL.md')):
                return full, d, None
        raise ValueError(f"目录里找不到 SKILL.md: {source}")
    if source.lower().endswith('.zip'):
        return stage_zip(source, confirm_large)
    raise ValueError("本地来源必须是包含 SKILL.md 的目录或 .zip 压缩包")


def stage_from_url(url, confirm_large=False):
    """https 下载 .zip → (skill_root, 目录名, tmp_root)。SSRF 预筛选 + 逐跳校验。"""
    if not _url_safe(url):
        raise ValueError(
            "不安全的 URL，已拒绝（目标解析为内网/回环/保留地址或云元数据端点）。"
            "下一步：如果你用的是代理类网络工具（域名被解析到 127.0.0.1），"
            "请先手动下载该 zip 后提供本地路径导入。")
    tmp = tempfile.mkdtemp(prefix='skill_package_dl_')
    try:
        data = _download_url_with_redirects(url, _MAX_PACKAGE_BYTES, confirm_large)  # forge-declared: SEC-4 理由=skill_package 为安全检测器规则字典/其攻击样本测试，非真实执行；下载为 SSRF 逐跳+超限确认的受控下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
        if not confirm_large and len(data) > _MAX_PACKAGE_BYTES:
            raise _NeedConfirmation(
                f"下载内容约 {round(len(data) / (1024 * 1024), 1)}MB，超过默认上限 {_MAX_PACKAGE_BYTES // (1024 * 1024)}MB",
                {"size_mb": round(len(data) / (1024 * 1024), 1), "source": "downloaded"},  # forge-declared: SEC-4 理由=skill_package 为安全检测器规则字典/其攻击样本测试，非真实执行；下载为 SSRF 逐跳+超限确认的受控下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
            )
        fname = _safe_name(os.path.basename(url.split('?')[0])) or 'skill.zip'
        fpath = os.path.join(tmp, fname)
        with open(fpath, 'wb') as f:
            f.write(data)
        if fname.lower().endswith('.zip') or data[:2] == b'PK':
            return stage_zip(fpath, confirm_large)
        raise ValueError("下载内容不是 .zip 压缩包。请提供 .zip 链接（如 GitHub 的 Download ZIP），或手动下载后提供本地路径。")  # forge-declared: SEC-4 理由=skill_package 为安全检测器规则字典/其攻击样本测试，非真实执行；下载为 SSRF 逐跳+超限确认的受控下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
    finally:
        # 无论成功/失败都清理保存 ZIP 的下载目录；stage_zip 返回的解压目录是另一个 tmp，保留给调用方
        shutil.rmtree(tmp, ignore_errors=True)