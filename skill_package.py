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
import tempfile
import time
import urllib.parse
import zipfile
import zlib

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
_AUDIT_SCRIPT_EXTS = {'.py', '.sh', '.ps1', '.js', '.mjs', '.cjs', '.bat', '.cmd', '.rb', '.pl', '.lua'}
# 依赖/缓存目录：其中的符号链接属正常安装产物，遍历时跳过（不视为包内容）
_SKIP_DIRS = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', '.idea', '.vscode'}
_AUDIT_MAX_SCRIPT_BYTES = 1_000_000
_AUDIT_MAX_SCRIPTS = 100
_AUDIT_MAX_FILES = 3000
_AUDIT_MAX_TOTAL_BYTES = 60 * 1024 * 1024

AUDIT_RULES = [
    ("exec_shell", "critical", "脚本直接执行系统命令",
     re.compile(r'(?i)\b(os\.system|os\.popen|Popen|commands\.getoutput|Invoke-Expression|\bIEX\b|Start-Process)\b|(?<![\w.])(?:eval|exec)\s*\(|os\.(?:exec\w*|spawn\w*)\s*\('),  # forge-declared: SEC-3 理由=exec_shell 检测规则正则字面量（裸 eval/exec 与 os.exec*/spawn* 族，(?<![\w.]) 排除成员调用），非真实执行 出处=AUDIT.md#sec-declared 复审=2026-12-18
     "脚本包含直接执行系统命令/代码的调用，运行时会执行任意命令", False),
    ("node_exec", "critical", "Node 子进程执行",
     re.compile(r"(?:child_process['\"]\s*\)|\bcp|child_process)\.exec(?:File)?(?:Sync)?\(|\bexecSync\(|\bexecFileSync\("),  # forge-declared: SEC-3 理由=node_exec 检测规则正则字面量（child_process/cp/require 形态 exec*），非真实执行 出处=AUDIT.md#sec-declared 复审=2026-12-18
     "脚本通过 Node child_process 执行命令，运行时会执行任意命令", True),
    ("js_member_exec", "critical", "JS 成员 exec 调用",
     re.compile(r'\.exec(?:Sync|File)?\('),  # forge-declared: SEC-3 理由=js_member_exec 检测规则正则字面量（仅 .js/.mjs/.cjs 生效的成员 exec），非真实执行 出处=AUDIT.md#sec-declared 复审=2026-12-18
     "JS 脚本通过对象成员 exec 执行命令（如 cp.exec），运行时会执行任意命令", True),
    ("download_exec", "critical", "下载内容并直接执行",  # forge-declared: SEC-4 理由=skill_package 为安全检测器规则字典/其攻击样本测试，非真实执行；下载为 SSRF 逐跳+超限确认的受控下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
     re.compile(r'(?i)(curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)\s+[^\r\n]{0,160}'  # forge-declared: SEC-4 理由=检测规则正则字面量本身 出处=AUDIT.md#sec-declared 复审=2026-12-18
                r'\|\s*(ba|pw)?sh\b|'  # forge-declared: SEC-3 理由=检测规则正则字面量本身 出处=AUDIT.md#sec-declared 复审=2026-12-18
                r'(curl|wget)\s+[^\r\n]{0,160}\s+-o\s+[^\r\n]{0,60}\.(py|s'  # forge-declared: SEC-4 理由=download_exec 检测规则正则字面量（-o 保存脚本形状），非真实下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
                r'h|ps1)\s*[;&]'),  # forge-declared: SEC-4 理由=download_exec 检测规则正则字面量续行，非真实下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
     "从网络下载内容后直接执行或保存为脚本，可能运行不可信代码", False),
    ("read_secret_file", "high", "脚本读取敏感文件",
     re.compile(r'(?i)(\.ssh[/\\]|id_rsa|\.aws[/\\]|credentials\.(json|ini|txt)|(?:open|read|cat|type)\([^\r\n]{0,80}\.env|~/\.env|wallet\.dat|mnemonic|seed[-_ ]?phrase|私钥|助记词)'),
     "脚本可能读取 SSH 私钥/AWS 凭证/.env 等敏感文件（路径形态，避免误报 process.env 等）", True),
    ("secret_harvest", "medium", "涉及敏感凭证字眼",
     re.compile(r'(?i)\b(password|passwd|api[_-]?key|secret|token|credentials?)\b|(密码|支付密码|验证码|银行卡号|身份证号|私钥|密钥|助记词)'),
     "出现敏感凭证相关字眼，请确认是正常配置说明还是要求提供/读取私密信息", False),
    ("exfil", "high", "数据外传",
     re.compile(r'(?i)(发送|上传|提交|传回|外传|\bpost\b|\bupload\b)[^\r\n]{0,60}(到|至|给|\bto\b)[^\r\n]{0,90}(http|服务器|server|邮箱|api|接口|url|endpoint)'),
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
     re.compile(r'(?i)\b(curl|wget|npm\s+install|pip\s+install|git\s+clone|rm\s+-rf|sudo|chmod\s+777|powershell|cmd\s+/c|bash\s|sh\s|docker\s+(run|exec))\b'),  # forge-declared: SEC-3 理由=cmd_hint 检测规则正则字面量（命令示例形状），非真实执行 出处=AUDIT.md#sec-declared 复审=2026-12-18
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
    if text.split('\n', 1)[0].strip() != '---':
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
    # 顶层映射缩进：以首个非空、非注释行为准；顶层 name/description 整体缩进也能识别。
    # metadata 这类纯键会切换当前顶层缩进，其下更深的同名 key 不再参与匹配。
    cur_top = None
    for i in range(1, end):
        s = lines[i]
        if not s.strip() or s.lstrip().startswith('#'):
            continue
        cur_top = len(s) - len(s.lstrip(' \t'))
        break
    if cur_top is None:
        return {}
    idx = 1
    while idx < end:
        line = lines[idx]
        indent = len(line) - len(line.lstrip(' \t'))
        stripped = line.strip()
        if not stripped:
            idx += 1
            continue
        # 纯键（`key:`，无值）出现时不高于当前顶层，即视为当前顶层映射的键
        if re.match(r'^[\w-]+\s*:\s*$', stripped) and indent <= cur_top:
            cur_top = indent
        if indent != cur_top:
            idx += 1
            continue
        m = re.match(r'^(name|description)\s*:\s*(.*)$', stripped)
        if not m:
            # 其它顶层键（如 metadata）：跳过其整段缩进子块，避免同名字段覆盖
            idx += 1
            while idx < end:
                s2 = lines[idx]
                ind2 = len(s2) - len(s2.lstrip(' \t'))
                if s2.strip() and ind2 <= cur_top:
                    break
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


# ---------- SSRF 预筛选与逐跳下载（钉 IP 防 rebinding） ----------
_NAT64_NET = ipaddress.ip_network('64:ff9b::/96')
_HARD_MAX_BYTES = 512 * 1024 * 1024  # confirm_large=True 后仍保留的硬上限 512MB（控制内存峰值）
_DL_DEADLINE_S = 300  # 单次下载整体 deadline（跨 hop/跨读块），非仅单次读写超时


def _ip_is_safe(ip_str):
    """IP 是否可安全访问：以 is_global 为主判据（覆盖 is_private 漏掉的 CGNAT/保留段），
    并对 ipv4_mapped / 6to4 / teredo / NAT64 内嵌的 v4 递归判定，防 SSRF 绕过。
    """
    try:
        ip = ipaddress.ip_address(ip_str.split('%')[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.ipv4_mapped or ip.sixtofour
        if embedded is None and ip.teredo is not None:
            embedded = ip.teredo[1]
        if embedded is None and ip in _NAT64_NET:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if embedded is not None:
            return _ip_is_safe(str(embedded))
    return bool(ip.is_global) and not ip.is_multicast


# GitHub 官方域白名单：本机加速器常把 github 系列域名在 hosts 里劫持到 127.0.0.1
# 做本地代理，若按解析 IP 判断会被误判为 SSRF。这些域名不可能是攻击者可控的内网/
# 云元数据端点，放行安全；其余域名仍走完整 SSRF 检查（含逐跳重定向校验）。
# 不含 github.io：任何人可托管内容，不能视为可信官方域。
_GITHUB_ALLOW_HOSTS = (
    "github.com", "www.github.com",
    "api.github.com", "codeload.github.com",
    "raw.githubusercontent.com", "githubusercontent.com",
    "gist.github.com",
)


def _host_is_github(host):
    return any(host == g or host.endswith("." + g) for g in _GITHUB_ALLOW_HOSTS)


def _url_safe(raw):
    """URL 输入预筛选：scheme/端口/字面内网 host/云元数据/白名单。
    DNS 解析与钉 IP 在连接时由 _resolve_safe_ip 单次完成，此处不做解析。
    """
    try:
        p = urllib.parse.urlparse(raw)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    try:
        port = p.port
    except ValueError:
        return False
    if port not in (None, 80, 443):
        return False
    host = (p.hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or host.endswith(".local"):
        return False
    if host in ("169.254.169.254", "100.100.100.200", "metadata.google.internal"):
        return False
    if _host_is_github(host):
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if host.isdigit():  # 十进制整数 IP（如 2130706433 = 127.0.0.1）
            try:
                return _ip_is_safe(str(ipaddress.IPv4Address(int(host))))
            except ValueError:
                return True
        return True  # 域名：连接时 _resolve_safe_ip 单次解析校验
    return _ip_is_safe(host)


def _resolve_safe_ips(host, port):
    """每跳只解析一次；全部 A/AAAA 记录须安全，返回全部已校验 IP（IPv4 优先）供逐个回退连接。
    GitHub 白名单域跳过 IP 判定：兼容 hosts 劫持到 127.0.0.1 的本地加速器（该域不可控内网）。
    其余域名任一记录内网/保留即拒（防 rebinding / 混合 A 记录）。
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as e:
        raise ValueError(f"无法解析主机 {host}: {e}")
    ips = sorted({i[4][0] for i in infos}, key=lambda s: (':' in s, s))
    if not ips:
        raise ValueError(f"无法解析主机 {host}")
    if not _host_is_github(host):
        for ip in ips:
            if not _ip_is_safe(ip):
                raise ValueError(f"下载目标不安全，已拒绝（解析到内网/保留地址）: {host} -> {ip}")
    return ips


def _resolve_safe_ip(host, port):
    """兼容入口：返回首个已校验 IP（IPv4 优先）。"""
    return _resolve_safe_ips(host, port)[0]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """连接到已校验 IP；Host 头保持原主机名。"""

    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._create_connection = lambda addr, t, src=None: socket.create_connection((ip, addr[1]), t, src)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """连接到已校验 IP；SNI/证书仍用原主机名（self.host），钉 IP 不降低 TLS 校验。"""

    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._create_connection = lambda addr, t, src=None: socket.create_connection((ip, addr[1]), t, src)


def _download_url_with_redirects(url, max_bytes, confirm_large=False):  # forge-declared: SEC-4 理由=受控下载入口（逐跳 SSRF 预筛选+钉 IP+超限确认+硬上限），非任意下载 出处=AUDIT.md#sec-declared 复审=2026-12-18
    """带安全重定向校验的下载：逐跳 _url_safe 预筛选 + _resolve_safe_ip 单次解析钉 IP。
    - 每跳重定向目标都过 _url_safe；初始 https 不允许降级 http；端口限 80/443
    - 最多 5 跳，防重定向死循环
    - 未确认超 max_bytes → _NeedConfirmation；确认后仍受 _HARD_MAX_BYTES 硬上限
    - TLS 走系统默认校验（不跳过证书）；连接用已校验 IP，防 DNS rebinding
    """
    initial_scheme = urllib.parse.urlparse(url).scheme
    current = url
    start = time.monotonic()
    for _ in range(6):
        if time.monotonic() - start > _DL_DEADLINE_S:
            raise ValueError("下载整体超时，已拒绝")
        try:
            p = urllib.parse.urlparse(current)
            host = p.hostname or ""
            port = p.port
        except (ValueError, AttributeError):
            raise ValueError(f"无法解析下载 URL（端口非法）: {current}")
        if not _url_safe(current):
            raise ValueError(f"下载目标不安全，已拒绝: {current}")
        if initial_scheme == "https" and p.scheme != "https":
            raise ValueError(f"重定向降级 https→http，已拒绝: {current}")
        port = port or (443 if p.scheme == "https" else 80)
        path = (p.path or "/") + (("?" + p.query) if p.query else "")
        ips = _resolve_safe_ips(host, port)
        conn = None
        resp = None
        last_err = None
        for ip in ips:  # 双栈回退：逐个已校验 IP 尝试，IPv4 优先
            remaining = _DL_DEADLINE_S - (time.monotonic() - start)
            if remaining <= 0:
                raise ValueError("下载整体超时，已拒绝")
            sock_timeout = max(1.0, min(60.0, remaining))  # 每次尝试共享同一绝对截止时间
            cand = (_PinnedHTTPSConnection(host, port, ip, sock_timeout) if p.scheme == "https"
                    else _PinnedHTTPConnection(host, port, ip, sock_timeout))
            try:
                cand.request("GET", path, headers={
                    "User-Agent": "skill-package-core/1.0",
                    "Connection": "close",
                    "Accept": "application/zip,application/octet-stream,*/*",
                    "Accept-Encoding": "identity",
                })
                resp = cand.getresponse()
                conn = cand
                break
            except (OSError, http.client.HTTPException) as e:
                last_err = e
                cand.close()
        if conn is None:
            raise ValueError(
                f"下载失败: {last_err}。下一步：若报证书校验失败，请改用本地路径/zip 导入，"
                "或先手动下载再提供本地路径。")
        try:
            if 300 <= resp.status < 400:
                loc = resp.getheader("Location")
                if not loc:
                    raise ValueError(f"重定向响应缺少 Location: {current} (status={resp.status})")
                current = urllib.parse.urljoin(current, loc)
                continue
            if resp.status >= 400:
                raise ValueError(f"下载失败: HTTP {resp.status} {resp.reason}。下一步：确认链接有效；或手动下载后提供本地路径。")
            limit = _HARD_MAX_BYTES if confirm_large else max_bytes
            cl = resp.getheader("Content-Length")
            if cl:
                try:
                    cl_n = int(cl)
                except ValueError:
                    cl_n = 0
                if cl_n > limit:
                    if confirm_large:
                        raise ValueError("下载超过硬上限 512MB，已拒绝")
                    raise _NeedConfirmation(
                        f"下载文件约 {round(cl_n / (1024 * 1024), 1)}MB，超过默认上限 {max_bytes // (1024 * 1024)}MB",
                        {"size_mb": round(cl_n / (1024 * 1024), 1), "source": "Content-Length"},
                    )
            try:
                buf = bytearray()
                while True:
                    remaining = _DL_DEADLINE_S - (time.monotonic() - start)
                    if remaining <= 0:
                        raise ValueError("下载整体超时，已拒绝")
                    try:  # 已阻塞的读也受剩余预算约束（urllib3/http.client 底层 socket）
                        resp.fp.raw._sock.settimeout(max(0.1, remaining))
                    except AttributeError:
                        pass
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    if len(buf) > limit:
                        break
                data = buf  # 直接返回 bytearray，避免 bytes(buf) 再复制一份整包
            except OSError as e:
                raise ValueError(f"下载中断: {e}。下一步：重试或改用本地路径导入。")
            if len(data) > limit:
                if confirm_large:
                    raise ValueError("下载超过硬上限 512MB，已拒绝")
                raise _NeedConfirmation(
                    f"下载内容约 {round(len(data) / (1024 * 1024), 1)}MB，超过默认上限 {max_bytes // (1024 * 1024)}MB",
                    {"size_mb": round(len(data) / (1024 * 1024), 1), "source": "downloaded"},  # forge-declared: SEC-4 理由=超限提示的来源元数据字段，非网络调用 出处=AUDIT.md#sec-declared 复审=2026-12-18
                )
            enc = (resp.getheader("Content-Encoding") or "").strip().lower()
            if enc == "gzip":
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gf:
                        out = bytearray()
                        while True:
                            if time.monotonic() - start > _DL_DEADLINE_S:
                                raise ValueError("下载整体超时，已拒绝")
                            chunk = gf.read(1 << 20)
                            if not chunk:
                                break
                            out.extend(chunk)
                            if len(out) > limit:
                                if confirm_large:
                                    raise ValueError("gzip 解压超过硬上限 512MB，已拒绝")
                                raise _NeedConfirmation(
                                    f"下载内容 gzip 解压后超过默认上限 {max_bytes // (1024 * 1024)}MB",
                                    {"source": "downloaded-gzip"},  # forge-declared: SEC-4 理由=gzip 超限提示的来源元数据字段，非网络调用 出处=AUDIT.md#sec-declared 复审=2026-12-18
                                )
                        data = out  # 避免 bytes(out) 再复制一份
                except _NeedConfirmation:
                    raise
                except (OSError, EOFError, zlib.error):
                    raise ValueError("下载内容 gzip 解压失败。下一步：手动下载后提供本地路径。")
            return data
        finally:
            try:  # 先关 resp：未读完的响应正文可能持有底层流，conn.close() 不一定释放
                if resp is not None:
                    resp.close()
            finally:
                conn.close()
    raise ValueError(f"重定向次数过多，已拒绝: {url}")


# ---------- 安全审计 ----------
def audit_text(text, where):
    """对一段文本跑全部规则，返回命中列表（合并重复规则）。"""
    hits = []
    for rule_id, level, label, pat, hint, only_scripts in AUDIT_RULES:
        if only_scripts and where == 'SKILL.md':
            continue
        if rule_id == 'js_member_exec' and not where.lower().endswith(('.js', '.mjs', '.cjs')):
            continue  # 成员 exec 仅在 JS 文件判定，避免 .py 的 re/regex 误报
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
        keep = []
        for d in dirs:
            full = os.path.join(root, d)
            if d in _SKIP_DIRS:
                continue
            if os.path.islink(full):
                # 目录链接：记入报告后跳过，不跟随（否则可能读包外文件且静默漏审）
                issues.append({"rule": "symlink_skipped", "level": "medium", "label": "符号链接未审计",
                               "where": os.path.relpath(full, path), "line": 0, "count": 1,
                               "hint": "目录符号链接可能指向包外文件，未读取未审计"})
                continue
            keep.append(d)
        dirs[:] = keep
        for fn in files:
            fp = os.path.join(root, fn)
            if os.path.islink(fp):
                issues.append({"rule": "symlink_skipped", "level": "medium", "label": "符号链接未审计",
                               "where": os.path.relpath(fp, path), "line": 0, "count": 1,
                               "hint": "符号链接可能指向包外文件，未读取未审计"})
                continue
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
        if sub in _SKIP_DIRS:
            continue
        full = os.path.join(d, sub)
        if os.path.islink(full):  # 不把目录链接当技能根（避免跟随到包外）
            continue
        if os.path.isdir(full):
            r = find_skill_root(full, depth + 1)
            if r:
                return r
    return None


def stage_zip(zip_path, confirm_large=False):
    """校验并解压 skill zip，返回 (skill_root, 目录名, tmp_root)。
    安全硬伤（穿越/盘符/符号链接）直接拒绝；超限转 _NeedConfirmation。
    逐成员流式写、边写边累计实际字节，超上限立即中止并清理（防"声明小实际大"）；
    confirm_large=True 仍受 _HARD_MAX_BYTES 硬上限。
    嵌套 `@owner/slug/` 返回 `owner__slug` 作目录名，避免同作者多 skill 互相覆盖。
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
            cap = _HARD_MAX_BYTES if confirm_large else _MAX_PACKAGE_BYTES
            actual = 0
            for i in infos:
                n = i.filename.replace('\\', '/')
                if n.startswith('/') or n.startswith('../') or '/../' in n or n.endswith('/..'):
                    raise ValueError(f"zip 内含非法路径，已拒绝: {n}")
                if re.match(r'^[a-zA-Z]:', n):
                    raise ValueError(f"zip 内含盘符路径条目，已拒绝: {n}")
                if ((i.external_attr >> 16) & 0o170000) == 0o120000:
                    raise ValueError(f"zip 内含符号链接条目，已拒绝: {n}")
                target = os.path.join(tmp, n)
                if i.is_dir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(i) as src, open(target, 'wb') as dst:
                    while True:
                        chunk = src.read(1 << 20)
                        if not chunk:
                            break
                        actual += len(chunk)
                        if actual > cap:
                            if confirm_large:
                                raise ValueError("解压超过硬上限 512MB，已拒绝")
                            raise _NeedConfirmation(
                                f"压缩包解压后实际占用约 {round(actual / (1024 * 1024), 1)}MB，超过默认上限 {_MAX_PACKAGE_BYTES // (1024 * 1024)}MB",
                                {"size_mb": round(actual / (1024 * 1024), 1), "entries": len(infos)},
                            )
                        dst.write(chunk)
        root = find_skill_root(tmp)
        if root:
            rel = os.path.relpath(root, tmp)
            parts = rel.split(os.sep) if rel != '.' else []
            if parts and parts[0].startswith('@') and len(parts) >= 2:
                name = parts[0][1:] + '__' + parts[1]
            else:
                name = parts[0] if parts else 'skill'
            return root, name, tmp
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError("zip 里找不到含 SKILL.md 的 skill 目录")
    except zipfile.BadZipFile:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError(f"不是有效的 zip 文件: {zip_path}")
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def _reject_symlinks(root):
    """本地目录含符号链接一律拒绝（与 zip 侧"符号链接硬拒绝"口径一致，防读包外文件）。
    跳过依赖/缓存目录（node_modules/.venv 等的 .bin 链接属正常安装产物）。
    注：Py<3.12 的 Windows junction 不被 os.path.islink 识别，属已知平台局限。
    """
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in {'.git', '__pycache__', 'node_modules', '.venv', 'venv'}]
        for n in dns + fns:
            if os.path.islink(os.path.join(dp, n)):
                raise ValueError(f"本地目录含符号链接，已拒绝: {os.path.join(dp, n)}")


def stage_from_local(source, confirm_large=False):
    """本地目录 / .zip → (skill_root, 目录名, tmp_root)。tmp_root 为 None 表示直接引用本地目录。"""
    if not os.path.exists(source):
        raise ValueError(f"本地路径不存在: {source}")
    if os.path.isdir(source):
        _reject_symlinks(source)
        if os.path.isfile(os.path.join(source, 'SKILL.md')):
            return source, os.path.basename(source.rstrip('/\\')), None
        for d in sorted(os.listdir(source)):
            if d in _SKIP_DIRS:
                continue
            full = os.path.join(source, d)
            if os.path.islink(full):  # 不接受目录链接作为技能根
                continue
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
        raise ValueError("下载内容不是 .zip 压缩包。请提供 .zip 链接（如 GitHub 的 Download ZIP），或手动下载后提供本地路径。")  # forge-declared: SEC-4 理由=报错提示文案含 Download 字样（引导用户手动下载），非网络调用 出处=AUDIT.md#sec-declared 复审=2026-12-18
    finally:
        # 无论成功/失败都清理保存 ZIP 的下载目录；stage_zip 返回的解压目录是另一个 tmp，保留给调用方
        shutil.rmtree(tmp, ignore_errors=True)