# ============================================================
# autostart_skill_compat.ps1
# 自动开启 skill_compat 插件（N.E.K.O 启动后自动 POST start 并等待工具就绪）
# 特性：幂等（插件已就绪则直接退出）、TCP 端口探测 + 注册表轮询、日志、明确退出码
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File autostart_skill_compat.ps1
# 可放入 Windows 启动文件夹（配合 .bat 包装）实现 N.E.K.O 启动后自动开启。
# ============================================================
param(
    [int]$TimeoutSec = 120,
    [string]$LogPath = "$env:LOCALAPPDATA\N.E.K.O\plugins\skill_compat\autostart.log"
)
$ErrorActionPreference = "Stop"
$PROC_NAME  = "N.E.K.O"
$HOST_PORT  = 48916   # 插件宿主 HTTP 端口
$REG_PORT   = 48911   # 工具注册表 HTTP 端口
$PLUGIN_ID  = "skill_compat"
# skill_compat 注册的工具名（出现即视为已启动）
$SC_TOOLS = @("install_skill","list_skills","load_skill","search_skills","skill_status",
              "remove_skill","audit_skill","confirm_consent","skillhub_search","skillhub_install")

function Log([string]$m) {
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $m
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
}

try { $null = New-Item -ItemType Directory -Force -Path (Split-Path $LogPath -Parent) } catch {}

Log "=== autostart begin (timeout=${TimeoutSec}s) ==="
$deadline = (Get-Date).AddSeconds($TimeoutSec)

# 1) 等待 N.E.K.O 进程出现
$procFound = $false
while ((Get-Date) -lt $deadline) {
    if (Get-Process -Name $PROC_NAME -ErrorAction SilentlyContinue) { $procFound = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $procFound) { Log "FAIL: process $PROC_NAME not running within ${TimeoutSec}s"; exit 1 }
Log "process $PROC_NAME detected"

# 2) 等待宿主端口 48916 TCP 可达（不发起 start，避免在已启动时重复触发）
$portOk = $false
while ((Get-Date) -lt $deadline) {
    $c = New-Object Net.Sockets.TcpClient
    try { $c.Connect("127.0.0.1", $HOST_PORT); $portOk = $true } catch { }
    $c.Close()
    if ($portOk) { break }
    Start-Sleep -Seconds 2
}
if (-not $portOk) { Log "FAIL: host port ${HOST_PORT} not reachable within ${TimeoutSec}s"; exit 1 }
Log "host port ${HOST_PORT} reachable"

# 3) 幂等判定：工具注册表里已有 skill_compat 工具 → 已就绪，直接退出
function Get-ScToolHits {
    try {
        $reg = Invoke-RestMethod -Uri "http://127.0.0.1:${REG_PORT}/api/tools" -TimeoutSec 5
        $names = @($reg.tools_by_role.YUI | ForEach-Object { $_.name })
        return @($names | Where-Object { $SC_TOOLS -contains $_ })
    } catch { return @() }
}
$hits = @(Get-ScToolHits)
if ($hits.Count -gt 0) {
    Log "already ready (tools: $($hits -join ',')) - skip start (idempotent)"
    Log "=== autostart ok (already ready) ==="
    exit 0
}
Log "not ready yet - requesting start"

# 4) POST start 开启插件
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:${HOST_PORT}/plugin/${PLUGIN_ID}/start" -Method Post -Body "{}" -ContentType "application/json" -TimeoutSec 10 -UseBasicParsing
    Log "start response: HTTP $($r.StatusCode)"
    if ($r.StatusCode -lt 200 -or $r.StatusCode -ge 400) { Log "FAIL: start returned HTTP $($r.StatusCode)"; exit 1 }
} catch {
    Log "FAIL: start request error: $($_.Exception.Message)"
    exit 1
}

# 5) 轮询工具注册表直到就绪
$ready = $false
while ((Get-Date) -lt $deadline) {
    $hits = @(Get-ScToolHits)
    if ($hits.Count -gt 0) { $ready = $true; Log "tools ready: $($hits -join ',')"; break }
    Start-Sleep -Seconds 2
}
if ($ready) { Log "=== autostart ok ==="; exit 0 }
Log "FAIL: skill_compat tools not registered within ${TimeoutSec}s"
exit 1
