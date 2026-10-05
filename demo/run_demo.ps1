# Heisenberg demo driver (PowerShell) — the thing deskhand screen-records on a VM.
# Same story as run_demo.py, but native so it needs no Python on the box:
# an agent diagnoses a hung process from a dump, then a machine change is
# blocked by the Critical-box policy until a human approves it out of band,
# and is reverted. Every 'agent' line is a real Heisenberg tool call over MCP.
#
# Expects heisenberg.exe and patient.exe in the same folder as this script.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $here 'heisenberg.exe'
$patientExe = Join-Path $here 'patient.exe'
$pauseSec = if ($env:DEMO_PAUSE) { [double]$env:DEMO_PAUSE } else { 0.7 }

# A throwaway state root + the Microsoft symbol server so cdb resolves ntdll.
# Honour a preset HEISENBERG_HOME (so a side-by-side log viewer can tail the same
# calls.jsonl); otherwise use a fresh temp root.
$home2 = if ($env:HEISENBERG_HOME) { $env:HEISENBERG_HOME } else { Join-Path $env:TEMP ("hbdemo_" + [guid]::NewGuid().ToString('N').Substring(0,8)) }
New-Item -ItemType Directory -Force $home2 | Out-Null
$env:HEISENBERG_HOME = $home2
Remove-Item (Join-Path $home2 'calls.jsonl') -EA SilentlyContinue  # fresh tool-call log for this run
$env:RUST_LOG = 'error'
# Stable symbol cache so a repeated run doesn't re-download ntdll symbols.
$symCache = if ($env:DEMO_SYMCACHE) { $env:DEMO_SYMCACHE } else { Join-Path $env:TEMP 'hb_symcache' }
New-Item -ItemType Directory -Force $symCache | Out-Null
$env:_NT_SYMBOL_PATH = "srv*$symCache*https://msdl.microsoft.com/download/symbols"
Remove-Item Env:HEISENBERG_POLICY -EA SilentlyContinue
Remove-Item Env:HEISENBERG_TRUST_UNSIGNED -EA SilentlyContinue

# If the classic Debugging Tools aren't on PATH but the modern WinDbg (Store)
# package is installed, point the tool locator at its bundled cdb so the dump
# analysis works on a box that only has the Store WinDbg.
if (-not $env:HEISENBERG_TOOLS) {
    try {
        $wd = Get-AppxPackage *WinDbg* | Select-Object -First 1 -ExpandProperty InstallLocation
        if ($wd -and (Test-Path (Join-Path $wd 'amd64\cdb.exe'))) { $env:HEISENBERG_TOOLS = (Join-Path $wd 'amd64') }
    } catch {}
}

try { $Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(120, 3000) } catch {}
try { $Host.UI.RawUI.WindowSize = New-Object Management.Automation.Host.Size(120, 34) } catch {}
# Maximize the console so the recording is a clean full-screen terminal (the flat
# black background also compresses far better than the desktop wallpaper).
try {
    Add-Type -Name Win -Namespace D -MemberDefinition '[DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow(); [DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr h, int n);'
    [D.Win]::ShowWindow([D.Win]::GetConsoleWindow(), 3) | Out-Null
    Start-Sleep -Milliseconds 300
} catch {}
Clear-Host

function Pause-Beat([double]$m = 1.0) { if ($pauseSec -gt 0) { Start-Sleep -Milliseconds ([int]($pauseSec * 1000 * $m)) } }
function Section($n, $t) {
    Write-Host ""
    Write-Host ("-" * 78) -ForegroundColor Cyan
    Write-Host " $n. $t" -ForegroundColor Cyan
    Write-Host ("-" * 78) -ForegroundColor Cyan
    Pause-Beat 0.6
}
function Agent($m)    { Write-Host "  agent > " -ForegroundColor Magenta -NoNewline; Write-Host $m; Pause-Beat }
function Operator($m) { Write-Host "  operator # " -ForegroundColor Yellow -NoNewline; Write-Host $m; Pause-Beat }
function Ok($m)       { Write-Host "         [ok] " -ForegroundColor Green -NoNewline; Write-Host $m; Pause-Beat }
function Blocked($m)  { Write-Host "         [blocked] " -ForegroundColor Red -NoNewline; Write-Host $m; Pause-Beat }
function Dim($m)      { Write-Host "    $m" -ForegroundColor DarkGray }

# --- MCP client over stdio (synchronous: one request -> one response line) ---
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe
$psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true
$psi.UseShellExecute = $false; $psi.WorkingDirectory = $here
$srv = [System.Diagnostics.Process]::Start($psi)
$script:id = 1
function Send($o) { $srv.StandardInput.WriteLine(($o | ConvertTo-Json -Compress -Depth 12)) }
function Tool($name, $a) {
    $script:id++
    Send @{ jsonrpc = '2.0'; id = $script:id; method = 'tools/call'; params = @{ name = $name; arguments = $a } }
    $line = $srv.StandardOutput.ReadLine()
    if ([string]::IsNullOrEmpty($line)) { return $null }
    return (($line | ConvertFrom-Json).result.content[0].text | ConvertFrom-Json)
}

Write-Host "Heisenberg - live debugging demo" -ForegroundColor White
Dim "an agent diagnoses a hung process, then hits the safety spine"
Pause-Beat

Send @{ jsonrpc = '2.0'; id = 1; method = 'initialize'; params = @{ protocolVersion = '2024-11-05'; capabilities = @{}; clientInfo = @{ name = 'demo'; version = '0' } } }
[void]$srv.StandardOutput.ReadLine()
Send @{ jsonrpc = '2.0'; method = 'notifications/initialized' }

# 1. Deploy check -----------------------------------------------------------
Section 1 "Drop the binary on the box and check it's wired up"
Dim "$ heisenberg selfcheck"
& $exe selfcheck | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
Pause-Beat

# 2. The patient ------------------------------------------------------------
Section 2 "A process is hung"
$patient = Start-Process -FilePath $patientExe -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 800
Dim "launched patient.exe -> two worker threads take locks A and B in opposite order"
Write-Host "    the app stopped responding. pid " -NoNewline; Write-Host $patient.Id -ForegroundColor White
Pause-Beat

$cleanupTool = $null
try {
    # 3. Investigate --------------------------------------------------------
    Section 3 "The agent investigates"
    $who = Tool 'env.check' @{}
    $admin = [bool]$who.data.isAdmin
    Agent ("checking the environment... " + $who.data.os.name + " build " + $who.data.os.build + ", " + $(if ($admin) { "elevated" } else { "not elevated" }))

    Agent "capturing a full memory dump of the hung process (pid $($patient.Id))..."
    $cap = Tool 'dump.capture' @{ pid = $patient.Id; full = $true }
    if (-not $cap.ok) { Blocked "capture failed: $($cap.error.kind)"; throw "cap" }
    $dumpId = $cap.data.dumpId
    Ok $cap.summary

    Agent "analyzing the dump for lock contention (!locks, !cs, all stacks)..."
    $an = Tool 'analyze.deadlock' @{ dump = $dumpId }
    if ($an.ok) {
        Ok $an.summary
        $raw = [string]$an.data.raw
        $syms = [System.Collections.Generic.List[string]]::new()
        foreach ($m in [regex]::Matches($raw, '[A-Za-z_]\w*![\w:~]+(?:\+0x[0-9a-fA-F]+)?')) {
            $t = $m.Value
            if (($t -match 'Wait|Critical|RtlpWait') -and -not $syms.Contains($t)) { $syms.Add($t) }
        }
        Write-Host "    evidence:" -ForegroundColor White
        foreach ($s in ($syms | Select-Object -First 4)) { Dim "threads parked in $s" }
        Agent "root cause: two worker threads deadlocked AB-BA - each holds one critical section and blocks forever on the other."
    } else {
        Blocked "analyze: $($an.error.kind) (cdb / Debugging Tools not staged on this box)"
    }

    # 4. The gate -----------------------------------------------------------
    Section 4 "The agent proposes a machine change - and the box says no"
    if ($admin) {
        $tool = 'gflags.set'; $toolArgs = @{ image = 'patient.exe' }; $token = 'enable-page-heap'
        $what = "enable Full Page Heap on patient.exe to catch heap corruption on the next run"
    } else {
        $tool = 'symbols.configure'; $toolArgs = @{ path = 'srv*C:\symbols*https://msdl.microsoft.com/download/symbols' }; $token = 'set-symbol-path'
        $what = "persist the Microsoft symbol path so the team can re-analyze this dump"
    }
    Agent "I'd like to $what."
    $b = Tool $tool $toolArgs
    Blocked "$tool`: $($b.error.kind) - $($b.error.message)"
    Dim "this box is unclassified -> fail-safe Critical -> every mutation needs a human."
    Pause-Beat

    # 5. Human approval -----------------------------------------------------
    Section 5 "A human approves it out of band"
    Operator "a person on the box runs:  heisenberg approve $tool"
    Dim "$ heisenberg approve $tool"
    & $exe approve $tool | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    Pause-Beat
    Agent "retrying $tool now that approval was granted..."
    $done = Tool $tool ($toolArgs + @{ confirm = $token })
    if ($done.ok) { Ok $done.summary; $cleanupTool = $tool } else { Blocked "still blocked: $($done.error.kind)" }

    # 6. Reversible ---------------------------------------------------------
    Section 6 "Every change is reversible"
    $ch = Tool 'changes.list' @{}
    $entries = @($ch.data.changes)
    if ($entries.Count -gt 0) {
        $last = $entries[-1]
        Write-Host "    ledger: " -NoNewline; Write-Host $last.tool -ForegroundColor White -NoNewline
        Write-Host " -> $($last.status) (id $($last.id))"
        Pause-Beat
        Agent "rolling the change back..."
        $rev = Tool 'changes.revert' @{ id = $last.id }
        if ($rev.ok) { Ok $rev.summary; $cleanupTool = $null } else { Blocked "revert failed: $($rev.error.kind)" }
    } else { Dim "(no ledger entry to revert)" }

    # 7. Wrap ---------------------------------------------------------------
    Section 7 "Done"
    Write-Host "    diagnosed a real deadlock from a dump, proposed a fix, kept a human in control," -ForegroundColor Green
    Write-Host "    and left the box as we found it." -ForegroundColor Green
    Pause-Beat 0.5
}
finally {
    if ($cleanupTool) { try { $ch = Tool 'changes.list' @{}; foreach ($e in $ch.data.changes) { if ($e.status -eq 'applied') { Tool 'changes.revert' @{ id = $e.id } | Out-Null } } } catch {} }
    try { $srv.StandardInput.Close(); [void]$srv.WaitForExit(4000) } catch {}
    try { Stop-Process -Id $patient.Id -Force -EA SilentlyContinue } catch {}
}
# Marker so the recorder knows the run finished.
New-Item -ItemType File -Force (Join-Path $here 'demo_done.flag') | Out-Null
