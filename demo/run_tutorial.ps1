# Heisenberg demo - TUTORIAL version: slower, with explanations. Every "agent"
# line is a real Heisenberg tool call over MCP; the "note" callouts explain what
# is happening (especially that analyze.deadlock runs cdb, and what cdb printed).
# Record this side-by-side with logview.ps1.

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $here 'heisenberg.exe'
$patientExe = Join-Path $here 'patient.exe'
$pauseSec = if ($env:DEMO_PAUSE) { [double]$env:DEMO_PAUSE } else { 2.2 }

$home2 = if ($env:HEISENBERG_HOME) { $env:HEISENBERG_HOME } else { Join-Path $env:TEMP ("hbtut_" + [guid]::NewGuid().ToString('N').Substring(0,8)) }
New-Item -ItemType Directory -Force $home2 | Out-Null
$env:HEISENBERG_HOME = $home2
$env:RUST_LOG = 'error'
Remove-Item (Join-Path $home2 'calls.jsonl') -EA SilentlyContinue
$symCache = if ($env:DEMO_SYMCACHE) { $env:DEMO_SYMCACHE } else { Join-Path $env:TEMP 'hb_symcache' }
New-Item -ItemType Directory -Force $symCache | Out-Null
$env:_NT_SYMBOL_PATH = "srv*$symCache*https://msdl.microsoft.com/download/symbols"
Remove-Item Env:HEISENBERG_POLICY -EA SilentlyContinue
Remove-Item Env:HEISENBERG_TRUST_UNSIGNED -EA SilentlyContinue
if (-not $env:HEISENBERG_TOOLS) {
    try {
        $wd = Get-AppxPackage *WinDbg* | Select-Object -First 1 -ExpandProperty InstallLocation
        if ($wd -and (Test-Path (Join-Path $wd 'amd64\cdb.exe'))) { $env:HEISENBERG_TOOLS = (Join-Path $wd 'amd64') }
    } catch {}
}
try {
    Add-Type -Name Win -Namespace D -MemberDefinition '[DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow(); [DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr h, int n);'
    [D.Win]::ShowWindow([D.Win]::GetConsoleWindow(), 3) | Out-Null; Start-Sleep -Milliseconds 300
} catch {}
try { $Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(120, 6000) } catch {}
Clear-Host

$CY='Cyan'; $MA='Magenta'; $YE='Yellow'; $GR='Green'; $RE='Red'; $GY='Gray'; $DG='DarkGray'; $WH='White'
function Pause-Beat([double]$m = 1.0) { if ($pauseSec -gt 0) { Start-Sleep -Milliseconds ([int]($pauseSec * 1000 * $m)) } }
function Section($n, $t) {
    Write-Host ""; Write-Host ("=" * 76) -ForegroundColor $CY
    Write-Host ("  {0}.  {1}" -f $n, $t) -ForegroundColor $CY
    Write-Host ("=" * 76) -ForegroundColor $CY; Pause-Beat 0.8
}
function Note($lines) {   # an explanation "pop-up" callout
    Write-Host ""
    Write-Host "  +- why / what ------------------------------------------------------+" -ForegroundColor $YE
    foreach ($l in @($lines)) { Write-Host ("  | " + $l) -ForegroundColor $YE }
    Write-Host "  +-------------------------------------------------------------------+" -ForegroundColor $YE
    Pause-Beat 1.3
}
function Agent($m)    { Write-Host "  agent > " -ForegroundColor $MA -NoNewline; Write-Host $m; Pause-Beat }
function Ok($m)       { Write-Host "          [ok] " -ForegroundColor $GR -NoNewline; Write-Host $m; Pause-Beat }
function Blocked($m)  { Write-Host "          [blocked] " -ForegroundColor $RE -NoNewline; Write-Host $m; Pause-Beat }
function Operator($m) { Write-Host "  operator # " -ForegroundColor $YE -NoNewline; Write-Host $m; Pause-Beat }
function Dim($m)      { Write-Host ("     " + $m) -ForegroundColor $DG }
function Raw($m)      { Write-Host ("       " + $m) -ForegroundColor $GY }

# MCP client
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true
$psi.UseShellExecute = $false; $psi.WorkingDirectory = $here
$srv = [System.Diagnostics.Process]::Start($psi)
$script:id = 1
function Send($o) { $srv.StandardInput.WriteLine(($o | ConvertTo-Json -Compress -Depth 12)) }
function Tool($name, $a) {
    $script:id++
    Send @{ jsonrpc='2.0'; id=$script:id; method='tools/call'; params=@{ name=$name; arguments=$a } }
    $line = $srv.StandardOutput.ReadLine()
    if ([string]::IsNullOrEmpty($line)) { return $null }
    return (($line | ConvertFrom-Json).result.content[0].text | ConvertFrom-Json)
}
Send @{ jsonrpc='2.0'; id=1; method='initialize'; params=@{ protocolVersion='2024-11-05'; capabilities=@{}; clientInfo=@{ name='demo'; version='0' } } }
[void]$srv.StandardOutput.ReadLine()
Send @{ jsonrpc='2.0'; method='notifications/initialized' }

Write-Host "  HEISENBERG - debugging a hung Windows process, step by step" -ForegroundColor $WH
Dim "Heisenberg is an MCP server that wraps Microsoft's own debugging tools so an"
Dim "agent can drive them safely. The log pane on the right is every tool-call result."
Pause-Beat 1.5

try {
    # 1 --------------------------------------------------------------------
    Section 1 "The patient: a process that has hung"
    $patient = Start-Process -FilePath $patientExe -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 900
    Write-Host "    started patient.exe, pid " -NoNewline; Write-Host $patient.Id -ForegroundColor $WH
    Note @(
        "patient.exe spawns two worker threads that each take two locks (A and B)",
        "in the OPPOSITE order. Thread 1: A then B. Thread 2: B then A. Each ends up",
        "holding one lock and waiting forever for the other -> a classic deadlock,",
        "so the process stops responding."
    )

    # 2 --------------------------------------------------------------------
    Section 2 "Capture a memory dump of the frozen process"
    Agent "capturing a full user-mode dump of pid $($patient.Id)..."
    $cap = Tool 'dump.capture' @{ pid = $patient.Id; full = $true }
    if (-not $cap.ok) { Blocked "capture failed: $($cap.error.kind)"; throw "cap" }
    $dumpId = $cap.data.dumpId
    Ok $cap.summary
    Note @(
        "A dump is a frozen snapshot of the process's memory + every thread's stack.",
        "Heisenberg uses Sysinternals ProcDump if present, else the in-box comsvcs",
        "MiniDump (rundll32). The .dmp is tagged HIGH-SENSITIVITY (it can contain",
        "secrets), so it is not moved off the box without review."
    )

    # 3 --------------------------------------------------------------------
    Section 3 "Analyze the dump - this runs cdb (the Windows debugger)"
    Note @(
        "analyze.deadlock opens the dump in cdb.exe -- the command-LINE debugger from",
        "Microsoft's 'Debugging Tools for Windows' (the same debug engine as the",
        "WinDbg GUI). Heisenberg scripts it with these debugger commands:",
        "   !locks     - held critical sections and who owns them",
        "   !cs -l     - locked critical sections",
        "   !syncblk   - .NET monitor locks",
        "   ~*kb       - the call stack of EVERY thread"
    )
    Agent "running cdb on the dump (!locks; !cs -l; !syncblk; ~*kb)..."
    $an = Tool 'analyze.deadlock' @{ dump = $dumpId }
    if ($an.ok) {
        Ok $an.summary
        Write-Host "    the exact debugger command Heisenberg ran:" -ForegroundColor $WH
        $cmds = @($an.commands)
        if ($cmds.Count -gt 0) { Dim ("$ " + ([string]$cmds[0])) }
        Write-Host "    what cdb printed (excerpt the agent read):" -ForegroundColor $WH
        $raw = [string]$an.data.raw
        $picked = 0
        foreach ($line in ($raw -split "`n")) {
            $s = $line.Trim()
            if ($s -and ($s -match 'CritSec|OwningThread|Owning thread|Lock|WaitFor|RtlEnterCritical|RtlpWait|NtWaitFor')) {
                Raw ($s.Substring(0, [Math]::Min(80, $s.Length)))
                $picked++; if ($picked -ge 10) { break }
            }
        }
        if ($picked -eq 0) { foreach ($line in (($raw -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 8)) { Raw $line.Trim() } }
        Note @(
            "Reading that: two worker threads are both stuck in RtlEnterCriticalSection /",
            "a wait, each OWNING one critical section and WAITING on the other. That is",
            "the A-B / B-A lock-order inversion -> the deadlock, confirmed from the dump."
        )
        Agent "root cause: AB-BA deadlock between the two worker threads."
    } else {
        Blocked "analyze: $($an.error.kind) (cdb / Debugging Tools not on this box)"
    }

    # 4 --------------------------------------------------------------------
    Section 4 "Propose a fix - and watch the safety policy stop it"
    Agent "I'd like to enable Full Page Heap on patient.exe (via gflags) to catch heap bugs next run."
    $b = Tool 'gflags.set' @{ image = 'patient.exe' }
    Blocked "gflags.set: $($b.error.kind) - $($b.error.message)"
    Note @(
        "gflags.set CHANGES the machine (an IFEO registry key). This box is",
        "unclassified, so Heisenberg fails safe to 'Critical' - where every mutation",
        "needs out-of-band HUMAN approval. The agent literally cannot do it alone."
    )

    # 5 --------------------------------------------------------------------
    Section 5 "A human approves it, out of band"
    Operator "a person on the box runs:  heisenberg approve gflags.set"
    Dim "$ heisenberg approve gflags.set"
    & $exe approve gflags.set | ForEach-Object { Raw $_ }
    Pause-Beat
    Agent "retrying gflags.set now that a one-shot approval was granted..."
    $done = Tool 'gflags.set' @{ image = 'patient.exe'; confirm = 'enable-page-heap' }
    if ($done.ok) { Ok $done.summary }
    Note @(
        "The approval is a one-shot, 15-minute grant written by a separate process.",
        "The agent can never approve itself through the protocol."
    )

    # 6 --------------------------------------------------------------------
    Section 6 "Every change is reversible"
    $ch = Tool 'changes.list' @{}
    $entries = @($ch.data.changes)
    if ($entries.Count -gt 0) {
        $last = $entries[-1]
        Write-Host "    ledger: " -NoNewline; Write-Host $last.tool -ForegroundColor $WH -NoNewline; Write-Host " -> $($last.status) (id $($last.id))"
        Pause-Beat
        Agent "rolling the change back..."
        $rev = Tool 'changes.revert' @{ id = $last.id }
        if ($rev.ok) { Ok $rev.summary }
        Note @(
            "Heisenberg records the inverse of every mutation in a crash-safe ledger",
            "BEFORE applying it, so any change can be undone cleanly - the box is left",
            "exactly as we found it."
        )
    }

    Section 7 "Done"
    Write-Host "    diagnosed a real deadlock from a dump with cdb, proposed a fix, kept a" -ForegroundColor $GR
    Write-Host "    human in control of the machine change, and reverted it." -ForegroundColor $GR
    Pause-Beat 2
}
finally {
    try { $srv.StandardInput.Close(); [void]$srv.WaitForExit(4000) } catch {}
    try { Stop-Process -Id $patient.Id -Force -EA SilentlyContinue } catch {}
}
New-Item -ItemType File -Force (Join-Path $here 'demo_done.flag') | Out-Null
