# Live viewer for Heisenberg's tool-call log. Tails <state-root>\calls.jsonl and
# pretty-prints each result as it lands — the demo's "see what the agent did"
# pane. Pass the calls.jsonl path, or set HEISENBERG_HOME.
param(
    [string]$Path = $(if ($env:HEISENBERG_HOME) { Join-Path $env:HEISENBERG_HOME 'calls.jsonl' } else { Join-Path $env:ProgramData 'Heisenberg\calls.jsonl' })
)

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try { $Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(80, 5000) } catch {}

Write-Host ""
Write-Host "  heisenberg://calls   live tool-call log" -ForegroundColor Black -BackgroundColor DarkCyan
Write-Host ""

# Wait for the first run to create the file.
while (-not (Test-Path $Path)) { Start-Sleep -Milliseconds 250 }

# Two-line entries (header + indented summary) so it reads cleanly in a narrow
# side pane.
Get-Content -Path $Path -Wait -Encoding utf8 | ForEach-Object {
    if ([string]::IsNullOrWhiteSpace($_)) { return }
    try { $o = $_ | ConvertFrom-Json } catch { return }
    $t = [string]$o.ts
    if ($t -match 'T([0-9:]{8})') { $t = $Matches[1] } else { $t = '' }
    Write-Host ("{0} " -f $t) -ForegroundColor DarkGray -NoNewline
    Write-Host ([string]$o.tool) -ForegroundColor Cyan -NoNewline
    if ($o.ok) {
        Write-Host "  [ok]" -ForegroundColor Green
    } else {
        Write-Host ("  [{0}]" -f $o.error) -ForegroundColor Red
    }
    $sum = [string]$o.summary
    if ($sum.Length -gt 56) { $sum = $sum.Substring(0, 56) + '...' }
    Write-Host ("   " + $sum) -ForegroundColor Gray
    foreach ($line in @($o.detail)) {
        if ($line) {
            $l = [string]$line
            if ($l.Length -gt 54) { $l = $l.Substring(0, 54) + '...' }
            Write-Host ("     - " + $l) -ForegroundColor DarkCyan
        }
    }
    foreach ($a in @($o.artifacts)) {
        if ($a) { Write-Host ("   -> " + (Split-Path $a -Leaf)) -ForegroundColor DarkYellow }
    }
}
