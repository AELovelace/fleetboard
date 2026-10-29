#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the Fleetboard client as a Windows service.
.DESCRIPTION
    Downloads the latest release binary from GitHub (or takes -BinaryPath), verifies it against
    SHA256SUMS, writes %ProgramData%\Fleetboard\client.toml with the shared token, registers the
    "Fleetboard client" service (runs as LocalService, restarts on failure), and adds a firewall rule
    that lets only the Mnemerynne box reach port 9280. -WhatIf shows every step without doing it.
.PARAMETER Token
    The shared token every client and the server have. Make one with: fleetboard-client gen-token
.PARAMETER ServerIp
    The Mnemerynne box's address; the firewall rule allows 9280 from it alone.
.PARAMETER BinaryPath
    A local fleetboard-client.exe instead of downloading.
.PARAMETER Version
    A release tag (v0.1.0) or "latest".
.PARAMETER Bind
    Where the client listens; 0.0.0.0:9280 unless this is the Mnemerynne box itself.
.PARAMETER Name
    A display name for the dashboard; empty = the hostname.
.PARAMETER Check
    Only report whether the service runs and answers.
.PARAMETER Uninstall
    Stop and remove the service, binary and firewall rule (the config stays).
.EXAMPLE
    .\Install-FleetboardClient.ps1 -Token "abc…" -ServerIp 10.0.5.2
.EXAMPLE
    .\Install-FleetboardClient.ps1 -Check
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Token,
    [string]$ServerIp,
    [string]$BinaryPath,
    [string]$Version = "latest",
    [ValidatePattern('^[0-9a-zA-Z\.\[\]:]+:\d{1,5}$')][string]$Bind = "0.0.0.0:9280",
    [string]$Name = "",
    [switch]$Check,
    [switch]$Uninstall
)
$ErrorActionPreference = "Stop"

$Repo = "AELovelace/fleetboard"
$ServiceName = "FleetboardClient"
$InstallDir = Join-Path $env:ProgramFiles "Fleetboard"
$Exe = Join-Path $InstallDir "fleetboard-client.exe"
$DataDir = Join-Path $env:ProgramData "Fleetboard"
$Config = Join-Path $DataDir "client.toml"
$LogDir = Join-Path $DataDir "logs"
$RuleName = "Fleetboard client"
$Port = [int]($Bind -split ":")[-1]

function Write-Step([string]$Text) { Write-Host "`n== $Text" -ForegroundColor Magenta }   # a heading per stage
function Write-Note([string]$Text) { Write-Host "   $Text" }                                # a line under it

function Get-FleetboardRelease {
    # Download the Windows client and verify its SHA-256 against the release's SHA256SUMS.
    $asset = "fleetboard-client-windows-x86_64.exe"
    $base = if ($Version -eq "latest") { "https://github.com/$Repo/releases/latest/download" } else { "https://github.com/$Repo/releases/download/$Version" }
    $tmp = Join-Path $env:TEMP "fleetboard-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $tmp | Out-Null
    Write-Note "downloading $base/$asset"
    Invoke-WebRequest -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset) -UseBasicParsing
    Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp "SHA256SUMS") -UseBasicParsing
    $expected = (Get-Content (Join-Path $tmp "SHA256SUMS") | Where-Object { $_ -match "\s$asset$" }) -split "\s+" | Select-Object -First 1
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $asset)).Hash.ToLower()
    if (-not $expected -or $actual -ne $expected.ToLower()) { throw "checksum of $asset ($actual) doesn't match SHA256SUMS ($expected)" }
    Write-Note "checksum ok"
    return (Join-Path $tmp $asset)
}

function Install-FleetboardBinary([string]$Source) {
    # Copy the exe into Program Files\Fleetboard.
    if ($PSCmdlet.ShouldProcess($Exe, "install binary")) {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        Copy-Item -Force $Source $Exe
        Write-Note "installed $Exe ($(& $Exe --version))"
    }
}

function Write-FleetboardConfig {
    # client.toml readable by Administrators and LocalService only; a logs folder LocalService may write.
    if (-not $Token) { throw "-Token is required (make one with: fleetboard-client gen-token)" }
    if ($Token.Length -lt 16) { throw "the token must be at least 16 characters" }
    $text = @"
# Fleetboard client. The token is shared with the server; bind is where it listens.
token = "$Token"
bind = "$Bind"
name = "$Name"
gpu = true
log = "info"
"@
    if ($PSCmdlet.ShouldProcess($Config, "write config")) {
        New-Item -ItemType Directory -Force -Path $DataDir, $LogDir | Out-Null
        [IO.File]::WriteAllText($Config, $text + "`n", (New-Object Text.UTF8Encoding $false))
        & icacls $Config /inheritance:r /grant:r "Administrators:F" "NT AUTHORITY\LocalService:R" "SYSTEM:F" | Out-Null
        & icacls $LogDir /inheritance:r /grant:r "Administrators:F" "NT AUTHORITY\LocalService:M" "SYSTEM:F" | Out-Null
        Write-Note "wrote $Config"
    }
}

function Register-FleetboardService {
    # The exe knows how to register itself (service install) with the right account and restart policy.
    if ($PSCmdlet.ShouldProcess($ServiceName, "register and start service")) {
        if (Get-Service $ServiceName -ErrorAction SilentlyContinue) { & $Exe service stop 2>$null; & $Exe service uninstall }
        & $Exe service install --config $Config
        & $Exe service start
        Write-Note "service ${ServiceName}: $((Get-Service $ServiceName).Status)"
    }
}

function Set-FleetboardFirewallRule {
    # Port 9280 from the Mnemerynne box only.
    if (-not $ServerIp) { Write-Note "no -ServerIp: firewall left alone (open $Port from the Mnemerynne box yourself)"; return }
    if ($PSCmdlet.ShouldProcess($RuleName, "firewall rule $Port from $ServerIp")) {
        Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Protocol TCP -LocalPort $Port -RemoteAddress $ServerIp -Program $Exe -Action Allow | Out-Null
        Write-Note "firewall: $Port/tcp allowed from $ServerIp"
    }
}

function Test-FleetboardClient {
    # Is it running and answering?
    Write-Step "Checking"
    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($svc) { Write-Note "service: $($svc.Status)" } else { Write-Note "FAIL service not installed" }
    try {
        $h = Invoke-RestMethod "http://127.0.0.1:$Port/healthz"
        Write-Note "ok   /healthz: $($h.hostname) agent $($h.agent)"
    } catch { Write-Note "FAIL /healthz on $Port ($($_.Exception.Message))" }
    if (Test-Path $Config) {
        $tok = (Select-String -Path $Config -Pattern '^token = "(.*)"').Matches.Groups[1].Value
        try {
            $s = Invoke-RestMethod "http://127.0.0.1:$Port/stats" -Headers @{ Authorization = "Bearer $tok" }
            Write-Note "ok   /stats: cpu $([math]::Round($s.cpu.percent)) %, $($s.gpus.Count) GPU(s)"
        } catch { Write-Note "FAIL /stats ($($_.Exception.Message))" }
    }
    if (Test-Path $LogDir) { Write-Note "logs: $LogDir" }
}

function Uninstall-Fleetboard {
    Write-Step "Removing"
    if ($PSCmdlet.ShouldProcess($ServiceName, "remove service, binary and firewall rule")) {
        if (Test-Path $Exe) { & $Exe service stop 2>$null; & $Exe service uninstall 2>$null }
        Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        Remove-Item -Force -ErrorAction SilentlyContinue $Exe
        Write-Note "left in place: $Config (holds the token)"
    }
}

if ($Check) { Test-FleetboardClient; return }
if ($Uninstall) { Uninstall-Fleetboard; return }

Write-Step "Fleetboard client"
$source = if ($BinaryPath) { Write-Note "using $BinaryPath"; $BinaryPath } else { Get-FleetboardRelease }
Install-FleetboardBinary $source
Write-FleetboardConfig
Register-FleetboardService
Set-FleetboardFirewallRule
Test-FleetboardClient
Write-Step "Done"
Write-Note "add this machine in Fleetboard's Hosts tab as $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1).IPAddress):$Port"
