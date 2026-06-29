# FraudSniffer - Start Script
# Usage: .\start_fraudsniffer.ps1 [-Port 5000] [-ApiKey "your-key"]

param(
    [int]$Port = 5000,
    [string]$ApiKey = "",
    [string]$DataDir = "data",
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "FraudSniffer v1.0"

Write-Host ""
Write-Host "  +------------------------------------------+" -ForegroundColor DarkCyan
Write-Host "  |       FraudSniffer v1.0                  |" -ForegroundColor DarkCyan
Write-Host "  |       Document Verification Platform     |" -ForegroundColor DarkCyan
Write-Host "  +------------------------------------------+" -ForegroundColor DarkCyan
Write-Host ""

# Navigate to project root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir
Write-Host "  Working directory: $ScriptDir" -ForegroundColor Gray

# Check Python
Write-Host ""
Write-Host "  [1/4] Checking Python..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "        $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "        ERROR: Python not found. Install Python 3.10+ and add to PATH." -ForegroundColor Red
    exit 1
}

# Check dependencies
Write-Host "  [2/4] Checking dependencies..." -ForegroundColor Yellow
$deps = @("flask", "fitz", "PIL")
$missing = @()
foreach ($dep in $deps) {
    $result = python -c "import $dep" 2>&1
    if ($LASTEXITCODE -ne 0) {
        $missing += $dep
    }
}

if ($missing.Count -gt 0) {
    Write-Host "        Missing: $($missing -join ', ')" -ForegroundColor Yellow
    Write-Host "        Installing from requirements.txt..." -ForegroundColor Yellow
    pip install -r requirements.txt --quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Host "        ERROR: pip install failed. Check requirements.txt" -ForegroundColor Red
        exit 1
    }
    Write-Host "        Dependencies installed." -ForegroundColor Green
} else {
    Write-Host "        All core dependencies present." -ForegroundColor Green
}

# Ensure data directories exist
Write-Host "  [3/4] Preparing data directories..." -ForegroundColor Yellow
$dirs = @(
    "$DataDir\documents\originals",
    "$DataDir\documents\annotated",
    "$DataDir\documents\seals",
    "$DataDir\reference"
)
foreach ($dir in $dirs) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
Write-Host "        Data directory: $DataDir" -ForegroundColor Green

# Build launch command
Write-Host "  [4/4] Starting Flask server..." -ForegroundColor Yellow
$cmd = "python -m fraudsniffer --web --port $Port --data-dir $DataDir"
if ($ApiKey) {
    $cmd += " --api-key $ApiKey"
    Write-Host "        API key: enabled" -ForegroundColor Green
} else {
    Write-Host "        API key: none (open access)" -ForegroundColor Gray
}

$url = "http://127.0.0.1:$Port"
Write-Host ""
Write-Host "  +------------------------------------------+" -ForegroundColor Cyan
Write-Host "  |  Dashboard: $url              |" -ForegroundColor Cyan
Write-Host "  |  Press Ctrl+C to stop                    |" -ForegroundColor Cyan
Write-Host "  +------------------------------------------+" -ForegroundColor Cyan
Write-Host ""

# Open browser
if (!$NoBrowser) {
    Start-Process $url
}

# Run the server
Invoke-Expression $cmd
