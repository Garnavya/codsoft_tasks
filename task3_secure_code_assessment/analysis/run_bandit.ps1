<#
.SYNOPSIS
    Automated Static Application Security Testing (SAST) execution script using Bandit.

.DESCRIPTION
    Runs Bandit static analysis on the vulnerable baseline app and the remediated secure app.
    Generates text and JSON reports documenting detected security flaws and remediation verification.

.EXAMPLE
    .\run_bandit.ps1
#>

$ErrorActionPreference = "Continue"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  CodSoft Task 3: Automated Bandit Security Code Analysis       " -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path "$scriptDir\..\.."
$venvBandit = "$repoRoot\.venv\Scripts\bandit.exe"

if (-not (Test-Path $venvBandit)) {
    Write-Host "[!] Bandit not found at $venvBandit. Attempting system bandit..." -ForegroundColor Yellow
    $venvBandit = "bandit"
}

$vulnApp = "$scriptDir\..\target_app\vulnerable_app.py"
$secApp = "$scriptDir\..\target_app\secure_app.py"

$reportBeforeTxt = "$scriptDir\bandit_report_before.txt"
$reportBeforeJson = "$scriptDir\bandit_report_before.json"
$reportAfterTxt = "$scriptDir\bandit_report_after.txt"
$reportAfterJson = "$scriptDir\bandit_report_after.json"

Write-Host "`n[1/2] Scanning Vulnerable Application Baseline..." -ForegroundColor Yellow
Write-Host "  Target: $vulnApp"

# Run Bandit on vulnerable app (expecting exit code 1 if issues found)
& $venvBandit -r $vulnApp -f txt -o $reportBeforeTxt
& $venvBandit -r $vulnApp -f json -o $reportBeforeJson

Write-Host "  ✔ Saved baseline text report to: $reportBeforeTxt" -ForegroundColor Green
Write-Host "  ✔ Saved baseline JSON report to: $reportBeforeJson" -ForegroundColor Green

Write-Host "`n[2/2] Scanning Remediated Secure Application..." -ForegroundColor Yellow
Write-Host "  Target: $secApp"

# Run Bandit on secure app
& $venvBandit -r $secApp -f txt -o $reportAfterTxt
& $venvBandit -r $secApp -f json -o $reportAfterJson

Write-Host "  ✔ Saved remediated text report to: $reportAfterTxt" -ForegroundColor Green
Write-Host "  ✔ Saved remediated JSON report to: $reportAfterJson" -ForegroundColor Green

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "  SAST Scan Complete. Review reports in task3_secure_code_assessment/analysis/" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
