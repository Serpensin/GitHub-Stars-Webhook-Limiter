#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Run all tests across all database configurations.

.DESCRIPTION
    This script runs the complete test suite against all supported database configurations:
    1. SQLite (default, lightweight)
    2. PostgreSQL (embedded server)
    
    Each configuration is tested independently with automatic cleanup between runs.
    The script reports a summary of all test results at the end.

.PARAMETER Configuration
    Specific database configuration to test: 'sqlite', 'postgresql', or 'all' (default)

.PARAMETER KeepRunning
    Keep containers running after tests complete (for debugging)

.PARAMETER ViewLogs
    Show container logs after tests complete

.PARAMETER FailFast
    Stop testing after the first configuration failure

.EXAMPLE
    .\test-all.ps1
    Run tests for all configurations

.EXAMPLE
    .\test-all.ps1 -Configuration sqlite
    Run tests only for SQLite

.EXAMPLE
    .\test-all.ps1 -FailFast
    Run all tests but stop at first failure

.EXAMPLE
    .\test-all.ps1 -Configuration postgresql -ViewLogs
    Run PostgreSQL tests and show logs
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('sqlite', 'postgresql', 'all')]
    [string]$Configuration = 'all',
    
    [Parameter()]
    [switch]$KeepRunning,
    
    [Parameter()]
    [switch]$ViewLogs,
    
    [Parameter()]
    [switch]$FailFast
)

# Set error action
$ErrorActionPreference = "Stop"

# Test configuration definitions
$configurations = @(
    @{
        Name = "SQLite"
        ComposeFile = "docker-compose.test.yml"
        ContainerSuffix = ""
        Description = "Lightweight file-based database"
    },
    @{
        Name = "PostgreSQL"
        ComposeFile = "docker-compose.test-postgresql.yml"
        ContainerSuffix = "-pg"
        Description = "Embedded PostgreSQL server"
    }
)

# Filter configurations if specific one requested
if ($Configuration -ne 'all') {
    $configurations = $configurations | Where-Object { $_.Name.ToLower() -eq $Configuration }
}

# Function to run tests for a specific configuration
function Test-Configuration {
    param(
        [hashtable]$Config,
        [bool]$ShowLogs,
        [bool]$KeepAlive
    )
    
    $composeFile = $Config.ComposeFile
    $configName = $Config.Name
    $containerSuffix = $Config.ContainerSuffix
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Testing: $configName" -ForegroundColor Cyan
    Write-Host "  Description: $($Config.Description)" -ForegroundColor Cyan
    Write-Host "  Compose File: $composeFile" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Prepare environment
    Write-Host "[1/5] Preparing environment..." -ForegroundColor Yellow
    if (Test-Path ".env") {
        $tempEnv = Get-Content ".env" | ForEach-Object {
            # Escape $ symbols by doubling them ($ becomes $$)
            $_ -replace '\$', '$$$$'
        }
        $tempEnv | Set-Content ".env.docker" -Encoding UTF8
        Write-Host "  ✓ Environment prepared" -ForegroundColor Gray
    } else {
        Write-Host "  ✗ ERROR: .env file not found!" -ForegroundColor Red
        return $false
    }
    
    # Clean up any existing containers
    Write-Host "[2/5] Cleaning up existing containers..." -ForegroundColor Yellow
    docker compose -f $composeFile --env-file .env.docker down -v 2>$null
    if ($configName -eq 'SQLite') {
        Remove-Item -Path "GitHub_Events_Limiter\data.db" -ErrorAction SilentlyContinue
        Write-Host "  ✓ SQLite database cleaned" -ForegroundColor Gray
    }
    Write-Host "  ✓ Cleanup complete" -ForegroundColor Gray
    
    # Build containers
    Write-Host "[3/5] Building containers..." -ForegroundColor Yellow
    docker compose -f $composeFile --env-file .env.docker build --no-cache 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ✗ Build failed!" -ForegroundColor Red
        return $false
    }
    Write-Host "  ✓ Build successful" -ForegroundColor Gray
    
    # Start the stack
    Write-Host "[4/5] Starting test stack..." -ForegroundColor Yellow
    docker compose -f $composeFile --env-file .env.docker up -d server 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ✗ Failed to start server!" -ForegroundColor Red
        return $false
    }
    Write-Host "  ✓ Server started" -ForegroundColor Gray
    
    # Wait for server to be healthy
    Write-Host "[4/5] Waiting for server to be healthy..." -ForegroundColor Yellow
    $maxWait = 120
    $waited = 0
    $healthy = $false
    
    while ($waited -lt $maxWait) {
        $health = docker inspect --format='{{.State.Health.Status}}' "github-events-limiter-test-server$containerSuffix" 2>$null
        
        if ($health -eq 'healthy') {
            $healthy = $true
            Write-Host "  ✓ Server is healthy!" -ForegroundColor Green
            break
        }
        
        if ($waited % 10 -eq 0) {
            Write-Host "  → Waiting... ($waited/$maxWait seconds)" -ForegroundColor Gray
        }
        Start-Sleep -Seconds 5
        $waited += 5
    }
    
    if (-not $healthy) {
        Write-Host "  ✗ Server failed to become healthy within $maxWait seconds!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Server logs:" -ForegroundColor Yellow
        docker compose -f $composeFile --env-file .env.docker logs server
        docker compose -f $composeFile --env-file .env.docker down -v 2>&1 | Out-Null
        return $false
    }
    
    # Run tests
    Write-Host "[5/5] Running tests..." -ForegroundColor Yellow
    Write-Host ""
    docker compose -f $composeFile --env-file .env.docker up --exit-code-from test-runner test-runner
    $testExitCode = $LASTEXITCODE
    Write-Host ""
    
    # Show results
    if ($testExitCode -eq 0) {
        Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Green
        Write-Host "  ✓ $configName: ALL TESTS PASSED" -ForegroundColor Green
        Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Green
    } else {
        Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Red
        Write-Host "  ✗ $configName: TESTS FAILED (Exit Code: $testExitCode)" -ForegroundColor Red
        Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Red
    }
    
    # Show logs if requested
    if ($ShowLogs) {
        Write-Host ""
        Write-Host "Container Logs:" -ForegroundColor Cyan
        Write-Host "--- Server Logs ---" -ForegroundColor Yellow
        docker compose -f $composeFile --env-file .env.docker logs server
        Write-Host ""
        Write-Host "--- Test Runner Logs ---" -ForegroundColor Yellow
        docker compose -f $composeFile --env-file .env.docker logs test-runner
        Write-Host ""
    }
    
    # Clean up unless KeepRunning is set
    if (-not $KeepAlive) {
        Write-Host "Cleaning up containers..." -ForegroundColor Yellow
        docker compose -f $composeFile --env-file .env.docker down -v 2>&1 | Out-Null
        Remove-Item -Path ".env.docker" -ErrorAction SilentlyContinue
        Write-Host "  ✓ Cleanup complete" -ForegroundColor Gray
    } else {
        Write-Host ""
        Write-Host "Containers are still running for debugging." -ForegroundColor Cyan
        Write-Host "To stop them: docker compose -f $composeFile --env-file .env.docker down -v" -ForegroundColor Cyan
        Write-Host ""
    }
    
    return ($testExitCode -eq 0)
}

# Main execution
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  GitHub Events Limiter - Comprehensive Test Suite            ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

$results = @()
$overallSuccess = $true

foreach ($config in $configurations) {
    $success = Test-Configuration -Config $config -ShowLogs:$ViewLogs -KeepAlive:$KeepRunning
    
    $results += @{
        Name = $config.Name
        Success = $success
    }
    
    if (-not $success) {
        $overallSuccess = $false
        if ($FailFast) {
            Write-Host ""
            Write-Host "FailFast enabled - stopping after first failure" -ForegroundColor Red
            break
        }
    }
}

# Final summary
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  TEST SUMMARY                                                 ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

foreach ($result in $results) {
    $status = if ($result.Success) { "✓ PASSED" } else { "✗ FAILED" }
    $color = if ($result.Success) { "Green" } else { "Red" }
    Write-Host ("  {0,-20} {1}" -f $result.Name, $status) -ForegroundColor $color
}

Write-Host ""
if ($overallSuccess) {
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║  ✓ ALL CONFIGURATIONS PASSED                                 ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    exit 0
} else {
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║  ✗ SOME CONFIGURATIONS FAILED                                ║" -ForegroundColor Red
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    exit 1
}
