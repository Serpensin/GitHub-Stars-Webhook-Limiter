#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Run tests in Docker stack with server and test runner containers.

.DESCRIPTION
    This script manages a Docker Compose stack that runs the server in one container
    and pytest in another. It supports both SQLite and PostgreSQL configurations.

.PARAMETER Database
    Database type to test: 'sqlite' (default) or 'postgresql'

.PARAMETER KeepRunning
    Keep containers running after tests complete (for debugging)

.PARAMETER ViewLogs
    Show container logs after tests complete

.EXAMPLE
    .\test-stack.ps1
    Run tests with SQLite

.EXAMPLE
    .\test-stack.ps1 -Database postgresql
    Run tests with PostgreSQL

.EXAMPLE
    .\test-stack.ps1 -KeepRunning -ViewLogs
    Run tests, keep containers running, and show logs
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('sqlite', 'postgresql')]
    [string]$Database = 'sqlite',
    
    [Parameter()]
    [switch]$KeepRunning,
    
    [Parameter()]
    [switch]$ViewLogs
)

# Set error action
$ErrorActionPreference = "Stop"

# Create a temporary .env file with escaped $ symbols for docker-compose
# Docker Compose tries to expand $variables, so we need to escape them as $$
Write-Host "Preparing environment for Docker Compose..." -ForegroundColor Gray
if (Test-Path ".env") {
    $tempEnv = Get-Content ".env" | ForEach-Object {
        # Escape $ symbols by doubling them ($ becomes $$)
        $_ -replace '\$', '$$$$'
    }
    $tempEnv | Set-Content ".env.docker" -Encoding UTF8
    Write-Host "  -> Environment prepared" -ForegroundColor Gray
} else {
    Write-Host "ERROR: .env file not found!" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Determine which compose file to use
$composeFile = if ($Database -eq 'postgresql') {
    'docker-compose.test-postgresql.yml'
} else {
    'docker-compose.test.yml'
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "GitHub Events Limiter - Test Stack" -ForegroundColor Cyan
Write-Host "Database: $Database" -ForegroundColor Cyan
Write-Host "Compose File: $composeFile" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Clean up any existing containers
Write-Host "[1/5] Cleaning up existing containers..." -ForegroundColor Yellow
docker compose -f $composeFile --env-file .env.docker down -v 2>$null
if ($Database -eq 'sqlite') {
    Remove-Item -Path "GitHub_Events_Limiter\data.db" -ErrorAction SilentlyContinue
    Write-Host "  -> SQLite database cleaned" -ForegroundColor Gray
}
Write-Host ""

# Build containers
Write-Host "[2/5] Building containers..." -ForegroundColor Yellow
docker compose -f $composeFile --env-file .env.docker build --no-cache
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed!" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Start the stack
Write-Host "[3/5] Starting test stack..." -ForegroundColor Yellow
docker compose -f $composeFile --env-file .env.docker up -d server
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to start server!" -ForegroundColor Red
    exit 1
}

# Wait for server to be healthy
Write-Host "[4/5] Waiting for server to be healthy..." -ForegroundColor Yellow
$maxWait = 120
$waited = 0
$healthy = $false

while ($waited -lt $maxWait) {
    $health = docker inspect --format='{{.State.Health.Status}}' github-events-limiter-test-server$(if ($Database -eq 'postgresql') { '-pg' }) 2>$null
    
    if ($health -eq 'healthy') {
        $healthy = $true
        Write-Host "  -> Server is healthy!" -ForegroundColor Green
        break
    }
    
    Write-Host "  -> Waiting... ($waited/$maxWait seconds)" -ForegroundColor Gray
    Start-Sleep -Seconds 5
    $waited += 5
}

if (-not $healthy) {
    Write-Host "ERROR: Server failed to become healthy within $maxWait seconds!" -ForegroundColor Red
    Write-Host "Server logs:" -ForegroundColor Yellow
    docker compose -f $composeFile --env-file .env.docker logs server
    docker compose -f $composeFile --env-file .env.docker down -v
    exit 1
}
Write-Host ""

# Run tests
Write-Host "[5/5] Running tests..." -ForegroundColor Yellow
docker compose -f $composeFile --env-file .env.docker up --exit-code-from test-runner test-runner
$testExitCode = $LASTEXITCODE
Write-Host ""

# Show results
if ($testExitCode -eq 0) {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "✓ ALL TESTS PASSED" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "✗ TESTS FAILED (Exit Code: $testExitCode)" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
}
Write-Host ""

# View logs if requested
if ($ViewLogs) {
    Write-Host "Container Logs:" -ForegroundColor Cyan
    Write-Host "--- Server Logs ---" -ForegroundColor Yellow
    docker compose -f $composeFile --env-file .env.docker logs server
    Write-Host ""
    Write-Host "--- Test Runner Logs ---" -ForegroundColor Yellow
    docker compose -f $composeFile --env-file .env.docker logs test-runner
    Write-Host ""
}

# Clean up unless KeepRunning is set
if (-not $KeepRunning) {
    Write-Host "Cleaning up containers..." -ForegroundColor Yellow
    docker compose -f $composeFile --env-file .env.docker down -v
    Remove-Item -Path ".env.docker" -ErrorAction SilentlyContinue
    Write-Host "Done!" -ForegroundColor Green
} else {
    Write-Host "Containers are still running. Use 'docker compose -f $composeFile --env-file .env.docker down -v' to stop them." -ForegroundColor Cyan
    Write-Host "Remember to delete .env.docker when done." -ForegroundColor Cyan
}

exit $testExitCode
