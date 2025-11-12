# Debug script for PostgreSQL Docker image
# This script builds and runs the PostgreSQL Docker image with embedded PostgreSQL server

# Create a temporary .env file without quotes for Docker
$tempEnvFile = ".env.docker.tmp"
Get-Content .env | ForEach-Object {
    if ($_ -match '^([^#][^=]+)=(.*)$') {  # Changed .+ to .* to allow empty values
        $key = $matches[1].Trim()
        $value = $matches[2].Trim()
        # Remove quotes if present
        $value = $value -replace '^[''"]|[''"]$', ''
        "$key=$value"
    } elseif ($_ -match '^#' -or $_.Trim() -eq '') {
        # Preserve comments and empty lines
        $_
    }
} | Set-Content -Path $tempEnvFile -Encoding UTF8

Write-Host "`n=== Validating environment variables ===" -ForegroundColor Cyan
# Load environment variables from temp file for validation
Get-Content $tempEnvFile | ForEach-Object {
    if ($_ -match '^([^#][^=]+)=(.*)$') {
        $key = $matches[1].Trim()
        $value = $matches[2].Trim()
        Set-Item -Path "env:$key" -Value $value
    }
}

# Validate environment variables before building Docker
# Use venv Python if available, otherwise use system Python
$pythonExe = if (Test-Path ".\.venv\Scripts\python.exe") { 
    ".\.venv\Scripts\python.exe" 
} elseif (Test-Path ".\env\Scripts\python.exe") { 
    ".\env\Scripts\python.exe" 
} else { 
    "python" 
}

& $pythonExe .\scripts\generate_required_secrets.py --check
$validationExitCode = $LASTEXITCODE

if ($validationExitCode -ne 0) {
    Write-Host "`n[ERROR] Environment validation failed!" -ForegroundColor Red
    Write-Host "Please fix your .env file before running Docker." -ForegroundColor Yellow
    Write-Host "Run: python generate_required_secrets.py" -ForegroundColor Yellow
    Remove-Item $tempEnvFile -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "[OK] Environment validation passed!" -ForegroundColor Green
Write-Host "`n=== Building PostgreSQL Docker image ===" -ForegroundColor Cyan

# Build PostgreSQL Docker image
docker build --no-cache --compress -f Dockerfile.postgresql -t github-events-limiter:postgresql .

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[ERROR] Docker build failed!" -ForegroundColor Red
    Remove-Item $tempEnvFile -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "`n=== Starting PostgreSQL Docker container ===" -ForegroundColor Cyan
Write-Host "This container includes an embedded PostgreSQL server" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop the container" -ForegroundColor Yellow
Write-Host ""

# Create a named volume for PostgreSQL data persistence
$volumeName = "github-events-limiter-postgres-debug"
Write-Host "Using volume: $volumeName" -ForegroundColor Cyan

# Run with cleaned env file
# Removed -it flag to prevent restart loop on validation errors
try {
    docker run -t --rm `
        --name github-events-limiter-postgresql-debug `
        --env-file $tempEnvFile `
        -v "${volumeName}:/var/lib/postgresql/data" `
        -p 5000:5000 `
        -p 5432:5432 `
        github-events-limiter:postgresql
}
finally {
    Write-Host "`n=== Cleaning up ===" -ForegroundColor Cyan
    
    # Clean up temporary file
    if (Test-Path $tempEnvFile) {
        Remove-Item $tempEnvFile -ErrorAction SilentlyContinue
        Write-Host "Removed temporary env file" -ForegroundColor Green
    }
    
    Write-Host "`nNote: PostgreSQL data is persisted in volume '$volumeName'" -ForegroundColor Cyan
    Write-Host "To remove the volume, run: docker volume rm $volumeName" -ForegroundColor Yellow
}
