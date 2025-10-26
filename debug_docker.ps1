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
$pythonExe = if (Test-Path ".\env\Scripts\python.exe") { ".\env\Scripts\python.exe" } else { "python" }
& $pythonExe generate_required_secrets.py --check
$validationExitCode = $LASTEXITCODE

if ($validationExitCode -ne 0) {
    Write-Host "`n[ERROR] Environment validation failed!" -ForegroundColor Red
    Write-Host "Please fix your .env file before running Docker." -ForegroundColor Yellow
    Write-Host "Run: python generate_required_secrets.py" -ForegroundColor Yellow
    Remove-Item $tempEnvFile -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "[OK] Environment validation passed!" -ForegroundColor Green
Write-Host "`n=== Building Docker image ===" -ForegroundColor Cyan

# Build Docker image
docker build --no-cache --compress -t github-events-limiter .

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[ERROR] Docker build failed!" -ForegroundColor Red
    Remove-Item $tempEnvFile -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "`n=== Starting Docker container ===" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the container" -ForegroundColor Yellow
Write-Host ""

# Run with cleaned env file
# Removed -it flag to prevent restart loop on validation errors
try {
    docker run --rm --env-file $tempEnvFile -v "${PWD}\GitHub_Events_Limiter:/app/GitHub_Events_Limiter" -p 5000:5000 github-events-limiter
}
finally {
    Write-Host "`n=== Cleaning up ===" -ForegroundColor Cyan
    
    # Clean up temporary file
    if (Test-Path $tempEnvFile) {
        Remove-Item $tempEnvFile -ErrorAction SilentlyContinue
        Write-Host "Removed temporary env file" -ForegroundColor Green
    }
}
