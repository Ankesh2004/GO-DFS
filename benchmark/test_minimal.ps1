$ErrorActionPreference = "Stop"

# Use the parent directory of the script as the project root
$ProjectRoot = (Get-Item $PSScriptRoot).Parent.FullName
Set-Location $ProjectRoot

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " GO-DFS DRL Minimal Secure Testing Harness" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Project Root: $ProjectRoot"

# 1. Setup isolated Python venv and install dependencies
$VenvPath = Join-Path $ProjectRoot ".drl_env"
$ReqPath = Join-Path $ProjectRoot "rl_sidecar\requirements.txt"

if (-Not (Test-Path $VenvPath)) {
    Write-Host "`n[1/5] Creating isolated Python virtual environment..." -ForegroundColor Yellow
    python -m venv $VenvPath
    Write-Host "Installing RL dependencies..."
    & "$VenvPath\Scripts\pip.exe" install -q -r $ReqPath
} else {
    Write-Host "`n[1/5] Isolated Python environment already exists." -ForegroundColor Green
}

# 2. Start RL Sidecar
Write-Host "`n[2/5] Checking Python DDPG Sidecar..." -ForegroundColor Yellow
$RLPort = Get-NetTCPConnection -LocalPort 5100 -State Listen -ErrorAction SilentlyContinue
if (-not $RLPort) {
    Write-Host "Starting sidecar..."
    $RLScript = Join-Path $ProjectRoot "rl_sidecar\server.py"
    $RLProcess = Start-Process -FilePath "$VenvPath\Scripts\python.exe" -ArgumentList $RLScript -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 3
} else {
    Write-Host "Sidecar already running on port 5100, skipping start." -ForegroundColor Green
}

# 3. Build and Start GO Nodes in temp directories
Write-Host "`n[3/5] Checking GO-DFS temporary swarm..." -ForegroundColor Yellow
$NodePort = Get-NetTCPConnection -LocalPort 7001 -State Listen -ErrorAction SilentlyContinue

if (-not $NodePort) {
    Write-Host "Compiling GO-DFS and bootstrapping nodes..."
    & go build -o dfs.exe ./cmd/dfs

    # Node 1: Fast NVMe node (Bootstrap)
    $Node1 = Start-Process -FilePath "$ProjectRoot\dfs.exe" -ArgumentList "node start --port :7001 --api-port :9001 --data .\cas_test_1 --tier nvme --latency 1.0 --cost 0.05 --rl-enabled" -PassThru -WindowStyle Hidden -RedirectStandardOutput ".\cas_test_1\node.log" -RedirectStandardError ".\cas_test_1\error.log"

    # Node 2: Balanced SSD node
    $Node2 = Start-Process -FilePath "$ProjectRoot\dfs.exe" -ArgumentList "node start --port :7002 --api-port :9002 --data .\cas_test_2 --bootstrap 127.0.0.1:7001 --tier ssd --latency 5.0 --cost 0.01 --rl-enabled" -PassThru -WindowStyle Hidden -RedirectStandardOutput ".\cas_test_2\node.log" -RedirectStandardError ".\cas_test_2\error.log"

    # Node 3: Slow/cheap HDD node
    $Node3 = Start-Process -FilePath "$ProjectRoot\dfs.exe" -ArgumentList "node start --port :7003 --api-port :9003 --data .\cas_test_3 --bootstrap 127.0.0.1:7001 --tier hdd --latency 15.0 --cost 0.002 --rl-enabled" -PassThru -WindowStyle Hidden -RedirectStandardOutput ".\cas_test_3\node.log" -RedirectStandardError ".\cas_test_3\error.log"

    Start-Sleep -Seconds 5
} else {
    Write-Host "GO-DFS swarm already running, skipping start." -ForegroundColor Green
}

# 4. Create and upload a test file
Write-Host "`n[4/5] Injecting test file into the network..." -ForegroundColor Yellow
$TestFilePath = Join-Path $ProjectRoot "test_upload.txt"
"This is a dummy file to trigger the RL placement optimization system." | Out-File $TestFilePath

# Get API token for Node 1
$Token = Get-Content "$ProjectRoot\cas_test_1\api_token" -Raw

# Upload via HTTP POST using curl.exe for proper multipart/form-data
$Uri = "http://127.0.0.1:9001/api/put"
Write-Host "Uploading to $Uri..."
$ResponseJson = curl.exe -s -X POST -F "file=@$TestFilePath" -H "X-Local-Auth: $Token" $Uri
$Response = $ResponseJson | ConvertFrom-Json

if ($Response.error) {
    Write-Host "Upload failed: $($Response.error)" -ForegroundColor Red
    exit 1
}

Write-Host "File stored with CID: $($Response.CID)" -ForegroundColor Green

Start-Sleep -Seconds 2

# 5. Read Metrics
Write-Host "`n[5/5] Fetching Placement Metrics from Node 1..." -ForegroundColor Yellow
$MetricsResp = Invoke-RestMethod -Uri "http://127.0.0.1:9001/api/metrics" -Method Get -Headers @{ "X-Local-Auth" = $Token }
Write-Host "DRL Placement Results:" -ForegroundColor Cyan
if ($MetricsResp.placements) {
    $MetricsResp.placements | Format-Table Timestamp, Method, SelectedNodes, SelectedTiers, AvgLatencyMs, DurationMs
} else {
    Write-Host "No placements recorded yet." -ForegroundColor Gray
}

# --- Cleanup Phase ---
Write-Host "`n==============================================" -ForegroundColor Cyan
$Response = Read-Host "Testing complete. Do you want to clean up processes and temp files? (Y/N)"
if ($Response -notmatch "^y") {
    Write-Host "Skipping cleanup. The swarm is still running in the background." -ForegroundColor Yellow
    exit 0
}

Write-Host " Cleaning up processes and temp files..." -ForegroundColor Yellow

if ($Node1) { Stop-Process -Id $Node1.Id -Force -ErrorAction SilentlyContinue }
if ($Node2) { Stop-Process -Id $Node2.Id -Force -ErrorAction SilentlyContinue }
if ($Node3) { Stop-Process -Id $Node3.Id -Force -ErrorAction SilentlyContinue }
if ($RLProcess) { Stop-Process -Id $RLProcess.Id -Force -ErrorAction SilentlyContinue }

# Fallback killer just in case
Get-Process dfs -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "rl_sidecar" } | Stop-Process -Force -ErrorAction SilentlyContinue

Start-Sleep -Seconds 2

Remove-Item -Path "$ProjectRoot\cas_test_1" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$ProjectRoot\cas_test_2" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$ProjectRoot\cas_test_3" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $TestFilePath -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$ProjectRoot\dfs.exe" -Force -ErrorAction SilentlyContinue

Write-Host "`nDone! Your PC state has been restored." -ForegroundColor Green
