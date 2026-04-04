param(
    [Parameter(Mandatory = $true)]
    [string]$SpaceRepoUrl
)

$ErrorActionPreference = "Stop"

$deployDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("hf-space-" + [System.Guid]::NewGuid().ToString("N"))

git clone $SpaceRepoUrl $tempDir

Get-ChildItem -LiteralPath $tempDir -Force | Where-Object { $_.Name -ne ".git" } | Remove-Item -Recurse -Force
Copy-Item -Path (Join-Path $deployDir "*") -Destination $tempDir -Recurse -Force

Push-Location $tempDir
git add .
git status --short
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Review changes above"
Write-Host "2. Run: git commit -m 'Deploy SENTRYX HF Space'"
Write-Host "3. Run: git push"
Pop-Location
