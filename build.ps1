#!/usr/bin/env pwsh
# build.ps1 — multi-platform build (NullFang + nfdb)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.IO.Compression

New-Item -ItemType Directory -Force -Path "builds" | Out-Null

$platforms = @(
    @{ OS = "windows"; Arch = "amd64" },
    @{ OS = "windows"; Arch = "arm64" },
    @{ OS = "linux";   Arch = "amd64" },
    @{ OS = "linux";   Arch = "arm64" },
    @{ OS = "darwin";  Arch = "amd64" },
    @{ OS = "darwin";  Arch = "arm64" }
)

foreach ($p in $platforms) {
    $goos   = $p.OS
    $goarch = $p.Arch

    $env:GOOS   = $goos
    $env:GOARCH = $goarch
    $env:CGO_ENABLED = if ($goos -eq "windows") { "1" } else { "0" }
    Remove-Item Env:\CC -ErrorAction SilentlyContinue

    $ext         = if ($goos -eq "windows") { ".exe" } else { "" }
    $nullfangOut = "builds\nullfang-$goos-$goarch$ext"
    $nfdbOut     = "builds\nfdb-$goos-$goarch$ext"

    Write-Host "Building nullfang for $goos/$goarch..."
    go build -ldflags "-s -w" -buildvcs=false -trimpath -o $nullfangOut .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host "Building nfdb for $goos/$goarch..."
    go build -ldflags "-s -w" -buildvcs=false -trimpath -o $nfdbOut ./nfdb/
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "All builds completed successfully!"
Get-ChildItem builds | Select-Object Name, @{n="Size";e={"{0:N0} KB" -f ($_.Length/1KB)}}

Write-Host "Compressing binaries..."
foreach ($file in Get-ChildItem builds -File | Where-Object { $_.Extension -ne ".gz" }) {
    $gzPath    = "$($file.FullName).gz"
    $inStream  = [System.IO.File]::OpenRead($file.FullName)
    $outStream = [System.IO.File]::Create($gzPath)
    $gzStream  = [System.IO.Compression.GZipStream]::new($outStream, [System.IO.Compression.CompressionMode]::Compress)
    $inStream.CopyTo($gzStream)
    $gzStream.Dispose(); $outStream.Dispose(); $inStream.Dispose()
    Write-Host "Compressed: $($file.Name) -> $($file.Name).gz"
}

Write-Host "Build and compression completed!"
Get-ChildItem builds | Select-Object Name, @{n="Size";e={"{0:N0} KB" -f ($_.Length/1KB)}}
