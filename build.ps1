param([ValidateSet('Release', 'Debug')][string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    & cmake -S . -B build -A x64
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed' }
    & cmake --build build --config $Configuration --parallel
    if ($LASTEXITCODE -ne 0) { throw 'MSVC build failed' }
    & ctest --test-dir build -C $Configuration --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    New-Item -ItemType Directory -Force bin | Out-Null
    Copy-Item -LiteralPath "build/$Configuration/cs2-dumper.exe" -Destination bin/cs2-dumper.exe -Force
    Write-Host "Ready: $PSScriptRoot\bin\cs2-dumper.exe"
} finally { Pop-Location }
