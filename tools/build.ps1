param(
    [ValidateSet("all", "desktop", "switch")]
    [string]$Target = "all"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Bash = "C:\msys64\usr\bin\bash.exe"

if (-not (Test-Path $Bash)) {
    throw "MSYS2 bash not found at $Bash"
}

function Invoke-MsysBash([string]$ScriptBody) {
    $lf = ($ScriptBody -replace "`r`n", "`n")
    $tmp = Join-Path $env:TEMP "yumi_build_cmd.sh"
    [System.IO.File]::WriteAllText($tmp, $lf, [System.Text.UTF8Encoding]::new($false))
    $msysTmp = & $Bash -lc "cygpath -u '$($tmp -replace '\\','/')'"
    & $Bash -lc "bash '$msysTmp'"
    if ($LASTEXITCODE -ne 0) {
        throw "Build command failed with exit code $LASTEXITCODE"
    }
}

$MsysRepo = ($RepoRoot -replace '\\', '/')

if ($Target -eq "desktop" -or $Target -eq "all") {
    Write-Output "=== Building Desktop (yumi_tests + desktop_preview) ==="
    Invoke-MsysBash @"
set -e
export PATH="/ucrt64/bin:/usr/bin:`$PATH"
REPO=`$(cygpath -u '$MsysRepo')
mkdir -p "`$REPO/build/desktop"
/ucrt64/bin/cmake -S "`$REPO" -B "`$REPO/build/desktop" -G Ninja -DCMAKE_BUILD_TYPE=Release
/ucrt64/bin/cmake --build "`$REPO/build/desktop" --parallel
echo "=== Running Unit Tests ==="
"`$REPO/build/desktop/yumi_tests.exe"
"@
}

if ($Target -eq "switch" -or $Target -eq "all") {
    Write-Output "=== Building Switch (yumi_sysmodule.nsp + yumi.nro + yumi.ovl) ==="
    Invoke-MsysBash @"
set -e
export DEVKITPRO=/opt/devkitpro
export DEVKITA64=/opt/devkitpro/devkitA64
export PORTLIBS_PATH=/opt/devkitpro/portlibs
export PATH="/opt/devkitpro/tools/bin:/opt/devkitpro/devkitA64/bin:/usr/bin:`$PATH"
REPO=`$(cygpath -u '$MsysRepo')

make -C "`$REPO/sysmodule" -j`$(nproc)
make -C "`$REPO/app" -j`$(nproc)
make -C "`$REPO/overlay" -j`$(nproc)

mkdir -p "`$REPO/sd_out/atmosphere/contents/4200000000079801/flags"
mkdir -p "`$REPO/sd_out/switch/yumi"
mkdir -p "`$REPO/sd_out/switch/.overlays"

cp "`$REPO/sysmodule/yumi_sysmodule.nsp" "`$REPO/sd_out/atmosphere/contents/4200000000079801/exefs.nsp"
cp "`$REPO/sysmodule/toolbox.json" "`$REPO/sd_out/atmosphere/contents/4200000000079801/toolbox.json"
: > "`$REPO/sd_out/atmosphere/contents/4200000000079801/flags/boot2.flag"

cp "`$REPO/app/yumi.nro" "`$REPO/sd_out/switch/yumi/yumi.nro"
cp "`$REPO/overlay/yumi.ovl" "`$REPO/sd_out/switch/.overlays/yumi.ovl"

echo "=== Switch Artifacts Ready in sd_out/ ==="
ls -lh "`$REPO/sd_out/atmosphere/contents/4200000000079801/exefs.nsp" \
       "`$REPO/sd_out/switch/yumi/yumi.nro" \
       "`$REPO/sd_out/switch/.overlays/yumi.ovl"
"@
}
