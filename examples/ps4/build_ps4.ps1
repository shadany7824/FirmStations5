# Builds a PS4 homebrew program with the OpenOrbis toolchain on Windows, without the packaging step.
# It runs the same compile / link / create-fself commands as the toolchain's own build.bat, but
# stops before PkgTool (which needs an old .NET runtime and is only for making installable .pkg files).
#
# Needs: clang and ld.lld on PATH (LLVM), and $env:OO_PS4_TOOLCHAIN pointing at the toolchain folder.
# Output (in <Source>\x64\Debug): <Name>.elf, <Name>.oelf and eboot.bin
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Libs = "-lc -lkernel -lc++"
)
$ErrorActionPreference = "Stop"
$tc = $env:OO_PS4_TOOLCHAIN
if (-not $tc) { throw "Set `$env:OO_PS4_TOOLCHAIN to the OpenOrbis toolchain folder first." }
$Source = (Resolve-Path $Source).Path
$out = Join-Path $Source "x64\Debug"
New-Item -ItemType Directory -Force $out | Out-Null

$objects = @()
foreach ($file in Get-ChildItem $Source -File | Where-Object { $_.Extension -in ".c", ".cpp" }) {
    $obj = Join-Path $out ($file.BaseName + ".o")
    $compiler = if ($file.Extension -eq ".c") { "clang" } else { "clang++" }
    & $compiler --target=x86_64-pc-freebsd12-elf -fPIC -funwind-tables "-I$tc\include" "-I$tc\include\c++\v1" -c -o $obj $file.FullName
    if ($LASTEXITCODE -ne 0) { throw "compiling $($file.Name) failed" }
    $objects += $obj
}
if ($objects.Count -eq 0) { throw "no .c or .cpp files found in $Source" }

$elf = Join-Path $out "$Name.elf"
$oelf = Join-Path $out "$Name.oelf"
& ld.lld -m elf_x86_64 -pie --script "$tc\link.x" --eh-frame-hdr -o $elf "-L$tc\lib" ($Libs -split " ") "$tc\lib\crt1.o" $objects
if ($LASTEXITCODE -ne 0) { throw "linking failed" }

& "$tc\bin\windows\create-fself.exe" -in $elf --out $oelf --eboot (Join-Path $out "eboot.bin") --paid 0x3800000000000011
if ($LASTEXITCODE -ne 0) { throw "create-fself failed" }

Write-Host "Built:"
Write-Host "  $elf"
Write-Host "  $oelf"
Write-Host "Run it with:  python -m orbemu `"$oelf`" --timeout 60"
