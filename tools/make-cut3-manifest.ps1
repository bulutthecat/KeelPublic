# KeelShim - Windows 7 user-mode UI translation for the Windows 10 kernel
# Copyright (C) 2026 Kevin Dalli <projectkeel@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

[CmdletBinding()]
param(
    [string]$Cut3,
    [string]$Manifest,
    [string]$Raw,
    [switch]$Write,
    [switch]$AllowDonorMismatch
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
if (-not $Cut3)     { $Cut3 = Join-Path $root 'donor\cut3' }
if (-not $Manifest) { $Manifest = Join-Path $here 'cut3-manifest.json' }
if (-not $Raw)      { $Raw = Join-Path $root 'donor\raw' }

# produced from scratch by the build, so they have no donor file to start from
$GeneratedOnly = @('keel32.dll', 'keelaux.dll', 'keelkr32.dll', 'keelstub.dll', 'kntdl.dll',
                   'Keel.Common-Controls\Keel.Common-Controls.manifest')

function Test-Generated([string]$rel) {
    if ($GeneratedOnly -contains $rel) { return $true }
    return ((Split-Path $rel -Leaf) -like 'api-ms*')
}

function Get-ByteDistance([byte[]]$target, [string]$path) {
    $b = [IO.File]::ReadAllBytes($path)
    if ($b.Length -ne $target.Length) { return [int]::MaxValue }
    $n = 0
    for ($i = 0; $i -lt $b.Length; $i++) { if ($b[$i] -ne $target[$i]) { $n++ } }
    return $n
}

function Get-Cut3Files([string]$dir) {
    Get-ChildItem $dir -Recurse -File -Force | Sort-Object FullName | ForEach-Object {
        [pscustomobject]@{
            path   = $_.FullName.Substring($dir.Length).TrimStart('\')
            size   = $_.Length
            sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        }
    }
}

if ($Write) {
    if (-not (Test-Path $Cut3)) { throw "donor\cut3 not found at $Cut3 so nothing to record" }
    if (-not (Test-Path $Raw))  { throw "donor\raw not found at $Raw so cannot record where each file came from" }

    $bySize = @{}; $byLeaf = @{}
    foreach ($f in (Get-ChildItem $Raw -Recurse -File -Force)) {
        $rel = $f.FullName.Substring($Raw.Length + 1)
        $k = ($f.Name.ToLower() + '|' + $f.Length)
        if (-not $bySize.ContainsKey($k)) { $bySize[$k] = @() }
        $bySize[$k] += $rel
        $l = $f.Name.ToLower()
        if (-not $byLeaf.ContainsKey($l)) { $byLeaf[$l] = @() }
        $byLeaf[$l] += $rel
    }

    # a recorded source is kept, guessing it by name picked System32's v5 comctl32 for the v6 assembly
    $prevFrom = @{}
    if (Test-Path $Manifest) {
        foreach ($p in (Get-Content $Manifest -Raw | ConvertFrom-Json).files) {
            if ($p.from -and (Test-Path -LiteralPath (Join-Path $Raw ($p.from -replace '/', '\')))) { $prevFrom[$p.path] = $p.from }
        }
    }

    $files = foreach ($f in (Get-Cut3Files $Cut3)) {
        $leaf = (Split-Path $f.path -Leaf)
        $e = [ordered]@{ path = $f.path; size = $f.size; sha256 = $f.sha256 }

        $src = $null
        foreach ($cand in @($bySize[($leaf.ToLower() + '|' + $f.size)])) {
            if ($cand -and (Get-FileHash (Join-Path $Raw $cand) -Algorithm SHA256).Hash -eq $f.sha256) { $src = $cand; break }
        }
        if ($src) {
            $e.from = $src -replace '\\', '/'
        }
        elseif ($prevFrom.ContainsKey($f.path)) {
            $e.from = $prevFrom[$f.path]
            $e.built = $true
        }
        elseif (-not (Test-Generated $f.path)) {
            # patched in place by the build, so record the pristine donor copy it starts from
            $all = @($byLeaf[$leaf.ToLower()])
            if (-not $all) { throw "no donor source for $($f.path) under $Raw" }
            # an in-place import patch keeps the size, so same-size donor copies are the candidates
            $same = @($all | Where-Object { (Get-Item (Join-Path $Raw $_) -Force).Length -eq $f.size })
            if ($same.Count -gt 1) {
                # with several builds of the same assembly the real source is the one closest to the patched file
                $tgt = [IO.File]::ReadAllBytes((Join-Path $Cut3 $f.path))
                $same = @($same | Sort-Object { Get-ByteDistance $tgt (Join-Path $Raw $_) })
            }
            $pref = @(if ($same.Count) { $same } else {
                $all | Sort-Object { if ($_ -like 'Windows\System32\*') { 0 } elseif ($_ -like 'Windows\*') { 1 } else { 2 } }
            })
            $e.from = $pref[0] -replace '\\', '/'
            $e.built = $true
        }
        else {
            $e.built = $true
        }
        [pscustomobject]$e
    }

    $doc = [ordered]@{
        note      = 'SHA-256 of every file in donor\cut3 and the donor\raw file it is built from. No Microsoft binaries here, only hashes.'
        recorded  = (Get-Date).ToString('yyyy-MM-dd')
        fileCount = @($files).Count
        files     = $files
    }
    $doc | ConvertTo-Json -Depth 4 | Set-Content $Manifest -Encoding UTF8
    $built = @($files | Where-Object { $_.built }).Count
    Write-Host "recorded $(@($files).Count) files ($built built here) -> $Manifest"
    return
}

if (-not (Test-Path $Manifest)) { throw "no cut3 manifest at $Manifest so run with -Write on a known-good tree" }
if (-not (Test-Path $Cut3)) {
    Write-Host "donor\cut3 is MISSING ($Cut3)." -ForegroundColor Red
    Write-Host 'build it from donor\raw with .\tools\make-cut3.ps1'
    exit 2
}

$want = (Get-Content $Manifest -Raw | ConvertFrom-Json)
$have = @{}
foreach ($f in (Get-Cut3Files $Cut3)) { $have[$f.path] = $f }

$missing = @(); $changed = @(); $resized = @(); $extra = @(); $builtOk = 0
foreach ($w in $want.files) {
    $h = $have[$w.path]
    if (-not $h) { $missing += $w.path; continue }
    # a file this machine builds never hash-matches a recording from another machine, but one built from the wrong donor file is far off its size
    if ($w.built) {
        if ([Math]::Abs($h.size - $w.size) -gt ($w.size / 4)) { $resized += ('{0}  ({1} bytes, recorded {2})' -f $w.path, $h.size, $w.size) }
        else { $builtOk++ }
        continue
    }
    if ($h.sha256 -ne $w.sha256) { $changed += $w.path }
}
$wantPaths = @{}; foreach ($w in $want.files) { $wantPaths[$w.path] = $true }
foreach ($k in $have.Keys) { if (-not $wantPaths[$k]) { $extra += $k } }

Write-Host ("cut3 {0} files on disk, manifest expects {1} ({2} built here, recorded {3})" -f $have.Count, $want.fileCount, $builtOk, $want.recorded)
foreach ($set in @(@{n='MISSING'; v=$missing}, @{n='CHANGED'; v=$changed}, @{n='BUILT FROM THE WRONG FILE'; v=$resized})) {
    if ($set.v.Count) {
        Write-Host ("  {0} {1}" -f $set.n, $set.v.Count) -ForegroundColor Red
        $set.v | Select-Object -First 12 | ForEach-Object { Write-Host "    $_" }
        if ($set.v.Count -gt 12) { Write-Host "    ... and $($set.v.Count - 12) more" }
    }
}

if ($extra.Count) {
    Write-Host ("  extra (not in manifest, not an error) {0}" -f $extra.Count) -ForegroundColor DarkYellow
    $extra | Select-Object -First 8 | ForEach-Object { Write-Host "    $_" }
}
if ($missing.Count -or ((-not $AllowDonorMismatch) -and ($changed.Count -or $resized.Count))) { Write-Host 'cut3 DOES NOT MATCH the manifest.' -ForegroundColor Red; exit 1 }
if ($changed.Count -or $resized.Count) { Write-Host 'cut3 does not match the manifest, accepted because of -AllowDonorMismatch.' -ForegroundColor Yellow; exit 0 }
Write-Host 'cut3 matches the manifest.' -ForegroundColor Green
