param(
    [string]$TargetPath = ".\ps",
    [string]$SignatureFile = ".\siglist.txt"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Convert-HexToByteArray {
    param([string]$Hex)

    $Hex = ($Hex -replace '\s+', '').ToUpper()

    if ([string]::IsNullOrWhiteSpace($Hex)) {
        return [byte[]]@()
    }

    if (($Hex.Length % 2) -ne 0) {
        throw "Invalid Hex string: $Hex"
    }

    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $Hex.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($Hex.Substring($i, 2), 16)
    }

    return [byte[]]$bytes
}

function Test-BytePrefix {
    param(
        $Data,
        $Prefix
    )

    [byte[]]$DataBytes = @()
    [byte[]]$PrefixBytes = @()

    if ($null -ne $Data)   { $DataBytes = [byte[]]$Data }
    if ($null -ne $Prefix) { $PrefixBytes = [byte[]]$Prefix }

    if ($PrefixBytes.Count -eq 0) { return $true }
    if ($DataBytes.Count -lt $PrefixBytes.Count) { return $false }

    for ($i = 0; $i -lt $PrefixBytes.Count; $i++) {
        if ($DataBytes[$i] -ne $PrefixBytes[$i]) {
            return $false
        }
    }

    return $true
}

function Test-ByteSuffix {
    param(
        $Data,
        $Suffix
    )

    [byte[]]$DataBytes = @()
    [byte[]]$SuffixBytes = @()

    if ($null -ne $Data)   { $DataBytes = [byte[]]$Data }
    if ($null -ne $Suffix) { $SuffixBytes = [byte[]]$Suffix }

    if ($SuffixBytes.Count -eq 0) { return $true }
    if ($DataBytes.Count -lt $SuffixBytes.Count) { return $false }

    $start = $DataBytes.Count - $SuffixBytes.Count

    for ($i = 0; $i -lt $SuffixBytes.Count; $i++) {
        if ($DataBytes[$start + $i] -ne $SuffixBytes[$i]) {
            return $false
        }
    }

    return $true
}

function Get-FileEdgeBytes {
    param(
        [string]$Path,
        [int]$HeadLength,
        [int]$TailLength
    )

    $item = Get-Item -LiteralPath $Path
    $length = $item.Length

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $headCount = [Math]::Min($HeadLength, [int]$length)
        [byte[]]$headBytes = @()
        if ($headCount -gt 0) {
            $headBytes = New-Object byte[] $headCount
            [void]$stream.Read($headBytes, 0, $headCount)
        }

        $tailCount = [Math]::Min($TailLength, [int]$length)
        [byte[]]$tailBytes = @()
        if ($tailCount -gt 0) {
            $tailBytes = New-Object byte[] $tailCount
            $stream.Seek(-1 * $tailCount, [System.IO.SeekOrigin]::End) | Out-Null
            [void]$stream.Read($tailBytes, 0, $tailCount)
        }

        return [pscustomobject]@{
            Head = [byte[]]$headBytes
            Tail = [byte[]]$tailBytes
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Import-Signatures {
    param([string]$Path)

    $signatures = @()

    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()

        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed.StartsWith("#")) { continue }
        if ($trimmed -match '^\s*Filetype\s*;') { continue }

        $parts = $trimmed -split ';', 3
        if ($parts.Count -lt 2) { continue }

        $type = $parts[0].Trim().ToUpper()
        $headerHex = $parts[1].Trim().ToUpper()
        $footerHex = if ($parts.Count -ge 3) { $parts[2].Trim().ToUpper() } else { "" }

        if ([string]::IsNullOrWhiteSpace($type) -or [string]::IsNullOrWhiteSpace($headerHex)) {
            continue
        }

        $signatures += [pscustomobject]@{
            Type        = $type
            HeaderBytes = [byte[]](Convert-HexToByteArray $headerHex)
            FooterBytes = [byte[]](Convert-HexToByteArray $footerHex)
        }
    }

    return $signatures
}

function Get-ExpectedTypesFromExtension {
    param([string]$Extension)

    $ext = $Extension.TrimStart('.').ToUpper()

    $map = @{
        EXE  = @("PE")
        DLL  = @("PE")
        SYS  = @("PE")
        SCR  = @("PE")
        CPL  = @("PE")
        OCX  = @("PE")
        MSI  = @("PE")
        JPG  = @("JPEG")
        JPEG = @("JPEG")
        JPE  = @("JPEG")
    }

    if ($map.ContainsKey($ext)) {
        return $map[$ext]
    }

    return @($ext)
}

function Find-MatchingSignature {
    param(
        $HeadBytes,
        $TailBytes,
        [array]$Signatures
    )

    foreach ($sig in $Signatures) {
        $headerOk = Test-BytePrefix -Data $HeadBytes -Prefix $sig.HeaderBytes
        $footerOk = Test-ByteSuffix -Data $TailBytes -Suffix $sig.FooterBytes

        if ($headerOk -and $footerOk) {
            return $sig.Type
        }
    }

    return $null
}

function Get-ArrayLength {
    param($Value)

    if ($null -eq $Value) {
        return 0
    }

    if ($Value -is [System.Array]) {
        return $Value.Length
    }

    return 0
}

if (-not (Test-Path -LiteralPath $TargetPath)) {
    throw "TargetPath does not exist: $TargetPath"
}

if (-not (Test-Path -LiteralPath $SignatureFile)) {
    throw "Signature file does not exist: $SignatureFile"
}

$signatures = Import-Signatures -Path $SignatureFile

if (-not $signatures -or $signatures.Count -eq 0) {
    throw "No valid signatures found in $SignatureFile"
}

$maxHeaderLength = (($signatures | ForEach-Object { Get-ArrayLength $_.HeaderBytes } | Measure-Object -Maximum).Maximum)
$maxFooterLength = (($signatures | ForEach-Object { Get-ArrayLength $_.FooterBytes } | Measure-Object -Maximum).Maximum)

if ($null -eq $maxHeaderLength) { $maxHeaderLength = 0 }
if ($null -eq $maxFooterLength) { $maxFooterLength = 0 }

Write-Host "Searching recursively for file signatures in: $(Resolve-Path $TargetPath)"
Write-Host "Using file signatures (magic numbers) from: $(Resolve-Path $SignatureFile)"
Write-Host "Type;Start;End(may be empty)"

Get-ChildItem -LiteralPath $TargetPath -File -Recurse | ForEach-Object {
    $file = $_
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash

    $edgeBytes = Get-FileEdgeBytes -Path $file.FullName -HeadLength $maxHeaderLength -TailLength $maxFooterLength
    $detectedType = Find-MatchingSignature -HeadBytes $edgeBytes.Head -TailBytes $edgeBytes.Tail -Signatures $signatures

    $expectedTypes = Get-ExpectedTypesFromExtension -Extension $file.Extension

    if ($null -eq $detectedType) {
        Write-Host "⚠️ File: $($file.FullName) is NOT PRESENT IN FILE SIGNATURE LIST! SHA256Hash: $hash"
    }
    elseif ($expectedTypes -contains $detectedType) {
        Write-Host "✅ File: $($file.FullName) is a VALID $detectedType file! SHA256Hash: $hash"
    }
    else {
        Write-Host "❌ File: $($file.FullName) is a ROUGE $detectedType file! SHA256Hash: $hash"
    }
}