[CmdletBinding()]
param([string]$ArchivePath)

$ErrorActionPreference = 'Stop'
$version = 'v1.0.7'
$name = "zapret2-$version"
$expectedHash = '35e14e4e1f345b870c3b87269fa45353efd597241a25304d38375c46b9fd2967'
$destination = Join-Path $PSScriptRoot $name
$requiredFiles = @(
    'binaries/windows-x86_64/winws2.exe'
    'binaries/windows-x86_64/WinDivert.dll'
    'binaries/windows-x86_64/WinDivert64.sys'
    'binaries/windows-x86_64/cygwin1.dll'
    'lua/zapret-lib.lua'
    'lua/zapret-antidpi.lua'
    'files/fake/quic_initial_www_google_com.bin'
    'init.d/windivert.filter.examples/windivert_part.quic_initial_ietf.txt'
)

function Assert-Zapret2Files([string]$Directory) {
    foreach ($file in $requiredFiles) {
        if (!(Test-Path -LiteralPath (Join-Path $Directory $file) -PathType Leaf)) {
            throw "Missing $file in $Directory. Move the incomplete installation aside and run setup again."
        }
    }
}

if (Test-Path -LiteralPath $destination) {
    Assert-Zapret2Files $destination
    Write-Host "Ready: $destination"
    return
}

$staging = Join-Path $PSScriptRoot ".zapret2-$([guid]::NewGuid())"
New-Item -Path $staging -ItemType Directory | Out-Null
try {
    if (!$ArchivePath) {
        $ArchivePath = Join-Path $staging "$name.zip"
        $url = "https://github.com/bol-van/zapret2/releases/download/$version/$name.zip"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $ArchivePath
    }
    if ((Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash -ne $expectedHash) {
        throw "SHA-256 mismatch for $ArchivePath"
    }

    $extracted = Join-Path $staging 'extracted'
    Expand-Archive -LiteralPath $ArchivePath -DestinationPath $extracted
    $source = Join-Path $extracted $name
    Assert-Zapret2Files $source
    [IO.Directory]::Move($source, $destination)
    Write-Host "Ready: $destination"
} finally {
    Remove-Item -LiteralPath $staging -Recurse -Force
}
