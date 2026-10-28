$ErrorActionPreference = 'Stop'

# url64bit and checksum64: set by .github/workflows/chocolatey.yml at each release.
$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  unzipLocation  = Split-Path -Parent $MyInvocation.MyCommand.Definition
  url64bit       = 'https://github.com/AlphaJack/mercurio/releases/download/v0/mercurio-cli-x86_64-pc-windows-msvc.zip'
  checksum64     = 'XXXXXX'
  checksumType64 = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs
