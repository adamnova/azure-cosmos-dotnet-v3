# ------------------------------------------------------------
# Copyright (c) Microsoft Corporation.  All rights reserved.
# ------------------------------------------------------------
# SPIKE (Option B) launcher: thin-server compat-matrix. Builds the two version-pinned ASP.NET shims
# (OLD 1.0.0-preview07 from nuget.org, NEW 1.1.0-preview01 from local-feed) and the typed driver,
# then runs the driver. The driver launches BOTH servers at once, health-checks + version-guards
# them, drives the matrix over HTTP against ONE shared Cosmos DB, prints the grid, and returns:
#   0 = all cross-version/cross-processor cells PASS   1 = data/version/count/tamper break
#   3 = emulator unreachable (skip; shims still built + version-guarded)
# This is the run-matrix.ps1 analogue for the server architecture; compare the two side by side.
[CmdletBinding()]
param(
  [string]$Endpoint = $env:COSMOS_ENDPOINT,
  [string]$Key      = $env:COSMOS_KEY,
  [string]$Database = "compat-matrix-srv-$([Guid]::NewGuid().ToString('N').Substring(0,8))",
  [ValidateSet('Newtonsoft','Stream','both')]
  [string]$Processor = 'both',
  [switch]$NoBuild
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Endpoint) { $Endpoint = 'http://127.0.0.1:8081/' }
if (-not $Key) { $Key = 'C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==' }

$projects = @(
  "$root\Old\CompatMatrix.Server.Old.csproj",
  "$root\New\CompatMatrix.Server.New.csproj",
  "$root\Driver\CompatMatrix.Server.Driver.csproj"
)
if (-not $NoBuild) {
  foreach ($p in $projects) { dotnet build $p -c Release -v q | Out-Null }
}

$driver = "$root\Driver\bin\Release\net8.0\CompatMatrix.Server.Driver.dll"
& dotnet $driver "--endpoint=$Endpoint" "--key=$Key" "--db=$Database" "--processor=$Processor"
exit $LASTEXITCODE
