# ------------------------------------------------------------
# Copyright (c) Microsoft Corporation.  All rights reserved.
# ------------------------------------------------------------
# SPIKE launcher: cross-version Encryption.Custom compat matrix over a long-lived worker per version.
# Two transports share ONE transport-agnostic orchestrator (driver-shared/MatrixRunner):
#   -Transport http  (Option B) : ASP.NET Core shims  + HTTP driver
#   -Transport stdio (Option C) : stdio NDJSON workers + stdio driver
#   -Transport both             : run both, back to back
# Each driver launches BOTH version processes at once, version-guards them, drives the matrix against
# ONE shared Cosmos DB, prints the grid, and returns: 0 = all PASS, 1 = break, 3 = emulator skip.
[CmdletBinding()]
param(
  [string]$Endpoint = $env:COSMOS_ENDPOINT,
  [string]$Key      = $env:COSMOS_KEY,
  [string]$Database = "compat-matrix-srv-$([Guid]::NewGuid().ToString('N').Substring(0,8))",
  [ValidateSet('Newtonsoft','Stream','both')]
  [string]$Processor = 'both',
  [ValidateSet('http','stdio','both')]
  [string]$Transport = 'http',
  [switch]$NoBuild
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Endpoint) { $Endpoint = 'http://127.0.0.1:8081/' }
if (-not $Key) { $Key = 'C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==' }

$http  = @("$root\Old\CompatMatrix.Server.Old.csproj", "$root\New\CompatMatrix.Server.New.csproj", "$root\Driver\CompatMatrix.Server.Driver.csproj")
$stdio = @("$root\OldWorker\CompatMatrix.Worker.Old.csproj", "$root\NewWorker\CompatMatrix.Worker.New.csproj", "$root\DriverStdio\CompatMatrix.Stdio.Driver.csproj")

$projects = @()
if ($Transport -in 'http','both')  { $projects += $http }
if ($Transport -in 'stdio','both') { $projects += $stdio }
if (-not $NoBuild) { foreach ($p in $projects) { dotnet build $p -c Release -v q | Out-Null } }

$rc = 0
if ($Transport -in 'http','both') {
  $d = "$root\Driver\bin\Release\net8.0\CompatMatrix.Server.Driver.dll"
  & dotnet $d "--endpoint=$Endpoint" "--key=$Key" "--db=$Database-http" "--processor=$Processor"
  if ($LASTEXITCODE -ne 0) { $rc = $LASTEXITCODE }
}
if ($Transport -in 'stdio','both') {
  $d = "$root\DriverStdio\bin\Release\net8.0\CompatMatrix.Stdio.Driver.dll"
  & dotnet $d "--endpoint=$Endpoint" "--key=$Key" "--db=$Database-stdio" "--processor=$Processor"
  if ($LASTEXITCODE -ne 0) { $rc = $LASTEXITCODE }
}
exit $rc
