[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet("Validate", "Promote")][string]$Mode,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$GitCommit,
    [Parameter(Mandatory)][string]$ManifestSha256,
    [string]$ProductId = "d1574a9d-d898-4b63-bf7a-7ecd787c3996",
    [string]$Repository = "dev-bento/secret-bento",
    [string]$ApiBaseUrl = "https://api.polar.sh/v1"
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($env:POLAR_OAT)) { throw "POLAR_OAT is required." }
$headers = @{ Authorization = "Bearer $($env:POLAR_OAT)"; Accept = "application/json"; "Content-Type" = "application/json" }
function Invoke-PolarApi {
    param([Parameter(Mandatory)][ValidateSet("GET", "PATCH")][string]$Method, [Parameter(Mandatory)][string]$Path, [object]$Body)
    $arguments = @{ Uri = "$ApiBaseUrl$Path"; Method = $Method; Headers = $headers; ErrorAction = "Stop" }
    if ($null -ne $Body) { $arguments.Body = $Body | ConvertTo-Json -Depth 10 -Compress }
    Invoke-RestMethod @arguments
}
$tag = "v$Version"
$cargo = Get-Content -Raw (Join-Path $PSScriptRoot "..\Cargo.toml")
$match = [regex]::Match($cargo, '(?m)^version = "([^"]+)"')
if (-not $match.Success -or $match.Groups[1].Value -ne $Version) { throw "Cargo.toml version does not match $Version." }
$crate = Invoke-RestMethod -Uri "https://crates.io/api/v1/crates/secret-bento/$Version" -Headers @{ Accept = "application/json" }
if ($crate.version.num -ne $Version) { throw "crates.io did not return secret-bento $Version." }
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases/tags/$tag" -Headers @{ Accept = "application/vnd.github+json" }
if ($release.tag_name -ne $tag -or $release.draft -or $release.prerelease) { throw "GitHub Release $tag is missing or is not final." }
$product = Invoke-PolarApi -Method GET -Path "/products/$ProductId"
if ($product.id -ne $ProductId) { throw "Polar returned an unexpected product." }
if ($Mode -eq "Validate") { Write-Host "Validated Cargo, crates.io, GitHub Release, and Polar product for $tag."; return }
$metadata = @{}
if ($null -ne $product.metadata) { $product.metadata.psobject.Properties | ForEach-Object { $metadata[$_.Name] = $_.Value } }
$metadata.current_version = $Version
$metadata.crate_version = $Version
$metadata.github_tag = $tag
$metadata.git_commit = $GitCommit
$metadata.manifest_sha256 = $ManifestSha256
$metadata.release_status = "released"
$updated = Invoke-PolarApi -Method PATCH -Path "/products/$ProductId" -Body @{ metadata = $metadata }
if ($updated.metadata.current_version -ne $Version -or $updated.metadata.manifest_sha256 -ne $ManifestSha256) { throw "Polar promotion response did not contain expected metadata." }
Write-Host "Promoted Polar product $ProductId to $tag."
