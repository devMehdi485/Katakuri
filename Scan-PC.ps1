#requires -Version 5.1
<#
.SYNOPSIS
Diagnostic cible en lecture seule de traces D3M0N sur Windows.
.DESCRIPTION
N'execute aucun fichier suspect, ne supprime rien et n'envoie aucune donnee.
Ecrit uniquement des rapports JSON/HTML dans OutputDirectory.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory=(Join-Path (Get-Location).Path 'reports'),
    [string]$ProfilePath=$env:USERPROFILE,
    [switch]$OfflineProfile
)
$ErrorActionPreference='Stop'
try {
    if ($env:OS -ne 'Windows_NT') { throw 'Cet outil necessite Windows.' }
    Import-Module (Join-Path $PSScriptRoot 'src\Checks.psm1') -Force
    $profileRoot=[IO.Path]::GetFullPath($ProfilePath).TrimEnd('\','/')
    if (-not (Test-Path -LiteralPath $profileRoot -PathType Container)) { throw 'Profil introuvable.' }
    if (-not $OfflineProfile -and $profileRoot -ne [IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\','/')) {
        throw 'Un autre profil necessite -OfflineProfile pour eviter de melanger ses fichiers au registre de la session.'
    }
    Write-Host 'Verification locale en lecture seule. Aucun fichier suspect ne sera execute.'
    $indicators=Read-Indicators (Join-Path $PSScriptRoot 'indicators.json')
    $tempPath=if($OfflineProfile){Join-Path $profileRoot 'AppData\Local\Temp'}else{$env:TEMP}
    $report=Invoke-LocalChecks -Indicators $indicators -ProfileRoot $profileRoot -TempDirectory $tempPath -OfflineProfile:$OfflineProfile
    $report=ConvertTo-PublicReport -Report $report -ProfileRoot $profileRoot
    $out=[IO.Path]::GetFullPath($OutputDirectory)
    New-Item -ItemType Directory -Path $out -Force | Out-Null
    $base='check-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,6)
    $jsonPath=Join-Path $out ($base+'.json')
    $htmlPath=Join-Path $out ($base+'.html')
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    ConvertTo-ReportHtml $report | Set-Content -LiteralPath $htmlPath -Encoding UTF8
    Write-Host ('Resultat : '+$report.verdict)
    Write-Host ('Empreintes malveillantes : '+$report.summary.knownMalwareFiles+' ; indices suspects : '+$report.summary.suspiciousFindings+' ; erreurs : '+$report.summary.checksWithErrors)
    Write-Host ('Rapport HTML : '+$htmlPath)
    Write-Host ('Rapport JSON : '+$jsonPath)
    Write-Host 'Aucun indicateur trouve ne signifie pas que le PC est sain.'
    if ($report.summary.knownMalwareFiles -gt 0 -or $report.summary.suspiciousFindings -gt 0) { exit 1 }
    if ($report.summary.checksWithErrors -gt 0) { exit 2 }
    exit 0
} catch {
    Write-Error ('Verification interrompue : '+$_.Exception.Message) -ErrorAction Continue
    exit 2
}
