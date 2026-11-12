#requires -Version 5.1
param([string]$TestRoot=[IO.Path]::GetTempPath())
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\Checks.psm1') -Force
$passed=0
function Assert-True($Condition,[string]$Message) {
    if (-not $Condition) { throw ('ECHEC : '+$Message) }
    $script:passed++
    Write-Host ('OK : '+$Message)
}
$base=[IO.Path]::GetFullPath($TestRoot)
New-Item -ItemType Directory -Path $base -Force | Out-Null
$caseRoot=Join-Path $base ('pc-security-check-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $caseRoot | Out-Null
try {
    $ind=Read-Indicators (Join-Path $PSScriptRoot '..\indicators.json')
    Assert-True (@($ind.files).Count -eq 7) 'Configuration attendue lisible'
    Assert-True ((Get-FileClassification ('A'*64) ('A'*64) 'malware') -eq 'KnownMalware') 'Une empreinte exacte confirme le fichier connu'
    Assert-True ((Get-FileClassification ('A'*64) ('A'*64) 'suspicious') -eq 'KnownSuspiciousFile') 'Le lanceur suspect ne devient pas un malware confirme'
    Assert-True ((Get-FileClassification ('B'*64) ('A'*64) 'malware') -eq 'SuspiciousPath') 'Un nom identique avec hash different reste suspect'
    Assert-True (@(Get-StartupMatches 'C:\Program Files\Adobe\adobe.exe' $ind.files).Count -eq 0) 'Pas de faux positif sur Adobe seul'
    Assert-True (@(Get-StartupMatches 'pythonw.exe "C:\Somewhere\Zotero.Spoc"' $ind.files).Count -eq 1) 'Reference de demarrage reconnue'
    Assert-True (@(Get-StartupMatches 'C:\Tools\NotWinSecurityUpdate.exe' $ind.files).Count -eq 0) 'Pas de correspondance de suffixe approximative'
    $clean=Invoke-LocalChecks -Indicators $ind -ProfileRoot $caseRoot -OfflineProfile
    Assert-True ($clean.verdict -eq 'NoKnownIndicators') 'Profil de test vide : aucun indicateur'
    Assert-True (@($clean.coverage | Where-Object status -eq 'Skipped').Count -gt 0) 'Mode hors ligne explicitement signale'

    # Fichier de test BENIN, jamais un echantillon de malware.
    $fixture=Join-Path $caseRoot $ind.files[0].relativePath
    New-Item -ItemType Directory -Path (Split-Path $fixture) -Force | Out-Null
    [IO.File]::WriteAllText($fixture,'BENIGN TEST FIXTURE - no executable code')
    $before=(Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash
    $warn=Invoke-LocalChecks -Indicators $ind -ProfileRoot $caseRoot -OfflineProfile
    Assert-True ($warn.verdict -eq 'SuspiciousIndicators') 'Nom suspect ne suffit pas a confirmer malware'
    # Configuration modifiee EN MEMOIRE seulement pour tester le chemin positif.
    $ind.files[0].sha256=$before
    $positive=Invoke-LocalChecks -Indicators $ind -ProfileRoot $caseRoot -OfflineProfile
    Assert-True ($positive.summary.knownMalwareFiles -eq 1) 'Detection positive avec empreinte de fixture'
    Assert-True ((Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash -eq $before) 'Le scanner ne modifie ni ne supprime le fichier inspecte'
    $public=ConvertTo-PublicReport $positive $caseRoot
    Assert-True (-not (($public | ConvertTo-Json -Depth 8).Contains($caseRoot))) 'Chemin du profil masque dans JSON'
    $public.findings[0].detail='<script>alert("x")</script>'
    $html=ConvertTo-ReportHtml $public
    Assert-True ($html.Contains('&lt;script&gt;') -and -not $html.Contains('<script>')) 'HTML protege contre injection de contenu'
    Assert-True ($html.Contains("default-src 'none'")) 'Rapport HTML sans ressources externes'

    $bad=Join-Path $caseRoot 'bad-indicators.json'
    $ind.files[0].relativePath='../outside'
    $ind | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $bad -Encoding UTF8
    $rejected=$false
    try { $null=Read-Indicators $bad } catch { $rejected=$true }
    Assert-True $rejected 'Configuration avec traversee de chemin refusee'
    Write-Host ('SUCCES : '+$passed+' tests ; aucun malware utilise.')
} finally {
    # Suppression reservee au repertoire de fixtures cree par CE test.
    $resolved=[IO.Path]::GetFullPath($caseRoot)
    $prefix=$base.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
    if ($resolved.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -match '^pc-security-check-test-[a-f0-9]{32}$') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    } else { throw 'Nettoyage refuse : repertoire de test hors perimetre.' }
}
