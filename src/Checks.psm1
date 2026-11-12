Set-StrictMode -Version 2.0

function Read-Indicators {
    param([Parameter(Mandatory=$true)][string]$Path)
    $data = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($data.schemaVersion -ne 1) { throw 'Version des indicateurs non prise en charge.' }
    foreach ($entry in $data.files) {
        if ($entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Empreinte SHA-256 invalide.' }
        if ($entry.classification -notin @('malware','suspicious')) { throw 'Classification invalide.' }
        if ([IO.Path]::IsPathRooted($entry.relativePath) -or $entry.relativePath -match '(^|[\/])\.\.([\/]|$)' -or $entry.relativePath.Contains(':')) {
            throw 'Chemin indicateur hors perimetre.'
        }
    }
    foreach ($name in $data.collectionFiles) {
        if ($name -match '[\/:]' -or $name -notmatch '^d3[a-z]+\.txt$') { throw 'Nom de sortie invalide.' }
    }
    return $data
}

function Protect-ReportText {
    param([AllowNull()][string]$Text,[string]$ProfileRoot)
    if ($null -eq $Text) { return '' }
    # Masque le profil inspecte, puis les autres chemins de profils Windows courants.
    if ($ProfileRoot) { $Text = [regex]::Replace($Text,[regex]::Escape($ProfileRoot.TrimEnd('\','/')),'%USERPROFILE%','IgnoreCase') }
    return [regex]::Replace($Text,'(?i)[A-Z]:[\\/]Users[\\/][^\\/\s"<>]+','%OTHER_USERPROFILE%')
}

function New-Finding {
    param([string]$Id,[string]$Level,[string]$Kind,[string]$Location,[string]$Detail,[string]$Hash='')
    return [pscustomobject][ordered]@{ id=$Id; level=$Level; kind=$Kind; location=$Location; detail=$Detail; sha256=$Hash }
}

function Get-FileClassification {
    param([string]$ActualHash,[string]$ExpectedHash,[string]$Classification)
    if ($ActualHash -eq $ExpectedHash -and $Classification -eq 'malware') { return 'KnownMalware' }
    if ($ActualHash -eq $ExpectedHash) { return 'KnownSuspiciousFile' }
    return 'SuspiciousPath'
}

function Get-StartupMatches {
    param([AllowEmptyString()][string]$Command,[object[]]$Indicators)
    # Un simple nom de valeur comme "adobe" ne suffit jamais a declencher une alerte.
    foreach ($entry in $Indicators) {
        $leaf = ($entry.relativePath -split '[\\/]')[-1]
        $pattern = '(?i)(?<![A-Za-z0-9_.-])' + [regex]::Escape($leaf) + '(?![A-Za-z0-9_.-])'
        if ($Command -match $pattern) { $entry.id }
    }
}

function Invoke-LocalChecks {
    param([Parameter(Mandatory=$true)][object]$Indicators,[Parameter(Mandatory=$true)][string]$ProfileRoot,[string]$TempDirectory,[switch]$OfflineProfile)
    $findings = New-Object 'System.Collections.Generic.List[object]'
    $coverage = New-Object 'System.Collections.Generic.List[object]'
    $checked = 0
    foreach ($entry in $Indicators.files) {
        $path = Join-Path $ProfileRoot $entry.relativePath.Replace('/',[IO.Path]::DirectorySeparatorChar)
        try {
            if (Test-Path -LiteralPath $path -ErrorAction Stop) {
                $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                if ($item.PSIsContainer) { throw 'Un dossier occupe le chemin du fichier attendu.' }
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Lien symbolique non suivi.' }
                $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
                $kind = Get-FileClassification $hash $entry.sha256 $entry.classification
                $level = 'Warning'; $detail = 'Nom/emplacement suspect, mais empreinte differente : verification necessaire.'
                if ($kind -eq 'KnownMalware') { $level='High'; $detail='Empreinte identique a un echantillon malveillant analyse.' }
                elseif ($kind -eq 'KnownSuspiciousFile') { $detail='Empreinte du lanceur renomme connu ; malveillance non confirmee.' }
                $findings.Add((New-Finding $entry.id $level $kind $path $detail $hash))
            }
            $checked++
        } catch {
            $coverage.Add([pscustomobject]@{check='file';location=$path;status='Error';detail=$_.Exception.Message})
        }
    }
    $coverage.Add([pscustomobject]@{check='target-files';status='Completed';checked=$checked;expected=@($Indicators.files).Count})

    if (-not $TempDirectory) { $TempDirectory=Join-Path $ProfileRoot 'AppData\Local\Temp' }
    $tempRoots=@($TempDirectory,(Join-Path $ProfileRoot 'AppData\Local\Temp')) | Select-Object -Unique
    foreach ($tempRoot in $tempRoots) {
        foreach ($name in $Indicators.collectionFiles) {
            $path=Join-Path $tempRoot $name
            try {
                if (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop) {
                    $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    # Ne lit jamais les mots de passe, cookies ou autres contenus collectes.
                    $detail='Nom de sortie associe au stealer ; taille {0} octets ; modification UTC {1}. Contenu non lu.' -f $item.Length,$item.LastWriteTimeUtc.ToString('o')
                    $findings.Add((New-Finding 'collection-file' 'Warning' 'CollectionArtifact' $path $detail))
                }
            } catch { $coverage.Add([pscustomobject]@{check='temp-file';location=$path;status='Error';detail=$_.Exception.Message}) }
        }
    }

    $defender=$null
    if ($OfflineProfile) {
        $coverage.Add([pscustomobject]@{check='live-windows';status='Skipped';detail='Profil hors ligne : registre, processus et Defender non examines.'})
    } else {
        foreach ($key in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')) {
            try {
                if (Test-Path -LiteralPath $key -ErrorAction Stop) {
                    $values=Get-ItemProperty -LiteralPath $key -ErrorAction Stop
                    foreach ($prop in $values.PSObject.Properties) {
                        if ($prop.Name -match '^PS') { continue }
                        $matchedIds=@(Get-StartupMatches ([string]$prop.Value) $Indicators.files)
                        foreach ($id in $matchedIds) {
                            # Ne sauvegarde pas les lignes de commande pouvant contenir des secrets.
                            $findings.Add((New-Finding $id 'Warning' 'StartupReference' ($key+' :: '+$prop.Name) 'Demarrage contenant un nom de fichier cible ; contenu de la commande non exporte.'))
                        }
                    }
                }
                $coverage.Add([pscustomobject]@{check='registry';location=$key;status='Completed'})
            } catch { $coverage.Add([pscustomobject]@{check='registry';location=$key;status='Error';detail=$_.Exception.Message}) }
        }
        try {
            foreach ($proc in Get-CimInstance Win32_Process -ErrorAction Stop) {
                # Seulement Python et le lanceur suspect, pour eviter les commandes de l'analyste.
                if ($proc.Name -notmatch '^(pythonw?|WinSecurityUpdate)\.exe$') { continue }
                if ($proc.Name -ieq 'WinSecurityUpdate.exe') { $ids=@('suspicious-startup-launcher') }
                else { $ids=@(Get-StartupMatches ([string]$proc.CommandLine) $Indicators.files) }
                foreach ($id in $ids) {
                    $findings.Add((New-Finding $id 'Warning' 'RunningReference' ('PID '+$proc.ProcessId+' / '+$proc.Name) 'Processus correspondant a un indicateur ; commande non exportee.'))
                }
            }
            $coverage.Add([pscustomobject]@{check='processes';status='Completed';detail='Certaines commandes de processus peuvent etre inaccessibles sans administration.'})
        } catch { $coverage.Add([pscustomobject]@{check='processes';status='Error';detail=$_.Exception.Message}) }
        try {
            if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { throw 'Module Defender indisponible.' }
            $mp=Get-MpComputerStatus -ErrorAction Stop
            $defender=[pscustomobject]@{antivirusEnabled=$mp.AntivirusEnabled;realTimeProtectionEnabled=$mp.RealTimeProtectionEnabled;signatureUpdated=$mp.AntivirusSignatureLastUpdated;lastQuickScanEnd=$mp.QuickScanEndTime;lastFullScanEnd=$mp.FullScanEndTime}
            if (-not $mp.AntivirusEnabled -or -not $mp.RealTimeProtectionEnabled) {
                $findings.Add((New-Finding 'defender-status' 'Info' 'ProtectionStatus' 'Microsoft Defender' 'Defender ou sa protection temps reel est inactif ; verifier si un autre antivirus prend le relais.'))
            }
            $coverage.Add([pscustomobject]@{check='defender-status';status='Completed';detail='Lecture du statut uniquement ; aucune analyse antivirus lancee.'})
        } catch { $coverage.Add([pscustomobject]@{check='defender-status';status='Error';detail=$_.Exception.Message}) }
    }
    $known=@($findings | Where-Object kind -eq 'KnownMalware').Count
    $suspicious=@($findings | Where-Object level -eq 'Warning').Count
    $errors=@($coverage | Where-Object status -eq 'Error').Count
    $verdict='NoKnownIndicators'
    if ($errors -gt 0) { $verdict='Incomplete' }
    if ($suspicious -gt 0) { $verdict='SuspiciousIndicators' }
    if ($known -gt 0) { $verdict='KnownMalwareFound' }
    return [pscustomobject][ordered]@{
        tool='PC Security Check';toolVersion='1.0.0';indicatorVersion=$Indicators.updated;createdUtc=[DateTime]::UtcNow.ToString('o')
        mode=$(if($OfflineProfile){'OfflineProfile'}else{'CurrentUser'});verdict=$verdict
        summary=[pscustomobject]@{knownMalwareFiles=$known;suspiciousFindings=$suspicious;checksWithErrors=$errors}
        limitations='Detection ciblee. Aucun indicateur ne signifie pas PC sain. Pas de scan exhaustif, memoire, rootkits, taches/services, charges distantes ni autres comptes.'
        findings=@($findings.ToArray());coverage=@($coverage.ToArray());defender=$defender
    }
}

function ConvertTo-PublicReport {
    param([Parameter(Mandatory=$true)][object]$Report,[string]$ProfileRoot)
    # Nettoyage des champs avant serialisation ; jamais de remplacement dans le JSON lui-meme.
    foreach ($item in @($Report.findings)+@($Report.coverage)) {
        foreach ($property in @('location','detail')) {
            if ($null -ne $item.PSObject.Properties[$property]) { $item.$property=Protect-ReportText $item.$property $ProfileRoot }
        }
    }
    return $Report
}

function ConvertTo-ReportHtml {
    param([Parameter(Mandatory=$true)][object]$Report)
    $encode={param($s) [System.Net.WebUtility]::HtmlEncode([string]$s)}
    $rows=foreach($f in $Report.findings){ '<tr><td>'+(& $encode $f.level)+'</td><td>'+(& $encode $f.kind)+'</td><td>'+(& $encode $f.location)+'</td><td>'+(& $encode $f.detail)+'</td></tr>' }
    if (-not $rows) { $rows='<tr><td colspan="4">Aucun indicateur cible trouve. Cela ne certifie pas que le PC est sain.</td></tr>' }
    $coverageRows=foreach($c in $Report.coverage){'<li>'+(& $encode $c.check)+' : '+(& $encode $c.status)+$(if($null -ne $c.PSObject.Properties['detail']){' - '+(& $encode $c.detail)})+'</li>'}
    return @"
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>PC Security Check</title><style>body{font:16px system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 24px;color:#172033;background:#f6f8fb}h1{font-size:30px}table{border-collapse:collapse;width:100%;background:white}th,td{border:1px solid #ccd3df;padding:12px;text-align:left;overflow-wrap:anywhere}strong{color:#7d291c}.note{padding:16px;background:#fff1d6}code{overflow-wrap:anywhere}</style></head><body><h1>PC Security Check</h1><p>UTC : $(& $encode $Report.createdUtc) · version $(& $encode $Report.toolVersion)</p><p><strong>Resultat : $(& $encode $Report.verdict)</strong></p><p class="note">$(& $encode $Report.limitations)</p><p>Fichiers malveillants reconnus : $($Report.summary.knownMalwareFiles) · indices suspects : $($Report.summary.suspiciousFindings) · controles en erreur : $($Report.summary.checksWithErrors)</p><table><thead><tr><th>Niveau</th><th>Type</th><th>Emplacement</th><th>Explication</th></tr></thead><tbody>$($rows -join "`n")</tbody></table><h2>Couverture</h2><ul>$($coverageRows -join "`n")</ul><p>Diagnostic uniquement : aucune suppression, aucun envoi reseau. Les noms de profil sont masques ; relisez le rapport avant tout partage.</p></body></html>
"@
}

Export-ModuleMember -Function Read-Indicators,Protect-ReportText,Get-FileClassification,Get-StartupMatches,Invoke-LocalChecks,ConvertTo-PublicReport,ConvertTo-ReportHtml
