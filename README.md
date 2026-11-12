# Katakuri - PC Security Check

Un outil PowerShell **local, sans suppression et sans télémétrie** pour rechercher des indicateurs d'un stealer Python s'auto-identifiant **D3M0N STEALER V2**.

**Ce n'est pas un antivirus généraliste. Un résultat sans alerte ne certifie pas que le PC est sain.** Le nom D3M0N provient du code analysé : il n'identifie pas l'auteur d'une attaque.

## Démarrer

Windows 10/11, Windows PowerShell **5.1** ou PowerShell **7**. Aucun paquet à installer. Les droits administrateur ne sont pas requis pour commencer ; certaines informations peuvent être inaccessibles.

1. Télécharger le dépôt ou son ZIP, puis l'extraire.
2. Lire `Scan-PC.ps1`, `src/Checks.psm1` et `indicators.json` avant de les exécuter.
3. Ouvrir PowerShell dans le dossier extrait et lancer :

```powershell
powershell.exe -NoProfile -File .\Scan-PC.ps1
```

Avec PowerShell 7 :

```powershell
pwsh -NoProfile -File .\Scan-PC.ps1
```

Les rapports datés **HTML** et **JSON** apparaissent dans `reports`, sous le dossier de travail courant. Ouvrir le fichier HTML pour lire le diagnostic. Il ne charge ni script ni ressource sur Internet.

Si Windows bloque un fichier téléchargé, vérifier son contenu et sa provenance avant de le débloquer dans ses propriétés. Ne pas désactiver globalement la politique d'exécution pour utiliser cet outil. Une politique d'entreprise peut nécessiter l'intervention de l'administrateur.

## Ce qui est vérifié

| Contrôle | Portée |
|---|---|
| Fichiers connus | Sept chemins du profil courant : six scripts du même échantillon et un lanceur suspect. SHA-256 calculé sans exécution. |
| Démarrage | Références aux noms ciblés dans les clés Run/RunOnce courantes et système accessibles. |
| Processus | Références ciblées parmi les processus Python et WinSecurityUpdate visibles. |
| Sorties de collecte | Présence des sept noms `d3*.txt` dans TEMP : métadonnées uniquement, **contenu jamais lu**. |
| Defender | État de la protection et dates de scans/signatures. **Aucun scan Defender n'est lancé.** |

Les noms courants tels que « adobe » ou la présence de Python ne déclenchent pas seuls une alerte.

**Non couvert :** autres familles, fichiers renommés ailleurs, toutes les variantes, mémoire, rootkits, firmware, tâches/services, extensions de navigateur, charges distantes, autres utilisateurs et historique complet des communications. Les clés de démarrage contrôlées ne représentent pas tous les mécanismes de persistance de Windows.

## Interpréter les résultats

| Verdict | Signification |
|---|---|
| `KnownMalwareFound` | Au moins un fichier a exactement l'empreinte du script malveillant analysé. |
| `SuspiciousIndicators` | Nom, chemin, référence ou sortie suspecte : examen nécessaire, faux positif possible. |
| `Incomplete` | Aucune correspondance signalée, mais au moins un contrôle a échoué. |
| `NoKnownIndicators` | Aucun des indicateurs ciblés n'a été retrouvé dans les contrôles réalisés. **Pas une certification de sécurité.** |

Des erreurs peuvent aussi accompagner une alerte : consulter toujours `checksWithErrors` et la couverture du rapport. L'absence de Defender peut être normale si un autre antivirus est utilisé. Un processus inaccessible peut ne pas être contrôlé complètement.

Le fichier `WinSecurityUpdate.exe` est classé **suspect**, même si son empreinte correspond. Il avait les métadonnées d'un lanceur Python renommé ; son rôle malveillant n'est pas confirmé. Les fichiers de collecte peuvent aussi être des copies de recherche. L'outil ne tranche pas à partir d'un simple nom.

Codes de sortie : `0` = aucun indicateur ciblé ni erreur signalée ; `1` = indicateur suspect ou malveillant ; `2` = erreur/incomplétude sans indicateur détecté ou erreur fatale. Le code `0` ne signifie pas « PC sain » et le mode hors ligne ignore volontairement les contrôles de session.

## Options

```powershell
# Dossier de rapport explicite
.\Scan-PC.ps1 -OutputDirectory .\mes-rapports

# Fichiers d'un autre profil / copie montée, sans toucher à son registre
.\Scan-PC.ps1 -ProfilePath 'E:\Copie\Users\Utilisateur' -OfflineProfile -OutputDirectory .\rapports-hors-ligne
```

Le mode hors ligne examine seulement les fichiers ciblés et sorties temporaires. Il ne charge aucune ruche de registre et n'utilise pas le registre/processus de la machine hôte pour attribuer des résultats à la copie.

## Confidentialité et sûreté

- Pas de requête réseau, d'envoi VirusTotal, de webhook, de téléchargement ou de télémétrie dans le code de l'outil.
- Pas d'exécution d'un fichier suspect, d'arrêt de processus, de suppression, de quarantaine ou de modification du registre.
- Seuls les rapports sont écrits ; la lecture des fichiers peut affecter les dates d'accès ou déclencher l'antivirus de Windows. Ce n'est pas une acquisition forensique avec bloqueur d'écriture.
- Les noms de profil sont masqués dans les rapports. Les lignes de commande, cookies, mots de passe et contenus de fichiers de collecte ne sont pas exportés.
- **Relire tout rapport avant partage** : des noms de valeurs du registre, chemins personnalisés, erreurs et métadonnées peuvent encore être personnels.
- Le `.gitignore` exclut les dossiers de rapports habituels. Une sortie personnalisée hors de ces dossiers doit être exclue manuellement avant un commit.

Ce dépôt public ne contient **aucun échantillon de malware**, secret de webhook, rapport réel ou donnée de victime. Les SHA-256 et noms de fichiers sont des indicateurs, pas du code malveillant.

## Que faire en cas d'alerte ?

Ne pas ouvrir le fichier suspect. Conserver le rapport localement et faire vérifier la correspondance. Une empreinte connue justifie une prise en charge rapide. Utiliser l'antivirus et, si nécessaire, une assistance compétente pour le nettoyage ; cet outil ne le réalise pas. Protéger également les comptes depuis un appareil sain si une collecte de données est confirmée.

## Tests sans malware

```powershell
powershell.exe -NoProfile -File .\tests\Run-Tests.ps1
```

Les tests utilisent uniquement un fichier texte bénin et des indicateurs modifiés **en mémoire**. Ils vérifient notamment la distinction suspect/malveillant, l'absence de modification des fichiers analysés, le masquage des chemins, l'échappement HTML et le rejet d'indicateurs sortant du périmètre. Le répertoire temporaire créé par les tests est supprimé après vérification de son emplacement.

## Organisation

```text
Scan-PC.ps1             Point d'entrée
src/Checks.psm1         Contrôles locaux et rapports
indicators.json        Indicateurs publics et classifications
tests/Run-Tests.ps1     Tests avec fixtures bénignes
SECURITY.md            Signalements et limites
CONTRIBUTING.md        Règles de contribution
LICENSE                Licence MIT
```

Version initiale : **1.0.0**, indicateurs datés du **12 novembre 2026**. Les correspondances exactes ne couvrent pas les variantes futures. Voir `CHANGELOG.md` pour la validation réalisée.

## Publier sur GitHub

Créer un dépôt et y déposer **uniquement le contenu du dossier `pc-security-check`**. Ne pas déposer son dossier parent, des rapports locaux ou une archive forensique. Vérifier que `.gitignore` est bien inclus. Le projet est fourni sous licence MIT ; aucun dépôt n'est créé ou publié automatiquement par cet outil.
