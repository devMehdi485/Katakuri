# Historique

## 1.0.0 — 2026-11-12

- Vérification ciblée par SHA-256 et chemins, références de démarrage/processus, noms de sorties temporaires et état Defender.
- Distinction entre malware connu et indice seulement suspect.
- Rapports JSON/HTML locaux, chemins de profils masqués et contenu HTML échappé.
- Mode profil hors ligne sans chargement de ruche et sans mélange avec les processus de l'hôte.
- Aucun nettoyage automatique et aucun échantillon malveillant inclus.

Validation de cette version : 16 tests bénins réussis sous Windows PowerShell 5.1 et PowerShell 7 ; exécution du point d'entrée sur Windows 10, génération HTML/JSON et code de sortie vérifiés. Windows 11 est visé par les API utilisées, mais n'a pas fait l'objet d'un test réel dans cette validation. Les rapports du poste de validation ne sont pas inclus.
