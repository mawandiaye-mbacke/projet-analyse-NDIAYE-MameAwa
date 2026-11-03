# Projet 1 — Analyse des journaux d'un pare-feu

**Nom / Prénom : NDIAYE Mame Awa** — Master RESI

Analyse d'une semaine de connexions enregistrées par le pare-feu d'une entreprise (PC, serveurs, caméras et capteurs IoT) : nettoyage des données, indicateurs clés, figures et détection de comportements suspects.

## Lancer le projet

```bash
pip install -r requirements.txt
python analyse.py
```

Le script lit `data/logs_reseau.csv`, nettoie les données, écrit `resultats.json` et enregistre les figures dans `figures/`.

## Contenu du dépôt

| Fichier | Rôle |
|---|---|
| `analyse.py` | script complet : nettoyage, calcul des résultats, figures |
| `resultats.json` | les 5 résultats demandés (généré par `analyse.py`) |
| `rapport.md` | rapport d'analyse : observations, comportements suspects, recommandations |
| `figures/` | 6 graphiques PNG |
| `data/logs_reseau.csv` | données brutes du pare-feu |
| `requirements.txt` | bibliothèques Python nécessaires |

## Résultats

| Indicateur | Valeur |
|---|---|
| Lignes après nettoyage | 5 440 |
| Port le plus fréquent | 443 (HTTPS) |
| Taux de connexions DENY | 13,57 % |
| IP « scanner » (le plus de ports distincts) | 192.168.1.99 |
| IP « exfiltration » (le plus d'octets envoyés) | 192.168.1.11 |
