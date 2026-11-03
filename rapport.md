# Rapport — Analyse des journaux du pare-feu

**Auteure : NDIAYE Mame Awa** · Période analysée : du 5 au 11 octobre 2026 · Données : `data/logs_reseau.csv`

## 1. Nettoyage

Le fichier contenait **5 500 lignes**. J'ai supprimé **60 doublons exacts**, mis la colonne `protocol` en majuscules (`tcp`, `udp`, `icmp` → `TCP`, `UDP`, `ICMP`) et remplacé les **163 valeurs manquantes** restantes de `bytes_sent` par la médiane de la colonne (**1 710 octets**). Il reste **5 440 connexions**.

## 2. Résumé de ce que j'ai observé

Le trafic est dominé par le web : **HTTPS (port 443)** est le port le plus utilisé (1 874 connexions), devant HTTP (80) et DNS (53). Le pare-feu a bloqué **13,57 %** des connexions. L'activité est régulière (environ 200 connexions par heure), sauf un **pic de plus de 600 connexions vers minuit**, presque toutes bloquées. Les caméras IoT ont envoyé **262 millions d'octets**, soit **95 %** de tous les octets du réseau, alors qu'elles ne représentent qu'environ 16 % des connexions. Enfin, des services risqués restent utilisés : **Telnet (port 23)** et **RDP (3389)**, souvent depuis des objets IoT.

## 3. Les 2 comportements suspects

### Suspect n° 1 — Un scan de ports depuis `192.168.1.99`

- **Preuve** : ce PC a contacté **328 ports différents** sur un seul serveur (`10.0.0.5`), alors que les autres machines en contactent au maximum 8 (figure `05_ports_distincts_par_ip.png`).
- Les **400 connexions** ont eu lieu en **15 minutes**, le jeudi 8 octobre entre 00 h 00 et 00 h 15, en pleine nuit. **383 ont été bloquées** (DENY). C'est le pic rouge de minuit sur la figure `02_connexions_par_heure.png`.
- **Interprétation** : c'est la signature d'un **scan de ports**, c'est-à-dire une reconnaissance qui précède souvent une attaque. Soit le PC est compromis, soit quelqu'un l'utilise pour cartographier le serveur.

### Suspect n° 2 — Une exfiltration de données depuis la caméra `192.168.1.11`

- **Preuve** : cette caméra IoT a envoyé **259,9 millions d'octets**, soit **95 %** de tout le trafic sortant de la semaine (figure `06_octets_par_ip.png`). La machine suivante n'a envoyé que 0,63 million d'octets, environ **400 fois moins**.
- L'essentiel vient de **38 transferts d'environ 7 à 8,7 Mo**, tous le **samedi 10 octobre**, tous vers une **adresse externe (8.8.8.8) sur le port 8080**, et tous **autorisés** (ALLOW).
- **Interprétation** : une caméra n'a aucune raison d'envoyer de gros fichiers vers Internet sur un port non standard. C'est le profil d'une **exfiltration de données**, ou d'une caméra **compromise** qui renvoie son flux vidéo à un attaquant. Le pare-feu ne l'a pas arrêtée.

## 4. Recommandations de sécurité

1. **Isoler immédiatement** la caméra `192.168.1.11` et le PC `192.168.1.99`, puis les analyser (micrologiciel de la caméra, logiciels installés sur le PC, comptes utilisés).
2. **Segmenter les objets IoT** dans un VLAN dédié : les caméras et capteurs ne doivent parler qu'à leur serveur de gestion (MQTT, port 1883) et **jamais directement à Internet**. Bloquer en sortie le port 8080 vers l'extérieur pour ce VLAN.
3. **Fermer Telnet (port 23)** sur tout le réseau et le remplacer par SSH avec authentification par clé. Restreindre **RDP (3389)** et **SSH (22)** aux seuls postes d'administration.
4. **Détecter automatiquement les scans** : déclencher une alerte quand une même adresse contacte plus de **20 ports distincts en moins de 5 minutes** (avec un IDS ou une règle du SIEM), et bloquer temporairement l'adresse source.
5. **Surveiller les volumes sortants** : alerter quand un appareil envoie plus de **100 Mo par jour** vers l'extérieur, en particulier les objets IoT.

## Figures

| Figure | Contenu |
|---|---|
| `figures/01_top_ports.png` | top 10 des ports de destination |
| `figures/02_connexions_par_heure.png` | connexions par heure, ALLOW / DENY |
| `figures/03_octets_par_appareil.png` | octets envoyés par type d'appareil |
| `figures/04_allow_deny.png` | répartition ALLOW / DENY |
| `figures/05_ports_distincts_par_ip.png` | IP ayant contacté le plus de ports distincts (scan) |
| `figures/06_octets_par_ip.png` | IP ayant envoyé le plus d'octets (exfiltration) |
