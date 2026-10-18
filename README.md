# TP1 - Analyse d'une capture réseau

## Présentation

Ce projet analyse un fichier PCAP avec Python et Scapy.

Il permet de :
- compter les protocoles réseau ;
- détecter un ARP spoofing ;
- détecter un scan de ports SYN ;
- détecter une injection SQL ;
- enregistrer le résultat dans un fichier JSON.

## Installation

```bash
poetry install
```

## Utilisation

```bash
poetry run tp1 --pcap FICHIER --out report.json
```

`--pcap` correspond au fichier PCAP à analyser.

`--out` correspond au fichier JSON généré.

## Détections

### ARP spoofing

Le programme cherche si une même IP est annoncée par plusieurs adresses MAC.

### Scan de ports

Le programme regarde les paquets SYN envoyés vers plusieurs ports différents.

À partir de 10 ports différents, l'IP est considérée comme un scanner.

### Injection SQL

Le contenu des requêtes HTTP est décodé puis comparé à des motifs comme :

```text
' or 1=1
union select
```

## Résultat

Le résultat est enregistré dans un fichier JSON :

```json
{
  "protocols": {
    "TCP": 95,
    "ARP": 20,
    "DNS": 12
  },
  "attacks": [
    {
      "type": "arp_spoofing",
      "attacker": "aa:bb:cc:dd:ee:ff"
    },
    {
      "type": "port_scan",
      "attacker": "10.0.0.5"
    },
    {
      "type": "sql_injection",
      "attacker": "10.0.0.9"
    }
  ],
  "flag": ""
}
```

## Organisation

- `src/tp1/main.py` : lancement du programme
- `src/tp1/utils/capture.py` : analyse du PCAP et détection des attaques
- `src/tp1/utils/lib.py` : fonctions utilitaires
- `tests/tp1/` : tests

## Tests

```bash
poetry run pytest
```

## Pre-commit

```bash
pre-commit run --all-files
```
