import argparse
import json
from urllib.parse import unquote_plus

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Dot3, Ether, Packet, Raw

MOTIFS_SQL = [
    "' or 1=1",
    "union select",
]


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    interface = ""
    return interface


def lire_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    """
    Lit les arguments de la ligne de commande

    :param arguments: liste des arguments, None pour utiliser la vraie ligne de commande
    :return: les arguments lus
    """
    parser = argparse.ArgumentParser(description="Analyse d'un fichier PCAP")
    parser.add_argument("--pcap", required=True, help="fichier PCAP à analyser")
    parser.add_argument("--out", default="report.json", help="fichier JSON de sortie")
    return parser.parse_args(arguments)


def est_http(paquet: Packet) -> bool:
    """
    Indique si un paquet TCP contient du HTTP

    :param paquet: paquet scapy
    :return: True si le paquet contient du HTTP
    """
    if paquet.haslayer(TCP) and paquet.haslayer(Raw):
        contenu = bytes(paquet[Raw].load)
        if b"HTTP/" in contenu:
            return True
    return False


def trouver_protocoles(paquet: Packet) -> list[str]:
    """
    Retourne la liste des protocoles présents dans un paquet

    :param paquet: paquet scapy
    :return: liste des noms de protocoles
    """
    protocoles = []
    if paquet.haslayer(Ether) or paquet.haslayer(Dot3):
        protocoles.append("ETHERNET")
    if paquet.haslayer(ARP):
        protocoles.append("ARP")
    if paquet.haslayer(IP):
        protocoles.append("IP")
    if paquet.haslayer(ICMP):
        protocoles.append("ICMP")
    if paquet.haslayer(TCP):
        protocoles.append("TCP")
    if paquet.haslayer(UDP):
        protocoles.append("UDP")
    if paquet.haslayer(DNS):
        protocoles.append("DNS")
    if est_http(paquet):
        protocoles.append("HTTP")
    return protocoles


def sauvegarder_json(donnees: dict, nom_fichier: str) -> None:
    """
    Sauvegarde un dictionnaire dans un fichier JSON

    :param donnees: données à sauvegarder
    :param nom_fichier: nom du fichier JSON
    """
    with open(nom_fichier, "w", encoding="utf-8") as fichier:
        json.dump(donnees, fichier, indent=2)


def lire_contenu(paquet: Packet) -> str:
    """
    Lit le contenu d'un paquet et le transforme en texte

    :param paquet: paquet scapy
    :return: contenu du paquet sous forme de texte
    """
    if not paquet.haslayer(Raw):
        return ""

    contenu = paquet[Raw].load.decode(errors="ignore")
    contenu = unquote_plus(contenu)
    contenu = contenu.lower()

    return contenu


def contient_injection_sql(texte: str) -> bool:
    """
    Vérifie si un texte contient un motif d'injection SQL

    :param texte: texte à analyser
    :return: True si une injection SQL est détectée
    """
    for motif in MOTIFS_SQL:
        if motif in texte:
            return True

    return False
