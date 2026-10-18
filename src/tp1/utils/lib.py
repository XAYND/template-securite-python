import argparse
import json

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Packet


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


def trouver_protocole(paquet: Packet) -> str:
    """
    Retourne le nom du protocole principal d'un paquet

    :param paquet: paquet scapy
    :return: nom du protocole
    """
    if paquet.haslayer(ARP):
        return "ARP"
    elif paquet.haslayer(DNS):
        return "DNS"
    elif paquet.haslayer(TCP):
        return "TCP"
    elif paquet.haslayer(UDP):
        return "UDP"
    elif paquet.haslayer(ICMP):
        return "ICMP"
    elif paquet.haslayer(IP):
        return "IP"
    else:
        return "Autre"


def sauvegarder_json(donnees: dict, nom_fichier: str) -> None:
    """
    Sauvegarde un dictionnaire dans un fichier JSON

    :param donnees: données à sauvegarder
    :param nom_fichier: nom du fichier JSON
    """
    with open(nom_fichier, "w", encoding="utf-8") as fichier:
        json.dump(donnees, fichier, indent=2)
