import json

import pytest
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether

from src.tp1.utils.lib import (
    hello_world,
    choose_interface,
    lire_arguments,
    sauvegarder_json,
    trouver_protocole,
)


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


def test_when_choose_interface_then_return_empty_string():
    # When
    result = choose_interface()

    # Then
    assert result == ""


def test_lire_arguments_avec_pcap_et_out():
    # When
    resultat = lire_arguments(["--pcap", "capture.pcap", "--out", "resultat.json"])

    # Then
    assert resultat.pcap == "capture.pcap"
    assert resultat.out == "resultat.json"


def test_lire_arguments_sans_out_donne_report_json():
    # When
    resultat = lire_arguments(["--pcap", "capture.pcap"])

    # Then
    assert resultat.out == "report.json"


def test_lire_arguments_sans_pcap_arrete_le_programme():
    # When / Then
    with pytest.raises(SystemExit):
        lire_arguments([])


def test_trouver_protocole_retourne_le_bon_nom():
    # Given
    paquet_arp = Ether() / ARP()
    paquet_dns = Ether() / IP() / UDP() / DNS()
    paquet_tcp = Ether() / IP() / TCP()
    paquet_udp = Ether() / IP() / UDP()
    paquet_icmp = Ether() / IP() / ICMP()
    paquet_ip = Ether() / IP()
    paquet_autre = Ether()

    # When / Then
    assert trouver_protocole(paquet_arp) == "ARP"
    assert trouver_protocole(paquet_dns) == "DNS"
    assert trouver_protocole(paquet_tcp) == "TCP"
    assert trouver_protocole(paquet_udp) == "UDP"
    assert trouver_protocole(paquet_icmp) == "ICMP"
    assert trouver_protocole(paquet_ip) == "IP"
    assert trouver_protocole(paquet_autre) == "Autre"


def test_sauvegarder_json_ecrit_les_donnees(tmp_path):
    # Given
    nom_fichier = str(tmp_path / "report.json")
    donnees = {"protocols": {"TCP": 3}, "attacks": [], "flag": ""}

    # When
    sauvegarder_json(donnees, nom_fichier)

    # Then
    with open(nom_fichier, encoding="utf-8") as fichier:
        assert json.load(fichier) == donnees
