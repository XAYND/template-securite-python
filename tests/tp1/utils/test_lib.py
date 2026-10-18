import json

import pytest
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, Raw

from src.tp1.utils.lib import (
    hello_world,
    choose_interface,
    lire_arguments,
    sauvegarder_json,
    trouver_protocoles,
    est_http,
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


def test_est_http_avec_une_requete_http():
    # Given
    paquet = Ether() / IP() / TCP(dport=80) / Raw(load=b"GET / HTTP/1.1\r\n\r\n")

    # When
    resultat = est_http(paquet)

    # Then
    assert resultat is True


def test_est_http_sans_contenu_http():
    # Given
    paquet_sans_contenu = Ether() / IP() / TCP(dport=80)
    paquet_autre_contenu = Ether() / IP() / TCP() / Raw(load=b"bonjour")

    # When / Then
    assert est_http(paquet_sans_contenu) is False
    assert est_http(paquet_autre_contenu) is False


def test_trouver_protocoles_retourne_toutes_les_couches():
    # Given
    paquet_arp = Ether() / ARP()
    paquet_dns = Ether() / IP() / UDP() / DNS()
    paquet_icmp = Ether() / IP() / ICMP()
    paquet_http = Ether() / IP() / TCP() / Raw(load=b"GET / HTTP/1.1\r\n\r\n")

    # When / Then
    assert trouver_protocoles(paquet_arp) == ["ETHERNET", "ARP"]
    assert trouver_protocoles(paquet_dns) == ["ETHERNET", "IP", "UDP", "DNS"]
    assert trouver_protocoles(paquet_icmp) == ["ETHERNET", "IP", "ICMP"]
    assert trouver_protocoles(paquet_http) == ["ETHERNET", "IP", "TCP", "HTTP"]


def test_sauvegarder_json_ecrit_les_donnees(tmp_path):
    # Given
    nom_fichier = str(tmp_path / "report.json")
    donnees = {"protocols": {"TCP": 3}, "attacks": [], "flag": ""}

    # When
    sauvegarder_json(donnees, nom_fichier)

    # Then
    with open(nom_fichier, encoding="utf-8") as fichier:
        assert json.load(fichier) == donnees
