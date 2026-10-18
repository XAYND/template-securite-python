import json
import os

import pytest
from scapy.all import IP, TCP, Ether, wrpcap

from src.tp1.main import main


def test_main_ecrit_le_rapport_json(tmp_path):
    # Given
    fichier_pcap = str(tmp_path / "test.pcap")
    fichier_json = str(tmp_path / "report.json")
    wrpcap(fichier_pcap, [Ether() / IP() / TCP()])
    ancien_dossier = os.getcwd()
    os.chdir(tmp_path)

    # When
    try:
        main(["--pcap", fichier_pcap, "--out", fichier_json])
    finally:
        os.chdir(ancien_dossier)

    # Then
    with open(fichier_json, encoding="utf-8") as fichier:
        resultat = json.load(fichier)
    assert resultat["protocols"] == {"TCP": 1}
    assert resultat["attacks"] == []
    assert "flag" in resultat


def test_main_sans_fichier_pcap_arrete_le_programme(tmp_path):
    # Given
    fichier_pcap = str(tmp_path / "absent.pcap")

    # When / Then
    with pytest.raises(SystemExit):
        main(["--pcap", fichier_pcap])
