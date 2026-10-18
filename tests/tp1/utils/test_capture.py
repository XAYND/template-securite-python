from unittest.mock import patch

from scapy.all import ARP, IP, TCP, Ether, wrpcap

from src.tp1.utils.capture import Capture


def test_capture_init():
    # When
    capture = Capture()

    # Then
    assert capture.interface == ""
    assert capture.summary == ""
    assert capture.fichier_pcap == ""
    assert capture.paquets == []
    assert capture.protocoles == {}
    assert capture.attaques == []


def test_lire_pcap_charge_les_paquets(tmp_path):
    # Given
    fichier_pcap = str(tmp_path / "test.pcap")
    paquets = [Ether() / IP() / TCP(), Ether() / ARP()]
    wrpcap(fichier_pcap, paquets)
    capture = Capture(fichier_pcap)

    # When
    capture.lire_pcap()

    # Then
    assert len(capture.paquets) == 2


def test_compter_protocoles():
    # Given
    capture = Capture()
    capture.paquets = [Ether() / IP() / TCP(), Ether() / IP() / TCP(), Ether() / ARP()]

    # When
    capture.compter_protocoles()

    # Then
    assert capture.protocoles == {"TCP": 2, "ARP": 1}


def test_sort_network_protocols_trie_les_noms():
    # Given
    capture = Capture()
    capture.protocoles = {"TCP": 2, "ARP": 1, "DNS": 4}

    # When
    resultat = capture.sort_network_protocols()

    # Then
    assert resultat == "ARP, DNS, TCP"


def test_get_all_protocols_retourne_les_nombres():
    # Given
    capture = Capture()
    capture.protocoles = {"TCP": 2, "ARP": 1}

    # When
    resultat = capture.get_all_protocols()

    # Then
    assert resultat == "TCP: 2\nARP: 1\n"


def test_ajouter_attaque_une_seule_fois():
    # Given
    capture = Capture()

    # When
    capture.ajouter_attaque("arp_spoofing", "aa:aa:aa:aa:aa:aa")
    capture.ajouter_attaque("arp_spoofing", "aa:aa:aa:aa:aa:aa")

    # Then
    assert capture.attaques == [{"type": "arp_spoofing", "attacker": "aa:aa:aa:aa:aa:aa"}]


def test_table_arp_donne_les_mac_par_ip():
    # Given
    capture = Capture()
    capture.paquets = [
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa", pdst="10.0.0.5"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb", pdst="10.0.0.5"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa", pdst="10.0.0.6"),
        Ether() / ARP(op=1, psrc="10.0.0.5", pdst="10.0.0.1"),
    ]

    # When
    resultat = capture.table_arp()

    # Then
    assert resultat == {"10.0.0.1": ["aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"]}


def test_compter_reponses_arp():
    # Given
    capture = Capture()
    capture.paquets = [
        Ether() / ARP(op=1, psrc="10.0.0.5", hwsrc="cc:cc:cc:cc:cc:cc", pdst="10.0.0.1"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa", pdst="10.0.0.5"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb", pdst="10.0.0.5"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb", pdst="10.0.0.6"),
    ]

    # When
    resultat = capture.compter_reponses_arp()

    # Then
    assert resultat == {"aa:aa:aa:aa:aa:aa": 1, "bb:bb:bb:bb:bb:bb": 2}


def test_detecter_arp_spoofing_trouve_l_attaquant():
    # Given
    capture = Capture()
    capture.paquets = [
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa", pdst="10.0.0.5"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb", pdst="10.0.0.5"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb", pdst="10.0.0.6"),
    ]

    # When
    capture.detecter_arp_spoofing()

    # Then
    assert capture.attaques == [{"type": "arp_spoofing", "attacker": "bb:bb:bb:bb:bb:bb"}]


def test_detecter_arp_spoofing_sans_attaque():
    # Given
    capture = Capture()
    capture.paquets = [
        Ether() / ARP(op=1, psrc="10.0.0.5", pdst="10.0.0.1"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa", pdst="10.0.0.5"),
    ]

    # When
    capture.detecter_arp_spoofing()

    # Then
    assert capture.attaques == []


def test_given_capture_when_capture_traffic_then_interface_is_set():
    # Given
    capture = Capture()

    # When
    capture.capture_traffic()

    # Then
    # This is a minimal test since the method doesn't do much yet
    assert capture.interface == ""


def test_sort_network_protocols():
    # Given
    capture = Capture()

    # When
    result = capture.sort_network_protocols()

    # Then
    assert result == ""  # Method currently returns None


def test_get_all_protocols():
    # Given
    capture = Capture()

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == ""  # Method currently returns None


def test_analyse():
    # Given
    capture = Capture()

    # When
    with (
        patch.object(capture, "compter_protocoles") as mock_compter,
        patch.object(capture, "detecter_arp_spoofing") as mock_arp,
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse("tcp")

    # Then
    mock_compter.assert_called_once()
    mock_arp.assert_called_once()
    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.summary == "Test summary"


def test_get_summary():
    # Given
    capture = Capture()
    capture.summary = "Test summary"

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"


def test_gen_summary():
    # Given
    capture = Capture()

    # When
    result = capture._gen_summary()

    # Then
    assert result == ""  # Method currently returns empty string
