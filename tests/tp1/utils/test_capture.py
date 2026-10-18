from unittest.mock import patch

from scapy.all import ARP, IP, TCP, Ether, Packet, wrpcap

from src.tp1.utils.capture import Capture


def test_capture_init():
    # When
    capture = Capture()

    # Then
    assert capture.interface == ""
    assert capture.summary == ""
    assert capture.pcap_file == ""
    assert capture.packets == []
    assert capture.attacks == []


def test_given_pcap_file_when_read_pcap_then_packets_are_loaded(tmp_path):
    # Given
    pcap_file = str(tmp_path / "test.pcap")
    packets = [Ether() / IP() / TCP(), Ether() / ARP()]
    wrpcap(pcap_file, packets)
    capture = Capture(pcap_file)

    # When
    capture.read_pcap()

    # Then
    assert len(capture.packets) == 2


def test_given_packets_when_count_protocols_then_protocols_are_counted():
    # Given
    capture = Capture()
    capture.packets = [Ether() / IP() / TCP(), Ether() / IP() / TCP(), Ether() / ARP()]

    # When
    capture.count_protocols()

    # Then
    assert capture.protocols == {"TCP": 2, "ARP": 1}


def test_given_protocols_when_sort_network_protocols_then_names_are_sorted():
    # Given
    capture = Capture()
    capture.protocols = {"TCP": 2, "ARP": 1, "DNS": 4}

    # When
    result = capture.sort_network_protocols()

    # Then
    assert result == "ARP, DNS, TCP"


def test_given_protocols_when_get_all_protocols_then_return_counts():
    # Given
    capture = Capture()
    capture.protocols = {"TCP": 2, "ARP": 1}

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == "TCP: 2\nARP: 1\n"


def make_arp_reply(ip: str, mac: str, target_ip: str) -> Packet:
    return Ether(src=mac) / ARP(op=2, psrc=ip, hwsrc=mac, pdst=target_ip)


def make_arp_request(ip: str, target_ip: str) -> Packet:
    return Ether() / ARP(op=1, psrc=ip, pdst=target_ip)


def test_given_new_attack_when_add_attack_then_attack_is_added_once():
    # Given
    capture = Capture()

    # When
    capture.add_attack("arp_spoofing", "aa:aa:aa:aa:aa:aa")
    capture.add_attack("arp_spoofing", "aa:aa:aa:aa:aa:aa")

    # Then
    assert capture.attacks == [{"type": "arp_spoofing", "attacker": "aa:aa:aa:aa:aa:aa"}]


def test_given_arp_replies_when_get_arp_table_then_macs_by_ip():
    # Given
    capture = Capture()
    capture.packets = [
        make_arp_reply("10.0.0.1", "aa:aa:aa:aa:aa:aa", "10.0.0.5"),
        make_arp_reply("10.0.0.1", "bb:bb:bb:bb:bb:bb", "10.0.0.5"),
        make_arp_reply("10.0.0.1", "aa:aa:aa:aa:aa:aa", "10.0.0.6"),
        make_arp_request("10.0.0.5", "10.0.0.1"),
    ]

    # When
    result = capture.get_arp_table()

    # Then
    assert result == {"10.0.0.1": ["aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"]}


def test_given_request_and_replies_when_count_unsolicited_arp_then_only_unsolicited_counted():
    # Given
    capture = Capture()
    capture.packets = [
        make_arp_request("10.0.0.5", "10.0.0.1"),
        make_arp_reply("10.0.0.1", "aa:aa:aa:aa:aa:aa", "10.0.0.5"),
        make_arp_reply("10.0.0.1", "bb:bb:bb:bb:bb:bb", "10.0.0.5"),
        make_arp_reply("10.0.0.1", "bb:bb:bb:bb:bb:bb", "10.0.0.6"),
    ]

    # When
    result = capture.count_unsolicited_arp()

    # Then
    assert result == {"bb:bb:bb:bb:bb:bb": 2}


def test_given_two_macs_for_one_ip_when_detect_arp_spoofing_then_attacker_found():
    # Given
    capture = Capture()
    capture.packets = [
        make_arp_request("10.0.0.5", "10.0.0.1"),
        make_arp_reply("10.0.0.1", "aa:aa:aa:aa:aa:aa", "10.0.0.5"),
        make_arp_reply("10.0.0.1", "bb:bb:bb:bb:bb:bb", "10.0.0.5"),
        make_arp_reply("10.0.0.1", "bb:bb:bb:bb:bb:bb", "10.0.0.6"),
    ]

    # When
    capture.detect_arp_spoofing()

    # Then
    assert capture.attacks == [{"type": "arp_spoofing", "attacker": "bb:bb:bb:bb:bb:bb"}]


def test_given_normal_arp_when_detect_arp_spoofing_then_no_attack():
    # Given
    capture = Capture()
    capture.packets = [
        make_arp_request("10.0.0.5", "10.0.0.1"),
        make_arp_reply("10.0.0.1", "aa:aa:aa:aa:aa:aa", "10.0.0.5"),
    ]

    # When
    capture.detect_arp_spoofing()

    # Then
    assert capture.attacks == []


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
        patch.object(capture, "count_protocols") as mock_count,
        patch.object(capture, "detect_arp_spoofing") as mock_arp,
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse("tcp")

    # Then
    mock_count.assert_called_once()
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
