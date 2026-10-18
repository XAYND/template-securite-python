import json

import pytest
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether

from src.tp1.utils.lib import hello_world, choose_interface, parse_args, save_json, get_protocol


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


def test_given_pcap_and_out_when_parse_args_then_values_are_read():
    # When
    result = parse_args(["--pcap", "capture.pcap", "--out", "result.json"])

    # Then
    assert result.pcap == "capture.pcap"
    assert result.out == "result.json"


def test_given_no_out_when_parse_args_then_default_is_report_json():
    # When
    result = parse_args(["--pcap", "capture.pcap"])

    # Then
    assert result.out == "report.json"


def test_given_no_pcap_when_parse_args_then_exit():
    # When / Then
    with pytest.raises(SystemExit):
        parse_args([])


def test_given_packets_when_get_protocol_then_return_protocol_name():
    # Given
    arp_packet = Ether() / ARP()
    dns_packet = Ether() / IP() / UDP() / DNS()
    tcp_packet = Ether() / IP() / TCP()
    udp_packet = Ether() / IP() / UDP()
    icmp_packet = Ether() / IP() / ICMP()
    ip_packet = Ether() / IP()
    other_packet = Ether()

    # When / Then
    assert get_protocol(arp_packet) == "ARP"
    assert get_protocol(dns_packet) == "DNS"
    assert get_protocol(tcp_packet) == "TCP"
    assert get_protocol(udp_packet) == "UDP"
    assert get_protocol(icmp_packet) == "ICMP"
    assert get_protocol(ip_packet) == "IP"
    assert get_protocol(other_packet) == "Other"


def test_given_data_when_save_json_then_file_contains_data(tmp_path):
    # Given
    filename = str(tmp_path / "report.json")
    data = {"protocols": {"TCP": 3}, "attacks": [], "flag": ""}

    # When
    save_json(data, filename)

    # Then
    with open(filename, encoding="utf-8") as file:
        assert json.load(file) == data
