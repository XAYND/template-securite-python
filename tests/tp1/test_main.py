import json
import os

import pytest
from scapy.all import IP, TCP, Ether, wrpcap

from src.tp1.main import main


def test_given_pcap_when_main_then_json_report_is_written(tmp_path):
    # Given
    pcap_file = str(tmp_path / "test.pcap")
    out_file = str(tmp_path / "report.json")
    wrpcap(pcap_file, [Ether() / IP() / TCP()])
    old_dir = os.getcwd()
    os.chdir(tmp_path)

    # When
    try:
        main(["--pcap", pcap_file, "--out", out_file])
    finally:
        os.chdir(old_dir)

    # Then
    with open(out_file, encoding="utf-8") as file:
        result = json.load(file)
    assert result["protocols"] == {"TCP": 1}
    assert result["attacks"] == []
    assert "flag" in result


def test_given_missing_pcap_when_main_then_exit(tmp_path):
    # Given
    pcap_file = str(tmp_path / "absent.pcap")

    # When / Then
    with pytest.raises(SystemExit):
        main(["--pcap", pcap_file])
