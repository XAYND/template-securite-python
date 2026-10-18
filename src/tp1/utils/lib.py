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


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """
    Read the command line arguments

    :param args: list of arguments, None to use the real command line
    :return: parsed arguments
    """
    parser = argparse.ArgumentParser(description="Analyse d'un fichier PCAP")
    parser.add_argument("--pcap", required=True, help="fichier PCAP a analyser")
    parser.add_argument("--out", default="report.json", help="fichier JSON de sortie")
    return parser.parse_args(args)


def get_protocol(packet: Packet) -> str:
    """
    Return the name of the main protocol of a packet

    :param packet: scapy packet
    :return: protocol name
    """
    if packet.haslayer(ARP):
        return "ARP"
    elif packet.haslayer(DNS):
        return "DNS"
    elif packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(IP):
        return "IP"
    else:
        return "Other"


def save_json(data: dict, filename: str) -> None:
    """
    Save a dictionary in a JSON file

    :param data: data to save
    :param filename: name of the JSON file
    """
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)
