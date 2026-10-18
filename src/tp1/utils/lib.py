import argparse
import json


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


def save_json(data: dict, filename: str) -> None:
    """
    Save a dictionary in a JSON file

    :param data: data to save
    :param filename: name of the JSON file
    """
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)
