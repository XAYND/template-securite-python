from tp1.utils.config import logger
from scapy.all import get_if_list


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    interface = get_if_list()
    for i in range(len(interface)):
        logger.info(f"{i} - {interface[i]}")

    choice = int(input("Choose interface: "))

    interface = interface[choice]

    return interface
