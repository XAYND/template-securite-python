from scapy.all import rdpcap

from tp1.utils.config import logger
from tp1.utils.lib import get_protocol


class Capture:
    def __init__(self, pcap_file: str = "", interface: str = "") -> None:
        self.pcap_file = pcap_file
        self.interface = interface
        self.packets = []
        self.protocols = {}
        self.summary = ""

    def read_pcap(self) -> None:
        """
        Read all packets from the pcap file
        """
        logger.info(f"Lecture du fichier {self.pcap_file}")
        self.packets = rdpcap(self.pcap_file)
        logger.info(f"{len(self.packets)} paquets lus")

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")

    def count_protocols(self) -> None:
        """
        Count the number of packets for each protocol
        """
        self.protocols = {}
        for packet in self.packets:
            protocol = get_protocol(packet)
            if protocol in self.protocols:
                self.protocols[protocol] += 1
            else:
                self.protocols[protocol] = 1

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        names = sorted(self.protocols)
        return ", ".join(names)

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        result = ""
        for protocol in self.protocols:
            result += f"{protocol}: {self.protocols[protocol]}\n"
        return result

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        self.count_protocols()
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.info(f"All protocols:\n{all_protocols}")
        logger.info(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary
