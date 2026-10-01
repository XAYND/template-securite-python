from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import sniff


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packet = []

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture du traffic de l'interface {interface}")
       
        self.packets = sniff (
            iface=interface, count=10
        )
        logger.info(f"{len(self.packets)} paquets capturés")

    def sort_network_protocols(self) -> str:
        protocols = [] 

        for packet in self.packets: 
            protocol = packet.lastlayer().name
            protocols.append(protocol)
    
        protocols.sort()

        return ", ".join(protocols)
        
        """
        Sort and return all captured network protocols
        """

    def get_all_protocols(self) -> str:
        protocols = {}

        for packet in self.packets:
            protocol = packet.lastlayer().name

            if protocol in protocols:
                protocols[protocol] += 1
            else:
                protocols[protocol] = 1

        result = ""

        for protocol in protocols:
            result += f"{protocol}: {protocols[protocol]}\n"

        return result


        """
        Return all protocols captured with total packets number
        """

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
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.info(f"All protocols:{all_protocols}")
        #logger.debug(f"Sorted protocols: {sort}")
        logger.info(f"Sorted protocols: {sort}")
        #logger.debug(f"All protocols: {all_protocols}")

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
