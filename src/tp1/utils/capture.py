from scapy.all import ARP, IP, TCP, rdpcap

from tp1.utils.config import logger
from tp1.utils.lib import trouver_protocoles

SEUIL_SCAN = 10


class Capture:
    def __init__(self, fichier_pcap: str = "", interface: str = "") -> None:
        self.fichier_pcap = fichier_pcap
        self.interface = interface
        self.paquets = []
        self.protocoles = {}
        self.attaques = []
        self.summary = ""

    def lire_pcap(self) -> None:
        """
        Lit tous les paquets du fichier PCAP
        """
        logger.info(f"Lecture du fichier {self.fichier_pcap}")
        self.paquets = rdpcap(self.fichier_pcap)
        logger.info(f"{len(self.paquets)} paquets lus")

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture du trafic sur l'interface {interface}")

    def compter_protocoles(self) -> None:
        """
        Compte le nombre de paquets pour chaque protocole
        """
        self.protocoles = {}
        for paquet in self.paquets:
            for protocole in trouver_protocoles(paquet):
                if protocole in self.protocoles:
                    self.protocoles[protocole] += 1
                else:
                    self.protocoles[protocole] = 1

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        noms = sorted(self.protocoles)
        return ", ".join(noms)

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        texte = ""
        for protocole in self.protocoles:
            texte += f"{protocole}: {self.protocoles[protocole]}\n"
        return texte

    def ajouter_attaque(self, type_attaque: str, attaquant: str) -> None:
        """
        Ajoute une attaque dans la liste si elle n'y est pas déjà

        :param type_attaque: type de l'attaque
        :param attaquant: adresse MAC ou IP de l'attaquant
        """
        attaque = {"type": type_attaque, "attacker": attaquant}
        if attaque not in self.attaques:
            self.attaques.append(attaque)
            logger.warning(f"Attaque détectée : {type_attaque} par {attaquant}")

    def table_arp(self) -> dict[str, list[str]]:
        """
        Retourne les adresses MAC annoncées pour chaque IP dans les réponses ARP

        :return: dictionnaire ip -> liste des adresses MAC
        """
        table = {}
        for paquet in self.paquets:
            if paquet.haslayer(ARP) and paquet[ARP].op == 2:
                ip = paquet[ARP].psrc
                mac = paquet[ARP].hwsrc
                if ip not in table:
                    table[ip] = []
                if mac not in table[ip]:
                    table[ip].append(mac)
        return table

    def compter_reponses_arp(self) -> dict[str, int]:
        """
        Compte le nombre de réponses ARP envoyées par chaque adresse MAC

        :return: dictionnaire mac -> nombre de réponses
        """
        reponses = {}
        for paquet in self.paquets:
            if paquet.haslayer(ARP) and paquet[ARP].op == 2:
                mac = paquet[ARP].hwsrc
                if mac in reponses:
                    reponses[mac] += 1
                else:
                    reponses[mac] = 1
        return reponses

    def detecter_arp_spoofing(self) -> None:
        """
        Détecte une IP annoncée par plusieurs adresses MAC.
        L'attaquant est la MAC qui envoie le plus de réponses ARP.
        """
        table = self.table_arp()
        reponses = self.compter_reponses_arp()
        for ip in table:
            macs = table[ip]
            if len(macs) > 1:
                logger.info(f"L'IP {ip} est annoncée par plusieurs MAC : {macs}")
                attaquant = ""
                maximum = 0
                for mac in macs:
                    if reponses[mac] > maximum:
                        maximum = reponses[mac]
                        attaquant = mac
                self.ajouter_attaque("arp_spoofing", attaquant)

    def ports_syn_par_ip(self) -> dict[str, list[int]]:
        """
        Retourne les ports différents visés par des paquets SYN pour chaque IP source

        :return: dictionnaire ip -> liste des ports
        """
        ports = {}
        for paquet in self.paquets:
            if paquet.haslayer(IP) and paquet.haslayer(TCP) and paquet[TCP].flags == "S":
                ip = paquet[IP].src
                port = paquet[TCP].dport
                if ip not in ports:
                    ports[ip] = []
                if port not in ports[ip]:
                    ports[ip].append(port)
        return ports

    def detecter_scan_ports(self) -> None:
        """
        Détecte une IP qui envoie des paquets SYN vers beaucoup de ports différents
        """
        ports = self.ports_syn_par_ip()
        for ip in ports:
            if len(ports[ip]) >= SEUIL_SCAN:
                logger.info(f"L'IP {ip} a envoyé des SYN vers {len(ports[ip])} ports")
                self.ajouter_attaque("port_scan", ip)

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
        self.compter_protocoles()
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.info(f"Protocoles :\n{all_protocols}")
        logger.info(f"Protocoles triés : {sort}")

        self.detecter_arp_spoofing()
        self.detecter_scan_ports()

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
