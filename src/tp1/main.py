import os
import sys

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.lib import lire_arguments, sauvegarder_json
from tp1.utils.report import Report


def main(arguments: list[str] | None = None) -> None:
    """
    Lit le fichier PCAP, l'analyse et écrit les rapports

    :param arguments: liste des arguments, None pour utiliser la vraie ligne de commande
    """
    options = lire_arguments(arguments)
    logger.info("Démarrage du TP1")

    if not os.path.isfile(options.pcap):
        logger.error(f"Fichier introuvable : {options.pcap}")
        sys.exit(1)

    capture = Capture(options.pcap)
    capture.lire_pcap()
    capture.analyse("tcp")
    summary = capture.get_summary()

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)

    resultat = {"protocols": capture.protocoles, "attacks": capture.attaques, "flag": ""}
    sauvegarder_json(resultat, options.out)
    logger.info(f"Rapport JSON écrit dans {options.out}")


if __name__ == "__main__":
    main()
