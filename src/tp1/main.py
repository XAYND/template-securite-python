import os
import sys

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.lib import parse_args, save_json
from tp1.utils.report import Report


def main(args: list[str] | None = None) -> None:
    """
    Read the pcap file, analyse it and write the reports

    :param args: list of arguments, None to use the real command line
    """
    options = parse_args(args)
    logger.info("Starting TP1")

    if not os.path.isfile(options.pcap):
        logger.error(f"Fichier introuvable : {options.pcap}")
        sys.exit(1)

    capture = Capture(options.pcap)
    capture.read_pcap()
    capture.analyse("tcp")
    summary = capture.get_summary()

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)

    result = {"protocols": {}, "attacks": [], "flag": ""}
    save_json(result, options.out)
    logger.info(f"Rapport JSON ecrit dans {options.out}")


if __name__ == "__main__":
    main()
