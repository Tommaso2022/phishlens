"""Processo worker: segnaposto finché non arriva la coda dei job (Fase 3)."""

import logging
import signal
import threading

logger = logging.getLogger("phishlens.worker")
_stop = threading.Event()


def _handle_stop(signum: int, _frame: object) -> None:
    logger.info("Ricevuto segnale %s, arresto in corso", signum)
    _stop.set()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    logger.info("Worker avviato, in attesa di job")
    while not _stop.wait(timeout=30):
        logger.debug("Worker attivo")
    logger.info("Worker arrestato")


if __name__ == "__main__":
    main()
