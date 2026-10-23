"""Parser unico degli URL di PhishLens.

Tutti i componenti (backend, worker, fetcher, addestramento del modello)
usano questo modulo: un solo parser evita che due parti dell'applicazione
interpretino lo stesso URL in modi diversi (ASVS v5.0.0-1.5.3, threat model E-05).
Le regole sono quelle di docs/validation.md, sezione 1.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

import idna

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({None, 80, 443})


class InvalidURL(ValueError):
    """L'URL non rispetta le regole di validazione."""


@dataclass(frozen=True)
class ParsedURL:
    scheme: str
    host: str  # minuscolo, in punycode, senza punto finale
    port: int | None
    path: str
    query: str

    @property
    def is_ip(self) -> bool:
        return is_ip_address(self.host)

    @property
    def site_host(self) -> str:
        """Host senza il prefisso "www.", usato per le feature del dominio."""
        return strip_www(self.host)


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def strip_www(host: str) -> str:
    if host.startswith("www.") and host.count(".") >= 2:
        return host[4:]
    return host


def normalize_host(raw_host: str) -> str:
    host = raw_host.strip().rstrip(".").lower()
    if not host:
        raise InvalidURL("host mancante")
    if is_ip_address(host):
        return host.strip("[]")
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError as e:
        raise InvalidURL(f"nome di dominio non valido: {e}") from e


def parse_url(raw: str) -> ParsedURL:
    """Valida e normalizza un URL. Solleva InvalidURL se non è accettabile."""
    if not isinstance(raw, str):
        raise InvalidURL("l'URL deve essere una stringa")
    candidate = raw.strip()
    if not candidate or len(candidate) > MAX_URL_LENGTH:
        raise InvalidURL(f"lunghezza non valida (massimo {MAX_URL_LENGTH} caratteri)")
    if any(ord(c) < 32 or ord(c) == 127 for c in candidate):
        raise InvalidURL("caratteri di controllo non ammessi")
    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError as e:
        raise InvalidURL(f"URL non interpretabile: {e}") from e

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidURL("sono ammessi solo gli schemi http e https")
    if parts.username is not None or parts.password is not None:
        raise InvalidURL("credenziali nell'URL non ammesse")
    if port not in ALLOWED_PORTS:
        raise InvalidURL("sono ammesse solo le porte 80 e 443")
    if parts.hostname is None:
        raise InvalidURL("host mancante")

    return ParsedURL(
        scheme=scheme,
        host=normalize_host(parts.hostname),
        port=port,
        path=parts.path,
        query=parts.query,
    )
