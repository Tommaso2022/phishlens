"""Indirizzo del client in forma ridotta, per audit e limiti.

Si conserva solo il prefisso di rete (/24 per IPv4, /48 per IPv6): basta per
limiti e indagini, ma non identifica la singola persona (minimizzazione, Q1).
"""

from __future__ import annotations

import ipaddress

from fastapi import Request


def ip_prefix(request: Request) -> str:
    host = request.client.host if request.client else ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "sconosciuto"
    bits = 24 if ip.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{bits}", strict=False))
