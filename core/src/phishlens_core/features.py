"""Estrazione delle feature dal nome di dominio (modello v1).

Lo stesso codice è usato per addestrare il modello e, nel worker, per
analizzare gli URL degli utenti: così il modello vede in produzione
esattamente le feature su cui è stato addestrato.

Il modello v1 usa solo l'host (senza "www.", schema, percorso e parametri):
nel dataset PhiUSIIL questi elementi separano le classi per come il dataset è
stato costruito, non per una differenza reale tra siti legittimi e phishing.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from functools import lru_cache

import idna
import tldextract

from phishlens_core.url import is_ip_address, strip_www

# Marchi spesso imitati, anche italiani. Un marchio nel sottodominio
# (paypal.esempio.xyz) o dentro un dominio diverso (paypal-sicurezza.com)
# è un segnale classico di phishing.
BRANDS = (
    "paypal",
    "apple",
    "icloud",
    "microsoft",
    "office365",
    "outlook",
    "google",
    "gmail",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "whatsapp",
    "linkedin",
    "dhl",
    "poste",
    "posteitaliane",
    "bancoposta",
    "intesa",
    "unicredit",
    "nexi",
    "inps",
    "agenziaentrate",
    "spid",
    "binance",
    "coinbase",
    "metamask",
)

KEYWORDS = (
    # inglese
    "login",
    "signin",
    "secure",
    "verify",
    "verification",
    "account",
    "update",
    "support",
    "auth",
    "wallet",
    "bank",
    "confirm",
    "billing",
    "recovery",
    "unlock",
    # italiano
    "accesso",
    "verifica",
    "sicurezza",
    "conferma",
    "aggiorna",
    "assistenza",
    "sblocca",
    "rimborso",
    "pagamento",
    "conto",
)

# Servizi legittimi su cui chiunque può pubblicare pagine. Per questi host il
# nome di dominio non dice nulla sul contenuto: il modello v1 non li valuta.
# Oltre a questo elenco valgono i suffissi "privati" della Public Suffix List
# (web.app, firebaseapp.com, github.io, ...), riconosciuti automaticamente.
SHARED_HOSTING = frozenset(
    {
        "ipfs.io",
        "cloudflare-ipfs.com",
        "dweb.link",
        "w3s.link",
        "nftstorage.link",
        "fleek.co",
        "4everland.io",
    }
)

NUMERIC_FEATURES = (
    "host_length",
    "n_labels",
    "n_subdomain_labels",
    "domain_label_length",
    "longest_label",
    "n_hyphens",
    "n_digits",
    "digit_ratio",
    "entropy",
    "max_consonant_run",
    "is_ip",
    "is_punycode",
    "brand_in_subdomain",
    "brand_in_domain_not_exact",
    "n_keywords",
)
CATEGORICAL_FEATURES = ("suffix",)
FEATURE_NAMES = NUMERIC_FEATURES + CATEGORICAL_FEATURES

_CONSONANT_RUN = re.compile(r"[bcdfghjklmnpqrstvwxyz]+")


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    # Elenco dei suffissi incluso nel pacchetto: nessun accesso alla rete e
    # nessuna scrittura su disco (i container hanno il filesystem in sola lettura).
    return tldextract.TLDExtract(
        suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
    )


def _parts(host: str) -> tuple[str, str, str, bool]:
    """(sottodominio, nome del dominio, suffisso, suffisso privato) in forma ASCII."""
    if is_ip_address(host):
        return "", host, "", False
    r = _extractor()(host)
    return r.subdomain, r.domain, r.suffix, bool(r.is_private)


def split_host(host: str) -> tuple[str, str, str]:
    """Restituisce (sottodominio, nome del dominio, suffisso pubblico)."""
    sub, domain, suffix, _ = _parts(host)
    return sub, domain, suffix


def registered_domain(host: str) -> str:
    """Dominio registrato (esempio.co.uk), usato per suddividere i dati."""
    _, domain, suffix = split_host(host)
    return f"{domain}.{suffix}" if suffix else domain


def is_shared_platform(host: str) -> bool:
    """Host su una piattaforma condivisa: il nome di dominio non è indicativo."""
    host = strip_www(host)
    _, _, _, private = _parts(host)
    return private or registered_domain(host) in SHARED_HOSTING


def to_unicode(label: str) -> str:
    """Forma leggibile di un'etichetta: "xn--bcher-kva" diventa "bücher".

    Le feature sui caratteri si calcolano su questa forma: le cifre e i
    trattini della codifica punycode non fanno parte del nome reale.
    """
    if not label.startswith("xn--"):
        return label
    try:
        return idna.decode(label)
    except idna.IDNAError:
        return label


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def extract_host_features(host: str) -> dict[str, float | int | str]:
    """Feature numeriche e categoriche di un host già normalizzato da parse_url."""
    host = strip_www(host)
    ip = is_ip_address(host)
    subdomain, domain, suffix, _ = _parts(host)
    ascii_labels = host.split(".")
    labels = ascii_labels if ip else [to_unicode(label) for label in ascii_labels]
    name = ".".join(labels)
    domain_u = domain if ip else to_unicode(domain)
    sub_labels = [s for s in subdomain.split(".") if s]
    digits = sum(ch.isdigit() for ch in name)
    runs = _CONSONANT_RUN.findall(domain_u) if not ip else []

    return {
        "host_length": len(name),
        "n_labels": len(labels),
        "n_subdomain_labels": len(sub_labels),
        "domain_label_length": len(domain_u),
        "longest_label": max(len(label) for label in labels),
        "n_hyphens": name.count("-"),
        "n_digits": digits,
        "digit_ratio": digits / len(name),
        "entropy": shannon_entropy(name),
        "max_consonant_run": max((len(r) for r in runs), default=0),
        "is_ip": int(ip),
        "is_punycode": int(any(label.startswith("xn--") for label in ascii_labels)),
        "brand_in_subdomain": int(any(b in subdomain for b in BRANDS)),
        "brand_in_domain_not_exact": int(any(b in domain and domain != b for b in BRANDS)),
        "n_keywords": sum(k in host for k in KEYWORDS),
        "suffix": suffix or ("(ip)" if ip else "(nessuno)"),
    }
