"""Traduzione dei contributi SHAP in frasi comprensibili.

Usato dall'analisi del modello e dal worker per spiegare all'utente perché un
dominio ha ricevuto un certo punteggio.

Le frasi descrivono il valore come un fatto ("Il nome ha 2 parti") e non lo
giudicano: se quel fatto ha spinto verso "sospetto" o verso "legittimo" lo dice
il segno del contributo, che l'interfaccia mostra separando le due colonne.
Così una frase non può contraddire il dato che riporta.

I testi non contengono mai il nome del dominio: l'interfaccia lo mostra a parte,
in forma non cliccabile.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Reason:
    feature: str
    value: float | int | str
    contribution: float  # > 0 spinge verso il phishing, < 0 verso il legittimo
    text: str


def _count(n, zero: str, one: str, many: str) -> str:
    n = int(n)
    if n == 0:
        return zero
    return one if n == 1 else many.format(n=n)


def _flag(yes: str, no: str) -> Callable[[object], str]:
    return lambda v: yes if int(v) else no


FACTS: dict[str, Callable[[object], str]] = {
    "host_length": lambda v: f"Il nome è lungo {int(v)} caratteri",
    "n_labels": lambda v: f"Il nome ha {int(v)} parti separate da punti",
    "n_subdomain_labels": lambda v: _count(
        v, "Nessun sottodominio", "Un sottodominio", "{n} livelli di sottodominio"
    ),
    "domain_label_length": lambda v: f"Il nome principale è lungo {int(v)} caratteri",
    "longest_label": lambda v: f"La parte più lunga del nome ha {int(v)} caratteri",
    "n_hyphens": lambda v: _count(v, "Nessun trattino", "Un trattino", "{n} trattini"),
    "n_digits": lambda v: _count(v, "Nessuna cifra", "Una cifra", "{n} cifre"),
    "digit_ratio": lambda v: f"Le cifre sono il {float(v):.0%} dei caratteri",
    "max_consonant_run": lambda v: _count(
        v,
        "Nessuna consonante",
        "Al massimo una consonante di fila",
        "Fino a {n} consonanti di fila",
    ),
    "is_ip": _flag("È un indirizzo IP, non un nome di dominio", "È un nome di dominio"),
    "is_punycode": _flag(
        "Contiene caratteri non latini, che possono imitare lettere comuni",
        "Solo caratteri latini standard",
    ),
    "brand_in_subdomain": _flag(
        "Un marchio noto compare nel sottodominio", "Nessun marchio noto nel sottodominio"
    ),
    "brand_in_domain_not_exact": _flag(
        "Un marchio noto è inserito in un nome diverso dal suo",
        "Nessun marchio noto inserito nel nome",
    ),
    "n_keywords": lambda v: _count(
        v,
        "Nessuna parola tipica del phishing",
        "Una parola tipica del phishing (accesso, verifica, ...)",
        "{n} parole tipiche del phishing (accesso, verifica, ...)",
    ),
}

# Per suffisso ed entropia la frase dipende dalla direzione del contributo:
# il valore da solo non dice nulla di comprensibile.
DIRECTIONAL: dict[str, tuple[Callable[[object], str], Callable[[object], str]]] = {
    "suffix": (
        lambda v: f"Il suffisso .{v} è frequente tra i domini di phishing",
        lambda v: f"Il suffisso .{v} è frequente tra i domini legittimi",
    ),
    "entropy": (
        lambda v: "Combinazione di caratteri poco comune nei nomi legittimi",
        lambda v: "Combinazione di caratteri comune nei nomi legittimi",
    ),
}


def describe(feature: str, value, contribution: float) -> str:
    if feature in DIRECTIONAL:
        risk, safe = DIRECTIONAL[feature]
        return (risk if contribution > 0 else safe)(value)
    fn = FACTS.get(feature)
    return fn(value) if fn else f"{feature} = {value}"


def top_reasons(
    features: dict, contributions: dict[str, float], k: int = 3, direction: str = "risk"
) -> list[Reason]:
    """Le k ragioni principali verso il phishing ("risk") o verso il legittimo ("safe")."""
    sign = 1 if direction == "risk" else -1
    ranked = sorted(
        ((f, c) for f, c in contributions.items() if sign * c > 0),
        key=lambda t: -abs(t[1]),
    )
    return [
        Reason(f, features[f], round(float(c), 4), describe(f, features[f], c))
        for f, c in ranked[:k]
    ]
