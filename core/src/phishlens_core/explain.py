"""Traduzione dei contributi SHAP in frasi comprensibili.

Usato dall'analisi del modello e, più avanti, dal worker per spiegare
all'utente perché un dominio ha ricevuto un certo punteggio.
I testi non contengono mai il nome del dominio: l'interfaccia lo mostrerà
a parte, in forma non cliccabile.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Reason:
    feature: str
    value: float | int | str
    contribution: float  # > 0 spinge verso il phishing, < 0 verso il legittimo
    text: str


def _n(v) -> str:
    return f"{v:g}" if isinstance(v, float) else str(v)


RISK_TEXT = {
    "suffix": lambda v: f"Il suffisso .{v} è frequente tra i domini di phishing",
    "host_length": lambda v: f"Nome di dominio lungo ({_n(v)} caratteri)",
    "n_labels": lambda v: f"Nome composto da molte parti ({_n(v)})",
    "n_subdomain_labels": lambda v: f"Contiene sottodomini ({_n(v)})",
    "domain_label_length": lambda v: f"Nome principale lungo ({_n(v)} caratteri)",
    "longest_label": lambda v: f"Una parte del nome è molto lunga ({_n(v)} caratteri)",
    "n_hyphens": lambda v: f"Contiene {_n(v)} trattini",
    "n_digits": lambda v: f"Contiene {_n(v)} cifre",
    "digit_ratio": lambda v: "Alta proporzione di cifre nel nome",
    "entropy": lambda v: "Sequenza di caratteri poco naturale, tipica dei nomi generati",
    "max_consonant_run": lambda v: f"Sequenza di {_n(v)} consonanti consecutive",
    "is_ip": lambda v: "Usa un indirizzo IP al posto di un nome di dominio",
    "is_punycode": lambda v: "Contiene caratteri internazionali che possono imitarne altri",
    "brand_in_subdomain": lambda v: "Un marchio noto compare nel sottodominio",
    "brand_in_domain_not_exact": lambda v: "Un marchio noto è inserito in un altro nome di dominio",
    "n_keywords": lambda v: "Contiene parole tipiche del phishing (accesso, verifica, ...)",
}

SAFE_TEXT = {
    "suffix": lambda v: f"Il suffisso .{v} è frequente tra i domini legittimi",
    "host_length": lambda v: f"Nome di dominio breve ({_n(v)} caratteri)",
    "n_subdomain_labels": lambda v: "Pochi o nessun sottodominio",
    "domain_label_length": lambda v: "Nome principale breve",
    "n_digits": lambda v: "Nessuna o poche cifre nel nome",
    "n_hyphens": lambda v: "Nessuno o pochi trattini",
    "entropy": lambda v: "Sequenza di caratteri naturale",
}


def describe(feature: str, value, contribution: float) -> str:
    table = RISK_TEXT if contribution > 0 else SAFE_TEXT
    fn = table.get(feature)
    return fn(value) if fn else f"{feature} = {_n(value)}"


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
