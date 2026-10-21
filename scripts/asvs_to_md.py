#!/usr/bin/env python3
"""
Genera lo scheletro di docs/security-requirements.md a partire dal CSV
ufficiale OWASP ASVS 5.0.0.

Uso (dalla cartella del repository):
    python3 scripts/asvs_to_md.py docs/asvs/asvs-5.0.0.csv

Opzioni:
    -o / --output     file di destinazione (default: docs/security-requirements.md)
    --max-level       livello massimo da includere: 1, 2 o 3 (default: 2)
    --force           sovrascrive il file di destinazione se non è vuoto

Lo script va lanciato una sola volta: dopo, il file si compila a mano.
Per proteggere il lavoro fatto, rifiuta di sovrascrivere un file non vuoto
a meno di usare --force.
"""

import argparse
import csv
import sys
from collections import OrderedDict
from pathlib import Path

ASVS_VERSION = "5.0.0"
SOURCE_URL = "https://github.com/OWASP/ASVS/tree/v5.0.0"

# Capitoli non applicabili a PhishLens, con la motivazione da riportare.
NOT_APPLICABLE = {
    "V9": "Sessioni lato server, nessun token self-contained (ADR-002)",
    "V10": "Nessun login tramite provider OAuth/OIDC esterni",
    "V17": "L'applicazione non usa WebRTC",
}

# Capitoli da compilare per primi.
PRIORITY = ["V8", "V6", "V7", "V1", "V2"]

EXPECTED_COLUMNS = {
    "chapter_id", "chapter_name", "section_id", "section_name",
    "req_id", "req_description", "L",
}


def cell(text: str) -> str:
    """Rende un testo sicuro dentro una cella di tabella Markdown."""
    return " ".join(text.split()).replace("|", "\\|")


def versioned_id(req_id: str) -> str:
    """V1.2.5 -> v5.0.0-1.2.5, il formato raccomandato da OWASP."""
    return f"v{ASVS_VERSION}-{req_id.lstrip('Vv')}"


def load(csv_path: Path, max_level: int) -> "OrderedDict[str, dict]":
    chapters: "OrderedDict[str, dict]" = OrderedDict()
    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = EXPECTED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            sys.exit(f"Errore: nel CSV mancano le colonne {sorted(missing)}.")
        for row in reader:
            try:
                level = int(row["L"])
            except (TypeError, ValueError):
                continue
            if level > max_level:
                continue
            chapter = chapters.setdefault(
                row["chapter_id"],
                {"name": row["chapter_name"], "sections": OrderedDict()},
            )
            section = chapter["sections"].setdefault(
                row["section_id"], {"name": row["section_name"], "reqs": []}
            )
            section["reqs"].append(
                (row["req_id"], row["req_description"], level)
            )
    return chapters


def render(chapters: "OrderedDict[str, dict]", max_level: int) -> str:
    levels = ", ".join(f"L{n}" for n in range(1, max_level + 1))
    out = [
        "# Requisiti di sicurezza — PhishLens",
        "",
        f"Requisiti tratti da OWASP Application Security Verification Standard "
        f"{ASVS_VERSION} ([fonte]({SOURCE_URL})), livelli inclusi: {levels}.",
        "Contenuto ASVS rilasciato da OWASP sotto licenza "
        "[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).",
        "",
        "## Come leggere questo documento",
        "",
        "- **Applicabile:** `Sì` oppure `No — motivazione`.",
        "- **Implementazione:** modulo, configurazione o ADR che soddisfa il requisito.",
        "- **Verifica:** test automatico, controllo di configurazione o revisione manuale.",
        "- **Stato:** `Da fare`, `Implementato`, `Verificato` oppure `Non applicabile`.",
        "",
        "Ordine di compilazione consigliato: " + ", ".join(PRIORITY)
        + ", poi gli altri capitoli.",
        "",
        "## Riepilogo",
        "",
        "| Capitolo | Requisiti | Applicabilità del capitolo |",
        "| --- | --- | --- |",
    ]
    for ch_id, ch in chapters.items():
        count = sum(len(s["reqs"]) for s in ch["sections"].values())
        status = (
            f"No — {NOT_APPLICABLE[ch_id]}" if ch_id in NOT_APPLICABLE
            else "Da valutare requisito per requisito"
        )
        out.append(f"| {ch_id} {cell(ch['name'])} | {count} | {status} |")
    out.append("")

    for ch_id, ch in chapters.items():
        out.append(f"## {ch_id} {ch['name']}")
        out.append("")
        na = NOT_APPLICABLE.get(ch_id)
        if na:
            out.append(f"> Capitolo non applicabile: {na}.")
            out.append("")
        for sec_id, sec in ch["sections"].items():
            out.append(f"### {sec_id} {sec['name']}")
            out.append("")
            out.append(
                "| ID | Requisito | Liv. | Applicabile | Implementazione "
                "| Verifica | Stato |"
            )
            out.append("| --- | --- | --- | --- | --- | --- | --- |")
            for req_id, desc, level in sec["reqs"]:
                applicable = "No — vedi capitolo" if na else ""
                state = "Non applicabile" if na else "Da fare"
                out.append(
                    f"| {versioned_id(req_id)} | {cell(desc)} | L{level} "
                    f"| {applicable} |  |  | {state} |"
                )
            out.append("")
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Genera security-requirements.md dal CSV OWASP ASVS."
    )
    parser.add_argument("csv_path", type=Path)
    parser.add_argument(
        "-o", "--output", type=Path,
        default=Path("docs/security-requirements.md"),
    )
    parser.add_argument("--max-level", type=int, default=2, choices=[1, 2, 3])
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if not args.csv_path.is_file():
        sys.exit(f"Errore: il file {args.csv_path} non esiste.")
    if (args.output.exists() and args.output.stat().st_size > 0
            and not args.force):
        sys.exit(
            f"Errore: {args.output} non è vuoto. Usa --force solo se vuoi "
            "davvero sovrascrivere il lavoro già fatto."
        )

    chapters = load(args.csv_path, args.max_level)
    if not chapters:
        sys.exit("Errore: nessun requisito trovato con i filtri scelti.")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(chapters, args.max_level) + "\n",
                           encoding="utf-8")

    total = sum(len(s["reqs"]) for c in chapters.values()
                for s in c["sections"].values())
    to_review = sum(len(s["reqs"]) for cid, c in chapters.items()
                    if cid not in NOT_APPLICABLE
                    for s in c["sections"].values())
    print(f"Scritto {args.output}: {total} requisiti, "
          f"{to_review} da valutare in {len(chapters)} capitoli.")


if __name__ == "__main__":
    main()
