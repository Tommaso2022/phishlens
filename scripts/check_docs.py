#!/usr/bin/env python3
"""
Controllo incrociato della documentazione di sicurezza di PhishLens.

Verifica che threat model e requisiti ASVS siano coerenti tra loro:
  - ogni abuse case (sezione 8) è coperto da almeno una riga STRIDE (sezione 7);
  - i collegamenti tra abuse case e righe STRIDE sono coerenti nei due sensi;
  - ogni riga STRIDE ha mitigazione, capitolo ASVS e test;
  - i capitoli ASVS citati esistono in security-requirements.md;
  - i requisiti dei capitoli prioritari sono compilati.

Uso (dalla cartella del repository):
    python3 scripts/check_docs.py

Esce con codice 1 se trova errori, quindi si può usare in CI.
Gli avvisi segnalano incoerenze da valutare ma non fanno fallire il controllo.
"""

import argparse
import re
import sys
from pathlib import Path

PRIORITY_CHAPTERS = ["V8", "V6", "V7", "V1", "V2"]
EMPTY = {"", "—", "-", "–"}

errors: list[str] = []
warnings: list[str] = []


def error(msg: str) -> None:
    errors.append(msg)


def warn(msg: str) -> None:
    warnings.append(msg)


def split_row(line: str) -> list[str]:
    """Divide una riga di tabella Markdown, rispettando i \\| e il codice inline."""
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|") and not line.endswith("\\|"):
        line = line[:-1]
    cells, cur, in_code, i = [], [], False, 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line) and line[i + 1] == "|":
            cur.append("|")
            i += 2
            continue
        if ch == "`":
            in_code = not in_code
        if ch == "|" and not in_code:
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    cells.append("".join(cur).strip())
    return cells


def section(text: str, number: str) -> str:
    """Restituisce il testo della sezione '## <number>.' fino alla successiva '## '."""
    m = re.search(rf"^## {re.escape(number)}\.[^\n]*\n", text, re.M)
    if not m:
        return ""
    rest = text[m.end():]
    nxt = re.search(r"^## ", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def tables(text: str) -> list[list[dict]]:
    """Estrae tutte le tabelle Markdown come liste di dizionari colonna → valore."""
    result, lines, i = [], text.splitlines(), 0
    while i < len(lines) - 1:
        if lines[i].lstrip().startswith("|") and re.match(
            r"^\s*\|?\s*:?-{3,}", lines[i + 1]
        ):
            header = split_row(lines[i])
            rows, j = [], i + 2
            while j < len(lines) and lines[j].lstrip().startswith("|"):
                cells = split_row(lines[j])
                cells += [""] * (len(header) - len(cells))
                rows.append(dict(zip(header, cells)))
                j += 1
            result.append(rows)
            i = j
        else:
            i += 1
    return result


def find_table(text: str, required: set[str]) -> list[dict] | None:
    for t in tables(text):
        if t and required <= set(t[0].keys()):
            return t
    return None


def ids(cell: str, pattern: str) -> set[str]:
    return set(re.findall(pattern, cell))


def check_threat_model(path: Path) -> tuple[set[str], set[str]]:
    text = path.read_text(encoding="utf-8")

    stride = find_table(section(text, "7"),
                        {"ID", "Mitigazione", "Abuse case", "ASVS", "Test"})
    abuse = find_table(section(text, "8"), {"ID", "Righe STRIDE"})
    if stride is None:
        error(f"{path}: tabella STRIDE non trovata nella sezione 7 "
              "(servono le colonne ID, Mitigazione, Abuse case, ASVS, Test).")
        return set(), set()
    if abuse is None:
        error(f"{path}: tabella degli abuse case non trovata nella sezione 8 "
              "(servono le colonne ID e Righe STRIDE).")
        return set(), set()

    stride_ids: dict[str, dict] = {}
    for row in stride:
        rid = row["ID"]
        if rid in stride_ids:
            error(f"Riga STRIDE duplicata: {rid}")
        stride_ids[rid] = row
        for col in ("Mitigazione", "ASVS", "Test"):
            if row[col] in EMPTY:
                (warn if col == "ASVS" else error)(
                    f"Riga STRIDE {rid}: colonna '{col}' vuota.")

    ac_rows = {row["ID"]: row for row in abuse}
    covered_by: dict[str, set[str]] = {ac: set() for ac in ac_rows}

    for rid, row in stride_ids.items():
        for ac in ids(row["Abuse case"], r"AC\d+"):
            if ac not in ac_rows:
                error(f"Riga STRIDE {rid}: cita {ac}, che non esiste nella sezione 8.")
            else:
                covered_by[ac].add(rid)

    for ac, row in ac_rows.items():
        declared = ids(row["Righe STRIDE"], r"[STRIDE]-\d+")
        for rid in declared - set(stride_ids):
            error(f"{ac}: cita la riga STRIDE {rid}, che non esiste nella sezione 7.")
        if not covered_by[ac] and not declared:
            error(f"{ac}: nessuna riga STRIDE lo copre.")
        for rid in sorted(covered_by[ac] - declared):
            warn(f"{rid} cita {ac}, ma {ac} non elenca {rid} nella colonna 'Righe STRIDE'.")
        for rid in sorted(declared & set(stride_ids) - covered_by[ac]):
            warn(f"{ac} elenca {rid}, ma {rid} non cita {ac} nella colonna 'Abuse case'.")

    chapters = set()
    tests = set()
    for row in stride_ids.values():
        chapters |= ids(row["ASVS"], r"V\d+")
        tests |= ids(row["Test"], r"test_\w+")
    return chapters, tests


def check_requirements(path: Path, chapters_used: set[str], tests: set[str]) -> None:
    text = path.read_text(encoding="utf-8")
    present = set(re.findall(r"^## (V\d+) ", text, re.M))

    for ch in sorted(chapters_used - present, key=lambda c: int(c[1:])):
        error(f"Il threat model cita il capitolo {ch}, assente in {path.name}.")

    for ch in PRIORITY_CHAPTERS:
        m = re.search(rf"^## {ch} [^\n]*\n", text, re.M)
        if not m:
            error(f"Capitolo prioritario {ch} assente in {path.name}.")
            continue
        rest = text[m.end():]
        nxt = re.search(r"^## ", rest, re.M)
        body = rest[: nxt.start()] if nxt else rest
        for t in tables(body):
            for row in t:
                rid = row.get("ID", "?")
                appl = row.get("Applicabile", "")
                if appl in EMPTY:
                    error(f"{rid}: colonna 'Applicabile' da compilare.")
                elif appl.startswith("Sì"):
                    for col in ("Implementazione", "Verifica"):
                        if row.get(col, "") in EMPTY:
                            error(f"{rid}: applicabile ma colonna '{col}' vuota.")
                elif appl.startswith("No") and len(appl) < 8:
                    error(f"{rid}: non applicabile senza motivazione.")

    missing = sorted(t for t in tests if t not in text)
    for t in missing:
        warn(f"Il test {t} è nel threat model ma nessun requisito ASVS lo cita.")


def main() -> None:
    p = argparse.ArgumentParser(description="Controllo incrociato dei documenti di sicurezza.")
    p.add_argument("--threat-model", type=Path, default=Path("docs/threat-model.md"))
    p.add_argument("--requirements", type=Path,
                   default=Path("docs/security-requirements.md"))
    p.add_argument("--strict", action="store_true",
                   help="tratta anche gli avvisi come errori")
    args = p.parse_args()

    for f in (args.threat_model, args.requirements):
        if not f.is_file():
            sys.exit(f"Errore: file {f} non trovato. Lancia lo script dalla cartella del repository.")

    chapters, tests = check_threat_model(args.threat_model)
    check_requirements(args.requirements, chapters, tests)

    for e in errors:
        print(f"ERRORE  {e}")
    for w in warnings:
        print(f"AVVISO  {w}")
    print(f"\n{len(errors)} errori, {len(warnings)} avvisi.")
    if errors or (args.strict and warnings):
        sys.exit(1)
    print("Controllo superato.")


if __name__ == "__main__":
    main()
