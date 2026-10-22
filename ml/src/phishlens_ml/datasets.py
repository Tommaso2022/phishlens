"""Download e preparazione del dataset PhiUSIIL.

Uso, dalla radice del repository:
    uv run python -m phishlens_ml.datasets

Cosa fa, in ordine:
 1. scarica l'archivio da UCI in ml/data/raw/ (solo se non c'è già);
 2. ne calcola l'hash SHA-256 e lo confronta con ml/data-manifest.json;
    al primo download registra l'hash, ai successivi lo verifica;
 3. estrae il solo file CSV atteso, con limiti di dimensione (zip bomb)
    e senza mai usare i percorsi scritti dentro l'archivio (zip slip);
 4. tiene solo URL ed etichetta, li valida e salva un file Parquet
    in ml/data/processed/.

I dati contengono URL di phishing reali: non aprirli nel browser e non
committarli (ml/data/ è escluso da Git).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

ML_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = ML_DIR / "data"
MANIFEST = ML_DIR / "data-manifest.json"

SOURCE = {
    "name": "phiusiil",
    "url": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
    "csv_member": "PhiUSIIL_Phishing_URL_Dataset.csv",
    "license": "CC BY 4.0",
    "citation": (
        "Prasad, A. & Chandra, S. (2024). PhiUSIIL: A diverse security profile empowered "
        "phishing URL detection framework based on similarity index and incremental learning. "
        "Computers & Security. https://doi.org/10.1016/j.cose.2023.103545"
    ),
}

MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024  # l'archivio reale è molto più piccolo
MAX_CSV_BYTES = 500 * 1024 * 1024  # limite sul file estratto (zip bomb)
MAX_RATIO = 50  # rapporto massimo tra dimensione estratta e compressa
MAX_URL_LENGTH = 2048  # coerente con docs/validation.md
CHUNK = 1024 * 1024


class DatasetError(Exception):
    """Errore di integrità o di formato: il processo si ferma."""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def load_manifest(path: Path = MANIFEST) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_manifest(manifest: dict, path: Path = MANIFEST) -> None:
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def download(url: str, dest: Path, max_bytes: int = MAX_DOWNLOAD_BYTES) -> None:
    if not url.startswith("https://"):
        raise DatasetError("Sono ammessi solo download via HTTPS.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    received = 0
    # Lo schema è verificato sopra: solo https, niente file:// o schemi personalizzati.
    with urllib.request.urlopen(url, timeout=60) as response, tmp.open("wb") as out:  # noqa: S310  # nosec B310
        while block := response.read(CHUNK):
            received += len(block)
            if received > max_bytes:
                tmp.unlink(missing_ok=True)
                raise DatasetError(f"Download oltre il limite di {max_bytes} byte: interrotto.")
            out.write(block)
    tmp.replace(dest)


def verify_or_record(name: str, path: Path, manifest: dict, extra: dict | None = None) -> str:
    """Verifica l'hash di un file contro il manifest; se manca, lo registra."""
    actual = sha256_of(path)
    entry = manifest.get(name)
    if entry is None:
        manifest[name] = {
            "file": path.name,
            "sha256": actual,
            "recorded": datetime.now(UTC).strftime("%Y-%m-%d"),
            **(extra or {}),
        }
        print(f"[nuovo] {name}: hash registrato nel manifest ({actual[:16]}...)")
    elif entry["sha256"] != actual:
        raise DatasetError(
            f"{name}: hash diverso da quello registrato.\n"
            f"  atteso: {entry['sha256']}\n  trovato: {actual}\n"
            "Il file è cambiato alla fonte o è stato manomesso: verifica prima di usarlo."
        )
    else:
        print(f"[ok] {name}: hash verificato")
    return actual


def extract_member(archive: Path, member: str, dest: Path) -> None:
    """Estrae un solo file dall'archivio, con controlli contro zip bomb e zip slip."""
    with zipfile.ZipFile(archive) as zf:
        names = [i.filename for i in zf.infolist()]
        matches = [i for i in zf.infolist() if Path(i.filename).name == member]
        if len(matches) != 1:
            raise DatasetError(f"Atteso un solo '{member}' nell'archivio, trovati: {names}")
        info = matches[0]
        if info.file_size > MAX_CSV_BYTES:
            raise DatasetError(f"File dichiarato di {info.file_size} byte: oltre il limite.")
        if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
            raise DatasetError("Rapporto di compressione anomalo: possibile zip bomb.")
        # Il nome del file di destinazione lo decidiamo noi: il percorso scritto
        # nell'archivio (che potrebbe contenere ../) non viene mai usato.
        dest.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with zf.open(info) as src, dest.open("wb") as out:
            while block := src.read(CHUNK):
                written += len(block)
                if written > MAX_CSV_BYTES:
                    out.close()
                    dest.unlink(missing_ok=True)
                    raise DatasetError("Il file estratto supera il limite: interrotto.")
                out.write(block)


def prepare(csv_path: Path) -> pd.DataFrame:
    """Tiene solo URL ed etichetta, valida e pulisce.

    In PhiUSIIL l'etichetta vale 1 per i siti legittimi e 0 per il phishing:
    la convertiamo in `is_phishing` (1 = phishing) per non confonderci.
    """
    df = pd.read_csv(csv_path, usecols=lambda c: c.strip() in {"URL", "label"}, dtype=str)
    df.columns = [c.strip() for c in df.columns]
    if set(df.columns) != {"URL", "label"}:
        raise DatasetError(f"Colonne attese URL e label, trovate: {list(df.columns)}")

    labels = set(df["label"].dropna().str.strip().unique())
    if not labels <= {"0", "1"}:
        raise DatasetError(f"Etichette inattese: {sorted(labels)}")

    df["url"] = df["URL"].str.strip()
    df = df[df["url"].notna() & (df["url"] != "")]
    df["is_phishing"] = (df["label"].str.strip() == "0").astype("int8")
    df = df[["url", "is_phishing"]]

    too_long = (df["url"].str.len() > MAX_URL_LENGTH).sum()
    df = df[df["url"].str.len() <= MAX_URL_LENGTH]

    conflicts = df.groupby("url")["is_phishing"].nunique()
    conflicting = set(conflicts[conflicts > 1].index)
    df = df[~df["url"].isin(conflicting)]
    before = len(df)
    df = df.drop_duplicates("url").reset_index(drop=True)

    print(
        f"Scartati: {too_long} URL oltre {MAX_URL_LENGTH} caratteri, "
        f"{len(conflicting)} URL con etichette in conflitto, {before - len(df)} duplicati."
    )
    return df


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--url", default=SOURCE["url"])
    args = parser.parse_args(argv)

    raw = args.data_dir / "raw" / "phiusiil.zip"
    csv_path = args.data_dir / "raw" / SOURCE["csv_member"]
    out = args.data_dir / "processed" / "phiusiil.parquet"
    manifest = load_manifest(args.manifest)

    try:
        if not raw.exists():
            print(f"Download da {args.url} ...")
            download(args.url, raw)
        meta = {k: SOURCE[k] for k in ("url", "license", "citation")}
        verify_or_record("phiusiil.zip", raw, manifest, meta)
        extract_member(raw, SOURCE["csv_member"], csv_path)
        verify_or_record("phiusiil.csv", csv_path, manifest)
        df = prepare(csv_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        df.to_parquet(out, index=False)
    except DatasetError as e:
        print(f"ERRORE: {e}", file=sys.stderr)
        return 1

    save_manifest(manifest, args.manifest)
    phishing = int(df["is_phishing"].sum())
    print(f"Salvato {out}: {len(df)} URL ({phishing} phishing, {len(df) - phishing} legittimi).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
