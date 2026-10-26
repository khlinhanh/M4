"""Sinh evidence/MANIFEST.txt: sha256 cua moi tep trong evidence/ (tru chinh MANIFEST.txt)."""
import hashlib
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parents[1] / "evidence"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    files = sorted(p for p in EVIDENCE.rglob("*") if p.is_file() and p.name != "MANIFEST.txt")
    lines = [f"{sha256(p)}  {p.relative_to(EVIDENCE).as_posix()}" for p in files]
    (EVIDENCE / "MANIFEST.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"MANIFEST.txt: {len(lines)} tep")


if __name__ == "__main__":
    main()
