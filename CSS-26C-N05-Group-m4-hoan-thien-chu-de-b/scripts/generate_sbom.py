"""Generate the project's source dependency SBOM with Syft."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SBOM_PATH = ROOT / "sbom.cdx.json"


def main() -> None:
    syft = shutil.which("syft")
    if syft is None and os.name == "nt":
        winget_link = (
            Path(os.environ.get("LOCALAPPDATA", ""))
            / "Microsoft"
            / "WinGet"
            / "Links"
            / "syft.exe"
        )
        if winget_link.is_file():
            syft = str(winget_link)
    if syft is None:
        raise SystemExit("Syft is required; install it and make sure it is on PATH")

    subprocess.run(
        [
            syft,
            "scan",
            "dir:.",
            "--source-name",
            "CSS-26C-OIDC-TOTP-Demo",
            "--select-catalogers",
            "python,github-actions,-file",
            "--quiet",
            "--output",
            f"cyclonedx-json={SBOM_PATH}",
        ],
        check=True,
        cwd=ROOT,
    )

    sbom = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
    component = sbom["metadata"]["component"]
    component["type"] = "application"
    component["name"] = "CSS-26C-OIDC-TOTP-Demo"
    component.pop("version", None)
    component["properties"] = [
        {
            "name": "scope",
            "value": (
                "Declared Python dependencies and GitHub Actions workflows; "
                "excludes container image package layers and runtime-resolved "
                "dependency inventories"
            ),
        }
    ]
    SBOM_PATH.write_text(
        json.dumps(sbom, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {SBOM_PATH}")


if __name__ == "__main__":
    main()
