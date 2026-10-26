"""Ve bieu do CHI tu du lieu trong evidence/: realm-export-filtered.json va make-verify.log."""
import json
import re
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
EV, FIG = ROOT / "evidence", ROOT / "docs" / "figures"
FIG.mkdir(parents=True, exist_ok=True)
realm = json.loads((EV / "realm-export-filtered.json").read_text(encoding="utf-8"))
log = (EV / "make-verify.log").read_text(encoding="utf-8")

# 1) Vong doi token/phien (giay) - tu realm-export-filtered.json
items = [("Access token", "accessTokenLifespan"), ("SSO idle", "ssoSessionIdleTimeout"),
         ("Client session idle", "clientSessionIdleTimeout"),
         ("SSO toi da", "ssoSessionMaxLifespan"), ("Client session toi da", "clientSessionMaxLifespan")]
labels = [a for a, _ in items]; vals = [realm[k] for _, k in items]
fig, ax = plt.subplots(figsize=(7, 3.2))
bars = ax.barh(labels[::-1], vals[::-1], color="#2f6f9f")
for b, v in zip(bars, vals[::-1]):
    ax.text(v, b.get_y() + b.get_height() / 2, f" {v} s", va="center", fontsize=9)
ax.set_xlabel("giây"); ax.set_xlim(0, max(vals) * 1.18); ax.spines[["top", "right"]].set_visible(False)
ax.set_title("Vòng đời token và phiên (nguồn: realm-export-filtered.json)", fontsize=10)
fig.tight_layout(); fig.savefig(FIG / "vong-doi-token.png", dpi=160); plt.close(fig)

# 2) So ca kiem dat theo bo - dem dong "ok" trong make-verify.log
c = Counter(m.group(1) for m in re.finditer(r"\(\w+\.(\w+)\.test_\w+\) \.\.\.", log))
ran = [int(x) for x in re.findall(r"Ran (\d+) tests", log)]
json.dump({"theo_bo": c, "Ran": ran}, open(FIG / "du-lieu-bieu-do-2.json", "w"), indent=1)
fig, ax = plt.subplots(figsize=(7, 3.0))
names = list(c.keys()); counts = [c[n] for n in names]
bars = ax.bar(names, counts, color="#4a8c5c")
for b, v in zip(bars, counts):
    ax.text(b.get_x() + b.get_width() / 2, v, str(v), ha="center", va="bottom", fontsize=9)
ax.set_ylabel("số ca"); ax.spines[["top", "right"]].set_visible(False)
ax.set_title("Ca kiểm unittest theo bộ (tất cả OK) (nguồn: make-verify.log)", fontsize=10)
plt.xticks(fontsize=8); fig.tight_layout(); fig.savefig(FIG / "ca-kiem-theo-bo.png", dpi=160); plt.close(fig)
assert sum(c.values()) == sum(ran), (sum(c.values()), ran)  # khop dong "Ran N tests"
assert "FAILED" not in log and log.count("\nOK\n") == len(ran)  # moi lan chay unittest deu OK
print(dict(c), "Ran:", ran)
