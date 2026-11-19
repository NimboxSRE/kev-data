#!/usr/bin/env python3
"""Genera poc.json: disponibilidad de PoC/exploit público en GitHub por CVE.

Uso: python3 scripts/poc.py <dir-clon-de-nomi-sec> [commit]

- Lee los ficheros AÑO/CVE-*.json de un clon de nomi-sec/PoC-in-GitHub (cada uno
  es el resultado de la búsqueda en GitHub: la lista de repos que mencionan ese
  CVE).
- Filtra ruido: descarta forks y exige un mínimo de tracción o corroboración
  (estrellas o varios repos distintos). Esto NO es el KEV (explotada de verdad):
  es solo "existe PoC público", una señal más débil para desempatar prioridad.
- Escribe poc.json compacto: por CVE, nº de repos, estrellas máx., primer visto
  y hasta 3 enlaces (los de más estrellas).
"""
import datetime as dt
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Umbrales de calidad. Se guarda un CVE si tiene al menos un repo (no fork) con
# MIN_STARS estrellas, o al menos MIN_REPOS repos distintos (no fork) que lo
# mencionan (corroboración). Así se filtran repos sueltos de 0 estrellas.
MIN_STARS = 2
MIN_REPOS = 2
TOP_LINKS = 3
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def main():
    if len(sys.argv) < 2:
        raise SystemExit("uso: poc.py <dir-clon-nomi-sec> [commit]")
    src = Path(sys.argv[1])
    commit = sys.argv[2] if len(sys.argv) > 2 else ""
    cves = {}
    for yd in sorted(src.glob("[12][09][0-9][0-9]")):
        if not yd.is_dir():
            continue
        for f in yd.glob("CVE-*.json"):
            cve = f.stem
            if not CVE_RE.match(cve):
                continue
            try:
                repos = json.loads(f.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            if not isinstance(repos, list):
                continue
            # dedupe por full_name, descarta forks; se queda la mejor (más estrellas).
            seen = {}
            for r in repos:
                if not isinstance(r, dict) or r.get("fork"):
                    continue
                fn, url = r.get("full_name"), r.get("html_url")
                if not fn or not url:
                    continue
                stars = int(r.get("stargazers_count") or 0)
                created = (r.get("created_at") or "")[:10]
                prev = seen.get(fn)
                if prev is None or stars > prev["stars"]:
                    seen[fn] = {"url": url, "stars": stars, "created": created}
            if not seen:
                continue
            items = sorted(seen.values(), key=lambda x: x["stars"], reverse=True)
            max_stars = items[0]["stars"]
            if max_stars < MIN_STARS and len(items) < MIN_REPOS:
                continue
            firsts = sorted(x["created"] for x in items if x["created"])
            cves[cve] = {
                "repos": len(items),
                "stars": max_stars,
                "firstSeen": firsts[0] if firsts else "",
                "top": [x["url"] for x in items[:TOP_LINKS]],
            }
    out = {
        "title": "Public exploit/PoC availability on GitHub, curated by NimboxSRE",
        "source": "nomi-sec/PoC-in-GitHub",
        "note": "Señal de 'existe PoC público', filtrada por tracción; NO es explotación activa (eso es el KEV).",
        "commit": commit,
        "generated": f"{dt.datetime.now(dt.UTC):%Y-%m-%dT%H:%M:%SZ}",
        "filters": {"minStars": MIN_STARS, "minRepos": MIN_REPOS, "excludeForks": True},
        "count": len(cves),
        "cves": dict(sorted(cves.items())),
    }
    target = ROOT / "poc.json"
    new = json.dumps(out, indent=1, ensure_ascii=False) + "\n"

    # No reescribir si solo cambian la hora/el commit (evita commits vacíos).
    def stable(s):
        d = json.loads(s)
        d.pop("generated", None)
        d.pop("commit", None)
        return json.dumps(d, sort_keys=True)

    if target.exists() and stable(target.read_text(encoding="utf-8")) == stable(new):
        print(f"sin cambios: {len(cves)} CVE con PoC")
        return
    target.write_text(new, encoding="utf-8")
    print(f"actualizado: {len(cves)} CVE con PoC público · {out['generated']}")


if __name__ == "__main__":
    main()
