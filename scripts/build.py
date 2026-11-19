#!/usr/bin/env python3
"""Genera el catálogo de NimboxSRE: CISA KEV + los añadidos propios.

Uso: python3 scripts/build.py [--cisa fichero.json]

- Descarga el catálogo de CISA (o lo lee de --cisa) y le suma additions.json.
- Cada entrada lleva "source": "CISA" o "NimboxSRE".
- Un añadido que CISA ya tiene se queda con los datos de CISA y se anota en
  "nimboxsreNotes" (lo vimos antes: dateAddedNimboxSRE).
- Escribe known_exploited_vulnerabilities.json y .csv con el mismo esquema que
  cisagov/kev-data (más esos campos), para que cualquier herramienta que lea el
  de CISA lea este sin cambios.
- Falla (exit 1) si additions.json no es válido: así no se publica nada roto.
"""
import argparse
import csv
import datetime as dt
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CISA_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
FIELDS = ["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription",
          "requiredAction", "dueDate", "knownRansomwareCampaignUse", "notes", "cwes", "source"]
REQUIRED = ["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription", "evidence"]


def fetch_cisa():
    last = None
    for url in CISA_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "nimboxsre-kev-data"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.load(r)
            if len(data.get("vulnerabilities", [])) < 1000:
                raise ValueError(f"{url}: catálogo sospechosamente corto")
            return data
        except Exception as e:  # noqa: BLE001 - se prueba la siguiente fuente
            last = e
            print(f"aviso: {url}: {e}", file=sys.stderr)
    raise SystemExit(f"no se pudo descargar el catálogo de CISA: {last}")


def load_additions():
    data = json.loads((ROOT / "additions.json").read_text(encoding="utf-8"))
    out, errors, seen = [], [], set()
    for i, a in enumerate(data.get("vulnerabilities", [])):
        where = f"additions.json #{i + 1} ({a.get('cveID', '?')})"
        for k in REQUIRED:
            if not a.get(k):
                errors.append(f"{where}: falta {k}")
        if a.get("cveID") and not CVE_RE.match(a["cveID"]):
            errors.append(f"{where}: cveID no válido")
        if a.get("dateAdded") and not DATE_RE.match(a["dateAdded"]):
            errors.append(f"{where}: dateAdded debe ser AAAA-MM-DD")
        ev = a.get("evidence") or []
        if not isinstance(ev, list) or not all(isinstance(u, str) and u.startswith("https://") for u in ev):
            errors.append(f"{where}: evidence debe ser una lista de URLs https://")
        if a.get("cveID") in seen:
            errors.append(f"{where}: repetida")
        seen.add(a.get("cveID"))
        out.append(a)
    if errors:
        raise SystemExit("additions.json no es válido:\n  " + "\n  ".join(errors))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cisa", help="usar este fichero en vez de descargar")
    args = ap.parse_args()
    cisa = json.loads(Path(args.cisa).read_text()) if args.cisa else fetch_cisa()
    additions = load_additions()

    by_cve = {}
    for v in cisa["vulnerabilities"]:
        v = dict(v)
        v["source"] = "CISA"
        by_cve[v["cveID"]] = v
    ours = 0
    for a in additions:
        cve = a["cveID"]
        note = a.get("notes", "")
        if cve in by_cve:
            # CISA ya la tiene: mandan sus datos; se deja constancia de que la vimos antes.
            v = by_cve[cve]
            v["dateAddedNimboxSRE"] = a["dateAdded"]
            v["evidence"] = a["evidence"]
            continue
        ours += 1
        v = {k: a.get(k, "") for k in FIELDS if k != "source"}
        v["cwes"] = a.get("cwes", [])
        v["requiredAction"] = a.get("requiredAction") or "Aplicar el parche del fabricante o la mitigación indicada; si no hay, retirar el servicio de la red."
        v["knownRansomwareCampaignUse"] = a.get("knownRansomwareCampaignUse") or "Unknown"
        v["notes"] = note
        v["evidence"] = a["evidence"]
        v["source"] = "NimboxSRE"
        by_cve[cve] = v

    # Explotación activa según el SSVC de CISA (vulnrichment) que aún no está en
    # el catálogo: entra con source CISA-ADP.
    adp = 0
    ssvc_file = ROOT / "ssvc.json"
    if ssvc_file.exists():
        for cve, a in json.loads(ssvc_file.read_text(encoding="utf-8")).get("active", {}).items():
            if cve in by_cve:
                continue
            adp += 1
            by_cve[cve] = {"cveID": cve, "vendorProject": a.get("vendor", ""), "product": a.get("product", ""),
                           "vulnerabilityName": a.get("title", "") or cve, "dateAdded": a.get("date", ""),
                           "shortDescription": a.get("description", ""),
                           "requiredAction": "Aplicar el parche del fabricante o la mitigación indicada; si no hay, retirar el servicio de la red.",
                           "dueDate": "", "knownRansomwareCampaignUse": "Unknown", "notes": "CISA marca explotación activa (SSVC, vulnrichment) y aún no está en KEV.",
                           "cwes": [], "source": "CISA-ADP",
                           "evidence": ["https://github.com/cisagov/vulnrichment"]}
    vulns = sorted(by_cve.values(), key=lambda v: (v.get("dateAdded", ""), v["cveID"]), reverse=True)
    out = {
        "title": "NimboxSRE Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": cisa.get("catalogVersion", ""),
        "dateReleased": cisa.get("dateReleased", ""),
        "count": len(vulns),
        "counts": {"CISA": len(vulns) - ours - adp, "CISA-ADP": adp, "NimboxSRE": ours},
        "sources": ["CISA KEV (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)",
                    "CISA-ADP: explotación activa en el SSVC de CISA (https://github.com/cisagov/vulnrichment)", "NimboxSRE (additions.json)"],
        "vulnerabilities": vulns,
    }
    new_json = json.dumps(out, indent=4, ensure_ascii=False) + "\n"
    target = ROOT / "known_exploited_vulnerabilities.json"
    # Sin cambios reales (solo la hora de generación), no se reescribe: así no hay commits vacíos.
    if target.exists() and target.read_text(encoding="utf-8") == new_json:
        print(f"sin cambios: {len(vulns)} entradas ({ours} propias)")
        return
    target.write_text(new_json, encoding="utf-8")
    with open(ROOT / "known_exploited_vulnerabilities.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(FIELDS)
        for v in vulns:
            w.writerow([", ".join(v.get(k) or []) if k == "cwes" else v.get(k, "") for k in FIELDS])
    print(f"actualizado: {len(vulns)} entradas ({ours} propias, {adp} de CISA-ADP) · {dt.datetime.now(dt.UTC):%Y-%m-%d %H:%M} UTC")


if __name__ == "__main__":
    main()
