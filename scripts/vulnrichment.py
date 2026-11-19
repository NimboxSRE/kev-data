#!/usr/bin/env python3
"""Extrae de cisagov/vulnrichment la valoración SSVC de CISA para cada CVE.

Uso: python3 scripts/vulnrichment.py RUTA_AL_CLON COMMIT

vulnrichment es el enriquecimiento que hace CISA (ADP «CISA-ADP») de cada
CVE: SSVC (explotación none/poc/active, automatizable, impacto técnico).
«Exploitation: active» es explotación confirmada, a menudo antes de que la
CVE entre en el catálogo KEV.

Escribe ssvc.json:
  {"source", "commit", "count", "counts", "cves": {"CVE-…": "e/a/t"}, "active": {...}}
con códigos cortos para que pese poco: e = n(one)/p(oc)/a(ctive),
a = y(es)/n(o), t = p(artial)/t(otal) («-» si CISA no lo dice). En «active»
van además fabricante, producto y título de las que se explotan, para
añadirlas al catálogo.
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
E = {"none": "n", "poc": "p", "active": "a"}
A = {"yes": "y", "no": "n"}
T = {"partial": "p", "total": "t"}


def ssvc_of(rec):
    for adp in rec.get("containers", {}).get("adp", []) or []:
        meta = adp.get("providerMetadata", {}) or {}
        if meta.get("shortName") != "CISA-ADP":
            continue
        for m in adp.get("metrics", []) or []:
            other = m.get("other", {}) or {}
            if other.get("type") != "ssvc":
                continue
            opts = {}
            for o in (other.get("content", {}) or {}).get("options", []) or []:
                for k, v in o.items():
                    opts[k.lower()] = str(v).lower()
            return opts, (other.get("content", {}) or {}).get("timestamp", "")
    return None, ""


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    clone, commit = Path(sys.argv[1]), sys.argv[2]
    cves, active = {}, {}
    counts = {"none": 0, "poc": 0, "active": 0}
    for dirpath, _, files in os.walk(clone):
        if ".git" in dirpath:
            continue
        for f in files:
            if not (f.startswith("CVE-") and f.endswith(".json")):
                continue
            try:
                rec = json.loads(Path(dirpath, f).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            opts, ts = ssvc_of(rec)
            if not opts:
                continue
            cve = rec.get("cveMetadata", {}).get("cveId") or f[:-5]
            e = opts.get("exploitation", "")
            code = E.get(e, "-") + A.get(opts.get("automatable", ""), "-") + T.get(opts.get("technical impact", ""), "-")
            cves[cve] = code
            if e in counts:
                counts[e] += 1
            if e == "active":
                cna = rec.get("containers", {}).get("cna", {}) or {}
                aff = (cna.get("affected") or [{}])[0]
                desc = next((d.get("value", "") for d in cna.get("descriptions", []) or [] if d.get("lang", "").startswith("en")), "")
                active[cve] = {"vendor": aff.get("vendor", ""), "product": aff.get("product", ""),
                               "title": cna.get("title", "") or desc[:160], "description": desc[:600], "date": ts[:10]}
    if len(cves) < 10000:
        raise SystemExit(f"solo {len(cves)} CVE con SSVC: el clon parece incompleto, no se escribe nada")
    out = {"source": "https://github.com/cisagov/vulnrichment", "commit": commit,
           "codes": "e: n(one)/p(oc)/a(ctive) · a: automatizable y/n · t: impacto técnico p(arcial)/t(otal)",
           "count": len(cves), "counts": counts, "cves": dict(sorted(cves.items())), "active": dict(sorted(active.items()))}
    (ROOT / "ssvc.json").write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"ssvc.json: {len(cves)} CVE · {counts} · commit {commit[:8]}")


if __name__ == "__main__":
    main()
