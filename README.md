# kev-data · NimboxSRE

Catálogo de **vulnerabilidades explotadas** de NimboxSRE: el catálogo
[KEV de CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) más las que NimboxSRE confirma
como explotadas antes de que CISA las publique.

Lo usa [Patch by NimboxSRE](https://patch.nimboxsre.com) para decidir qué parchear primero, y lo puede usar
cualquier herramienta que ya lea el catálogo de CISA: el esquema es el mismo.

## Ficheros

| Fichero | Qué es |
|---|---|
| [`known_exploited_vulnerabilities.json`](known_exploited_vulnerabilities.json) | El catálogo completo (mismo esquema que [cisagov/kev-data](https://github.com/cisagov/kev-data)) |
| [`known_exploited_vulnerabilities.csv`](known_exploited_vulnerabilities.csv) | Lo mismo en CSV |
| [`additions.json`](additions.json) | Las entradas propias de NimboxSRE (se editan a mano) |
| [`scripts/build.py`](scripts/build.py) | Genera el catálogo |

URL estable para descargarlo:

```
https://raw.githubusercontent.com/NimboxSRE/kev-data/main/known_exploited_vulnerabilities.json
```

## Qué añade sobre el de CISA

- `source` en cada entrada: `CISA` o `NimboxSRE`.
- `counts` en la cabecera: cuántas entradas vienen de cada sitio.
- Entradas con `source: NimboxSRE`: explotación confirmada que CISA aún no tiene, con `evidence` (enlaces
  públicos que la prueban).
- Cuando CISA añade una que ya teníamos, mandan sus datos y la entrada conserva `dateAddedNimboxSRE` y
  `evidence`: así se ve cuánto antes se supo.

## Cómo se actualiza

Una acción de GitHub ([`update.yml`](.github/workflows/update.yml)) se ejecuta **cada hora** y cada vez que
cambia `additions.json`. Descarga el catálogo de CISA (de cisa.gov o, si no responde, de cisagov/kev-data), le
suma los añadidos y solo hace commit si algo cambió.

## Añadir una vulnerabilidad

Solo explotación **confirmada** (no basta un PoC publicado), con evidencia pública. Una entrada en
`additions.json`:

```json
{
    "cveID": "CVE-2026-12345",
    "vendorProject": "OpenBSD",
    "product": "OpenSSH",
    "vulnerabilityName": "OpenSSH ... Remote Code Execution",
    "dateAdded": "2026-11-19",
    "shortDescription": "Qué es y qué permite, en una o dos frases.",
    "requiredAction": "Actualizar a 10.6p2 o, hasta entonces, ...",
    "knownRansomwareCampaignUse": "Unknown",
    "notes": "Opcional.",
    "cwes": ["CWE-787"],
    "evidence": ["https://…aviso del fabricante o informe de la explotación…"]
}
```

Obligatorios: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded` (AAAA-MM-DD),
`shortDescription` y `evidence` (lista de URLs `https://`). Si falta algo, `build.py` falla y no se publica nada.

Para probarlo en local: `python3 scripts/build.py`.

## Privacidad

Este repositorio no contiene nada de los servidores ni de los clientes de NimboxSRE: solo datos públicos de
vulnerabilidades.

## Licencia

Los datos de CISA son de dominio público. Las aportaciones de NimboxSRE y el código se publican con
[CC0 1.0](LICENSE): úsalos como quieras.
