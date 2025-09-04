"""
Модуль обогащения веб-отчёта информацией об уязвимостях (NVD) и статусе поддержки/EOL (endoflife.date).

Использование как отдельного CLI:
    python asm.py --vuln -i reports/web_analyzer_report_YYYYMMDD_HHMMSS.json \
        --json-out reports/web_enriched.json --csv-out reports/web_enriched.csv \
        [--nvd-api-key XXX]

Также может использоваться программно через класс VulnEnricher.
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional

import json
import re
import time
from pathlib import Path

import requests


EOL_SLUGS: Dict[str, str] = {
    "PHP": "php",
    "WordPress": "wordpress",
    "Nginx": "nginx",
    "Apache": "httpd",
    "MySQL": "mysql",
    "jQuery": "jquery",
}

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _fetch_json(url: str, params: Optional[Dict[str, str]] = None, timeout: int = 20) -> Optional[dict]:
    try:
        r = requests.get(url, params=params, timeout=timeout)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None


def _normalize_version(version: str) -> str:
    m = re.match(r"(\d+(?:\.\d+){0,2})", version or "")
    return m.group(1) if m else (version or "")


class VulnEnricher:
    def __init__(self, nvd_api_key: Optional[str] = None, throttle_s: float = 0.2) -> None:
        self.nvd_api_key = nvd_api_key
        self.throttle_s = throttle_s

    def eol_status(self, product_name: str, version: str) -> Dict[str, Any]:
        slug = EOL_SLUGS.get(product_name)
        if not slug or not version:
            return {"supported": None, "cycle": None, "latest": None, "eol": None, "source": "endoflife.date"}
        data = _fetch_json(f"https://endoflife.date/api/{slug}.json")
        if not data or not isinstance(data, list):
            return {"supported": None, "cycle": None, "latest": None, "eol": None, "source": "endoflife.date"}
        ver = _normalize_version(version)

        best = None
        for row in data:
            cycle = str(row.get("cycle", "")).strip()
            if cycle == ver or cycle.startswith(ver) or ver.startswith(cycle):
                best = row
                break
        if not best:
            v_mm = ".".join(ver.split(".")[:2])
            for row in data:
                cycle = str(row.get("cycle", "")).strip()
                if cycle == v_mm or cycle.startswith(v_mm) or v_mm.startswith(cycle):
                    best = row
                    break
        if not best:
            latest = next((r for r in data if r.get("latest")), None)
            return {
                "supported": None,
                "cycle": None,
                "latest": latest.get("latest") if latest else None,
                "eol": None,
                "source": "endoflife.date",
            }
        return {
            "supported": not bool(best.get("eol")),
            "cycle": best.get("cycle"),
            "latest": best.get("latest"),
            "eol": best.get("eol"),
            "source": "endoflife.date",
        }

    def nvd_search(self, product_name: str, version: str, max_items: int = 5) -> List[Dict[str, Any]]:
        if not product_name or not version:
            return []
        params = {
            "keywordSearch": f"{product_name} {version}",
            "startIndex": "0",
            "resultsPerPage": str(max_items),
            "pubStartDate": "2010-01-01T00:00:00.000",
        }
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        try:
            r = requests.get(NVD_API, params=params, headers=headers, timeout=25)
            if r.status_code != 200:
                return []
            data = r.json()
        except Exception:
            return []
        vulns: List[Dict[str, Any]] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key)
                if arr and isinstance(arr, list) and arr[0].get("cvssData", {}).get("baseScore") is not None:
                    cvss = arr[0]["cvssData"]["baseScore"]
                    break
            # Извлечение CWE идентификаторов из слабостей
            cwes: List[str] = []
            weaknesses = cve.get("weaknesses", [])
            for w in weaknesses:
                desc = w.get("description", []) or w.get("descriptions", [])
                for d in desc:
                    val = d.get("value")
                    if val and val.startswith("CWE-"):
                        cwes.append(val)
            vulns.append({
                "id": cve.get("id"),
                "published": cve.get("published"),
                "lastModified": cve.get("lastModified"),
                "cvss": cvss,
                "source": "NVD",
                "descriptions": cve.get("descriptions", []),
                "cwe": sorted(set(cwes)),
            })
        return vulns

    def enrich(self, report_json_path: Path) -> Dict[str, Any]:
        data = json.loads(report_json_path.read_text(encoding="utf-8"))
        enriched: Dict[str, Any] = {}
        for domain, blob in data.items():
            detected = (blob.get("detected") or {})
            domain_out: Dict[str, Any] = {}
            for product, meta in detected.items():
                versions = meta.get("versions", []) or [""]
                prod_out: Dict[str, Any] = {}
                for ver in versions:
                    eol = self.eol_status(product, ver)
                    time.sleep(self.throttle_s)
                    vulns = self.nvd_search(product, ver, max_items=5)
                    prod_out[ver or "-"] = {
                        "eol": eol,
                        "vulnerabilities": vulns,
                    }
                domain_out[product] = prod_out
            enriched[domain] = {
                "domain": domain,
                "enriched": domain_out,
            }
        return enriched

    def save_outputs(self, enriched: Dict[str, Any], json_out: Optional[Path], csv_out: Optional[Path]) -> None:
        if json_out:
            json_out.write_text(json.dumps(enriched, ensure_ascii=False, indent=2), encoding="utf-8")
        if csv_out:
            rows: List[str] = [
                "domain,product,version,eol_supported,eol_cycle,eol_date,latest,vuln_count,top_cvss",
            ]
            for domain, payload in enriched.items():
                enr = payload.get("enriched", {})
                for product, versions in enr.items():
                    for ver, info in versions.items():
                        eol = info.get("eol", {})
                        vulns = info.get("vulnerabilities", [])
                        top_cvss = max((v.get("cvss") or 0 for v in vulns), default=0)
                        rows.append(
                            ",".join([
                                str(domain),
                                str(product).replace(",", " "),
                                str(ver).replace(",", " "),
                                str(eol.get("supported")),
                                str(eol.get("cycle") or ""),
                                str(eol.get("eol") or ""),
                                str(eol.get("latest") or ""),
                                str(len(vulns)),
                                str(top_cvss),
                            ])
                        )
            csv_out.write_text("\n".join(rows), encoding="utf-8")


