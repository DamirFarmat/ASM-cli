from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

import requests
from colorama import Fore, Style, init
from tabulate import tabulate


init()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


class CVELookup:
    def __init__(self, nvd_api_key: Optional[str] = None, timeout_s: int = 25) -> None:
        self.nvd_api_key = nvd_api_key
        self.timeout_s = timeout_s

    def parse_software_input(self, raw: str) -> Tuple[str, str]:
        text = (raw or "").strip()
        if not text:
            return "", ""
        parts = text.split()
        if len(parts) < 2:
            return text, ""
        version = parts[-1]
        software = " ".join(parts[:-1]).strip()
        return software, version

    def _extract_cvss(self, metrics: Dict[str, Any]) -> Optional[float]:
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key)
            if not arr or not isinstance(arr, list):
                continue
            cvss_data = (arr[0] or {}).get("cvssData", {})
            score = cvss_data.get("baseScore")
            if score is not None:
                return score
        return None

    def _extract_cwes(self, cve: Dict[str, Any]) -> List[str]:
        cwes: List[str] = []
        for weakness in cve.get("weaknesses", []):
            desc = weakness.get("description", []) or weakness.get("descriptions", [])
            for item in desc:
                value = item.get("value")
                if isinstance(value, str) and value.startswith("CWE-"):
                    cwes.append(value)
        return sorted(set(cwes))

    def _description_ru_en(self, cve: Dict[str, Any]) -> str:
        descriptions = cve.get("descriptions", []) or []
        preferred = None
        fallback = None
        for item in descriptions:
            lang = (item.get("lang") or "").lower()
            value = (item.get("value") or "").strip()
            if not value:
                continue
            if lang == "ru":
                preferred = value
                break
            if lang == "en" and not fallback:
                fallback = value
        text = preferred or fallback or ""
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) > 180:
            return text[:177] + "..."
        return text

    def _nvd_get(self, url: str, params: Dict[str, str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        try:
            response = requests.get(url, params=params, headers=headers, timeout=self.timeout_s)
            if response.status_code != 200:
                return None, f"NVD API HTTP {response.status_code}"
            return response.json(), None
        except Exception as e:
            return None, str(e)

    def _normalize_name(self, value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", (value or "").lower()).strip("_")

    def _software_tokens(self, software: str) -> List[str]:
        return [t for t in re.split(r"[^a-z0-9]+", (software or "").lower()) if t]

    def _software_alias_products(self, software: str) -> List[str]:
        norm = self._normalize_name(software)
        aliases = {norm}
        # NVD часто использует nginx_open_source вместо nginx
        if norm == "nginx":
            aliases.add("nginx_open_source")
        return [a for a in aliases if a]

    def _find_cpe_candidates(self, software: str, version: str, max_candidates: int = 8) -> List[str]:
        query = f"{software} {version}".strip()
        data, _ = self._nvd_get(
            CPE_API,
            {
                "keywordSearch": query,
                "startIndex": "0",
                "resultsPerPage": "120",
            },
        )
        if not data:
            return []

        tokens = self._software_tokens(software)
        normalized_sw = self._normalize_name(software)
        candidates: List[Tuple[int, str]] = []
        seen = set()

        for product_blob in data.get("products", []):
            cpe_name = ((product_blob.get("cpe") or {}).get("cpeName") or "").strip()
            if not cpe_name or cpe_name in seen:
                continue

            parts = cpe_name.split(":")
            # cpe:2.3:a:vendor:product:version:...
            if len(parts) < 6 or parts[2] != "a":
                continue

            vendor = parts[3].lower()
            product = parts[4].lower()
            cpe_ver = parts[5].lower()
            ver = version.lower()

            # Ищем релевантность по имени ПО
            name_match = False
            if normalized_sw and (normalized_sw in vendor or normalized_sw in product):
                name_match = True
            if not name_match and tokens:
                token_hits = sum(1 for t in tokens if t in vendor or t in product)
                name_match = token_hits > 0
            if not name_match:
                continue

            # Ищем релевантность по версии
            score = 0
            if cpe_ver == ver:
                score += 6
            elif cpe_ver.startswith(ver) or ver.startswith(cpe_ver):
                score += 4
            else:
                continue

            if product == normalized_sw:
                score += 3
            elif normalized_sw and normalized_sw in product:
                score += 2

            if normalized_sw and normalized_sw in vendor:
                score += 1

            seen.add(cpe_name)
            candidates.append((score, cpe_name))

        candidates.sort(key=lambda x: x[0], reverse=True)
        return [name for _, name in candidates[: max(1, max_candidates)]]

    def _discover_vendor_candidates(self, software: str, max_items: int = 120) -> List[str]:
        data, _ = self._nvd_get(
            CPE_API,
            {
                "keywordSearch": software,
                "startIndex": "0",
                "resultsPerPage": str(max(20, max_items)),
            },
        )
        if not data:
            return []

        tokens = self._software_tokens(software)
        vendors = set()
        for product_blob in data.get("products", []):
            cpe_name = ((product_blob.get("cpe") or {}).get("cpeName") or "").strip()
            parts = cpe_name.split(":")
            if len(parts) < 6 or parts[2] != "a":
                continue
            vendor = parts[3].lower()
            product = parts[4].lower()
            if any(t in product or t in vendor for t in tokens):
                vendors.add(vendor)
        return sorted(vendors)

    def _cve_items_from_payload(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for entry in payload.get("vulnerabilities", []):
            cve = entry.get("cve", {})
            metrics = cve.get("metrics", {})
            items.append(
                {
                    "id": cve.get("id"),
                    "published": cve.get("published"),
                    "lastModified": cve.get("lastModified"),
                    "cvss": self._extract_cvss(metrics),
                    "cwe": self._extract_cwes(cve),
                    "description": self._description_ru_en(cve),
                    "source": "NVD",
                }
            )
        return items

    def search(self, software: str, version: str, max_items: int = 10) -> Dict[str, Any]:
        sw = (software or "").strip()
        ver = (version or "").strip()
        if not sw or not ver:
            return {"query": {"software": sw, "version": ver}, "total": 0, "items": []}
        report: Dict[str, Any] = {
            "query": {"software": sw, "version": ver},
            "total": 0,
            "items": [],
            "matched_cpes": [],
            "search_strategy": "",
            "warnings": [],
        }

        all_items_by_id: Dict[str, Dict[str, Any]] = {}
        cpe_candidates = self._find_cpe_candidates(sw, ver, max_candidates=8)
        report["matched_cpes"] = cpe_candidates

        # Стратегия 1: точный поиск CVE по cpeName
        for cpe_name in cpe_candidates:
            payload, err = self._nvd_get(
                NVD_API,
                {
                    "cpeName": cpe_name,
                    "startIndex": "0",
                    "resultsPerPage": str(max(20, max_items)),
                },
            )
            if err:
                report["warnings"].append(f"{cpe_name}: {err}")
                continue
            for item in self._cve_items_from_payload(payload or {}):
                cve_id = item.get("id")
                if cve_id and cve_id not in all_items_by_id:
                    all_items_by_id[cve_id] = item

        # Стратегия 2 (fallback): keyword search
        if not all_items_by_id:
            # Стратегия 2a: синтетические CPE по алиасам продукта и найденным vendor.
            vendors_set = set(self._discover_vendor_candidates(sw, max_items=120))
            # Добавим vendors, уже встреченные в кандидатах CPE (они наиболее релевантны).
            for cpe_name in cpe_candidates:
                parts = cpe_name.split(":")
                if len(parts) > 4:
                    vendors_set.add(parts[3].lower())
            if self._normalize_name(sw) == "nginx":
                vendors_set.add("f5")
            vendors = sorted(vendors_set) or ["f5"]
            products = self._software_alias_products(sw)
            synthetic_cpes = []
            for vendor in vendors:
                for product in products:
                    synthetic_cpes.append(
                        f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"
                    )
            for cpe_name in synthetic_cpes:
                payload, err = self._nvd_get(
                    NVD_API,
                    {
                        "cpeName": cpe_name,
                        "startIndex": "0",
                        "resultsPerPage": str(max(20, max_items)),
                    },
                )
                if err:
                    report["warnings"].append(f"{cpe_name}: {err}")
                    continue
                for item in self._cve_items_from_payload(payload or {}):
                    cve_id = item.get("id")
                    if cve_id and cve_id not in all_items_by_id:
                        all_items_by_id[cve_id] = item
                if cpe_name not in report["matched_cpes"]:
                    report["matched_cpes"].append(cpe_name)

        # Стратегия 2b (fallback): keyword search
        if not all_items_by_id:
            payload, err = self._nvd_get(
                NVD_API,
                {
                    "keywordSearch": f"{sw} {ver}",
                    "startIndex": "0",
                    "resultsPerPage": str(max(20, max_items)),
                },
            )
            if err:
                report["warnings"].append(f"keywordSearch: {err}")
            else:
                for item in self._cve_items_from_payload(payload or {}):
                    cve_id = item.get("id")
                    if cve_id and cve_id not in all_items_by_id:
                        all_items_by_id[cve_id] = item
                report["search_strategy"] = "keywordSearch"
        else:
            report["search_strategy"] = "cpeName"

        items = list(all_items_by_id.values())
        items.sort(
            key=lambda x: (
                x.get("cvss") if isinstance(x.get("cvss"), (int, float)) else -1,
                x.get("published") or "",
            ),
            reverse=True,
        )
        items = items[: max(1, max_items)]

        report["total"] = len(items)
        report["items"] = items
        if report["warnings"] and not items:
            report["error"] = report["warnings"][-1]
        return report

    def run(
        self,
        software: str,
        version: str,
        json_only: bool = False,
        output_file: Optional[str] = None,
        max_items: int = 10,
    ) -> Dict[str, Any]:
        report = self.search(software=software, version=version, max_items=max_items)

        if not json_only:
            query = report.get("query", {})
            print(f"{Fore.CYAN}=== CVE Lookup ==={Style.RESET_ALL}")
            print(f"Software: {query.get('software', '')}")
            print(f"Version:  {query.get('version', '')}")
            if report.get("error"):
                print(f"{Fore.RED}Error: {report.get('error')}{Style.RESET_ALL}")
            elif report.get("total", 0) == 0:
                print(f"{Fore.YELLOW}CVE не найдены по запросу.{Style.RESET_ALL}")
            else:
                rows = []
                for item in report.get("items", []):
                    rows.append(
                        [
                            item.get("id"),
                            item.get("cvss"),
                            ", ".join(item.get("cwe") or []),
                            item.get("published"),
                        ]
                    )
                print(
                    tabulate(
                        rows,
                        headers=["CVE", "CVSS", "CWE", "Published"],
                        tablefmt="grid",
                    )
                )

        try:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        except Exception:
            pass

        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(report, f, ensure_ascii=False, indent=2)
                if not json_only:
                    print(f"[+] Report saved to {output_file}")
            except OSError as e:
                if not json_only:
                    print(f"[-] Error saving report: {e}")

        return report
