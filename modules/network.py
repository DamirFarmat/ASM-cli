"""
Модуль для сетевого анализа IP-адресов через InternetDB (бесплатный сервис)

Источник данных: https://internetdb.shodan.io/{ip}
"""

from __future__ import annotations

import json
import html as htmllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import ipaddress
import requests
from tabulate import tabulate
from colorama import Fore, Style, init


init()


class InternetDBNetwork:
    """
    Выполняет запросы к InternetDB по списку IP-адресов, формирует удобный вывод
    в консоли и (опционально) сохраняет JSON и общий HTML-отчет.
    """

    def __init__(self, max_workers: int = 5, timeout_s: int = 20) -> None:
        self.max_workers = max_workers
        self.timeout_s = timeout_s
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    # ----------------------- helpers -----------------------
    def _is_ip(self, target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def _normalize_host(self, ip: str, data: Dict[str, Any]) -> Dict[str, Any]:
        # InternetDB возвращает: ip, ports, vulns, hostnames, tags, cpes
        return {
            "ip": data.get("ip") or ip,
            "hostnames": data.get("hostnames") or [],
            "ports": data.get("ports") or [],
            "tags": data.get("tags") or [],
            "cpes": data.get("cpes") or [],
            "vulns": data.get("vulns") or [],
        }

    # ----------------------- HTML -----------------------
    def _build_simple_table_html(self, title: str, items: List[str]) -> str:
        if not items:
            return f'<div class="record-section"><h4>{htmllib.escape(title)}</h4><p class="no-records">Нет данных</p></div>'
        rows = [[htmllib.escape(str(x))] for x in items]
        table = tabulate(rows, headers=[title], tablefmt="html")
        return f'<div class="record-section"><h4>{htmllib.escape(title)}</h4>{table}</div>'

    def _wrap_global_html(self, items: List[Dict[str, Any]]) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sections: List[str] = []
        for idx, host in enumerate(items):
            details_rows = [
                ["IP", host.get("ip", "")],
                ["Ports", ", ".join(map(str, host.get("ports") or []))],
                ["Tags", ", ".join(host.get("tags") or [])],
            ]
            details = tabulate(details_rows, headers=["Field", "Value"], tablefmt="html")
            hostnames_html = self._build_simple_table_html("Hostnames", host.get("hostnames") or [])
            cpes_html = self._build_simple_table_html("CPEs", host.get("cpes") or [])
            vulns_html = self._build_simple_table_html("Vulns", host.get("vulns") or [])
            sections.append(
                f"""
<div class="domain-section" id="ip-{idx}">
  <h3 class="domain-header">{host.get('ip','')} <span class="toggle">▼</span></h3>
  <div class="records">{details}{hostnames_html}{cpes_html}{vulns_html}</div>
  <div class="footer-note">Источник данных: InternetDB</div>
</div>
"""
            )
        content = "\n".join(sections)
        return f"""
<!DOCTYPE html>
<html lang=\"ru\">
<head>
  <meta charset=\"UTF-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
  <title>InternetDB Network Report</title>
  <style>
    body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 20px; background:#f7f9fb; color:#1f2937; }}
    .container {{ max-width: 1100px; margin: auto; background:#fff; border:1px solid #e5e7eb; border-radius:8px; box-shadow:0 4px 10px rgba(0,0,0,.04); }}
    .header {{ padding: 18px 22px; border-bottom:1px solid #e5e7eb; display:flex; justify-content:space-between; align-items:center; }}
    .header h1 {{ margin:0; font-size:20px; }}
    .header .meta {{ color:#6b7280; font-size:13px; }}
    .domain-section {{ border-top:1px solid #e5e7eb; }}
    .domain-header {{ margin:0; padding:14px 18px; cursor:pointer; user-select:none; }}
    .domain-header .toggle {{ font-size:12px; color:#6b7280; margin-left:6px; }}
    .records {{ display:none; padding: 0 18px 18px; }}
    .domain-section.open .records {{ display:block; }}
    .footer-note {{ padding: 0 18px 18px; color:#6b7280; font-size:12px; }}
    table {{ width:100%; border-collapse:collapse; }}
    th, td {{ padding:10px 12px; border-bottom:1px solid #eef2f7; vertical-align:top; }}
    th {{ background:#f8fafc; text-align:left; font-weight:600; color:#374151; }}
  </style>
  <script>
  document.addEventListener('DOMContentLoaded', function() {{
    document.querySelectorAll('.domain-header').forEach(function(h) {{
      h.addEventListener('click', function() {{
        const s = h.closest('.domain-section');
        s.classList.toggle('open');
        const t = h.querySelector('.toggle');
        if (t) t.textContent = s.classList.contains('open') ? '▲' : '▼';
      }});
    }});
  }});
  </script>
  </head>
  <body>
    <div class=\"container\">
      <div class=\"header\"><h1>InternetDB Network Report</h1><div class=\"meta\">Generated: {timestamp}</div></div>
      {content}
    </div>
  </body>
</html>
"""

    # ----------------------- core -----------------------
    def _fetch_host(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            url = f"https://internetdb.shodan.io/{ip}"
            resp = self.session.get(url, timeout=self.timeout_s)
            if resp.status_code == 404:
                # Нет данных по IP
                return {
                    "ip": ip,
                    "hostnames": [],
                    "ports": [],
                    "tags": [],
                    "cpes": [],
                    "vulns": [],
                }
            resp.raise_for_status()
            data = resp.json()
            return self._normalize_host(ip, data)
        except requests.RequestException as e:
            print(f"{Fore.RED}[{ip}] HTTP error: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[{ip}] Error: {e}{Style.RESET_ALL}")
        return None

    def run(self, targets: List[str], save_json: bool = False, save_html: bool = False) -> None:
        # Оставляем только IP-адреса, сохраняя порядок и убирая дубли
        seen = set()
        ips: List[str] = []
        for t in targets:
            if t in seen:
                continue
            if self._is_ip(t):
                ips.append(t)
                seen.add(t)

        if not ips:
            print(f"{Fore.YELLOW}Во входном файле не найдено IP адресов{Style.RESET_ALL}")
            return

        print(f"Найдено IP для проверки через InternetDB: {len(ips)}")

        reports_dir = Path("reports")
        if save_json or save_html:
            reports_dir.mkdir(parents=True, exist_ok=True)

        normalized_hosts: List[Dict[str, Any]] = []
        json_paths: List[str] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {executor.submit(self._fetch_host, ip): ip for ip in ips}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    host = future.result()
                    if host is None:
                        continue
                    normalized_hosts.append(host)

                    # Console output
                    header = f"{Fore.CYAN}=== {ip} ==={Style.RESET_ALL}"
                    print(f"\n{header}")
                    summary_rows = [
                        ["Ports", ", ".join(map(str, host.get("ports") or []))],
                        ["Hostnames", ", ".join(host.get("hostnames") or [])],
                        ["Tags", ", ".join(host.get("tags") or [])],
                        ["CPEs", ", ".join(host.get("cpes") or [])],
                        ["Vulns", ", ".join(host.get("vulns") or [])],
                    ]
                    print(tabulate(summary_rows, headers=["Field", "Value"], tablefmt="grid"))

                    # Save JSON per IP if requested
                    if save_json:
                        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                        out = reports_dir / f"internetdb_{ip.replace(':','_')}_{ts}.json"
                        out.write_text(json.dumps(host, ensure_ascii=False, indent=2), encoding="utf-8")
                        json_paths.append(str(out.resolve()))
                except Exception as e:
                    print(f"{Fore.RED}[{ip}] Error: {e}{Style.RESET_ALL}")

        # Single combined HTML
        if save_html and normalized_hosts:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_html = reports_dir / f"internetdb_network_report_{ts}.html"
            out_html.write_text(self._wrap_global_html(normalized_hosts), encoding="utf-8")
            print(f"HTML отчет: {out_html.resolve()}")

        if save_json and json_paths:
            for p in json_paths:
                print(f"JSON сохранен: {p}")


