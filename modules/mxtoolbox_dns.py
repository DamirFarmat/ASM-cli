import os
import time
import json
from typing import List, Dict, Any, Optional, Tuple
import requests
from colorama import Fore, Style, init
from tabulate import tabulate
from pathlib import Path
from datetime import datetime
import re
import html as htmllib
from publicsuffix2 import PublicSuffixList
from .reporters import MXTHTMLReporter

init()

# Правильный API хост согласно документации/примеру
MXTOOLBOX_BASE = 'https://api.mxtoolbox.com/api/v1'
_psl = PublicSuffixList()


class MXToolboxDNS:
    def __init__(self) -> None:
        self.api_key = os.getenv('MXTOOLBOX_API_KEY')
        if not self.api_key:
            raise RuntimeError('Не найден ключ MXTOOLBOX_API_KEY в окружении. Укажите его в .env')
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/json',
            'Authorization': self.api_key,
        })
        self.reporter = MXTHTMLReporter()

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{MXTOOLBOX_BASE}{path}"
        resp = self.session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def lookup_dns(self, domain: str) -> Dict[str, Any]:
        # Используем эндпоинт из примера: /api/v1/Lookup/dns/?argument={domain}
        return self._get('/Lookup/dns/', params={'argument': domain})

    def lookup_mx(self, domain: str) -> Dict[str, Any]:
        return self._get('/Lookup/mx/', params={'argument': domain})

    def lookup_spf(self, domain: str) -> Dict[str, Any]:
        return self._get('/Lookup/spf/', params={'argument': domain})

    def _clean_html(self, text: Optional[str]) -> str:
        if not text:
            return ''
        txt = re.sub(r'<[^>]+>', ' ', text)
        txt = htmllib.unescape(txt)
        txt = re.sub(r'[\r\n\t]+', ' ', txt)
        txt = re.sub(r'\s{2,}', ' ', txt).strip()
        return txt

    def _collect_rows(self, data: Dict[str, Any], prefix: str = '') -> List[List[str]]:
        rows: List[List[str]] = []
        def add_items(items: Any, status_label: str):
            if isinstance(items, list):
                for it in items:
                    if isinstance(it, dict):
                        name = it.get('Name') or it.get('TestName') or '—'
                        info = self._clean_html(it.get('Info') or it.get('Description') or it.get('HelpText') or '')
                        addi = it.get('AdditionalInfo')
                        if isinstance(addi, list) and addi:
                            info = (info + ' ' + '; '.join(map(str, addi))).strip()
                        rows.append([status_label, (prefix + name).strip(), info, it.get('Url') or ''])
                    else:
                        rows.append([status_label, prefix + str(it), '', ''])
        add_items(data.get('Failed'), 'Failed')
        add_items(data.get('Warnings'), 'Warning')
        add_items(data.get('Passed'), 'Passed')
        # Timeouts и Errors больше не добавляем в основной вывод терминала
        return rows

    def _registrable(self, domain: str) -> str:
        try:
            return _psl.get_public_suffix(domain)
        except Exception:
            return domain

    def _dedup_rows(self, rows: List[List[str]]) -> List[List[str]]:
        """Удаляет дубли записей по ключу (status, normalized_name, normalized_info),
        где normalized_name — без префикса DNS:/MX:/SPF:. Сохраняем первый встретившийся."""
        seen: set[Tuple[str, str, str]] = set()
        result: List[List[str]] = []
        for status, name, info, url in rows:
            base_name = re.sub(r'^(DNS|MX|SPF):\s*', '', name, flags=re.IGNORECASE)
            key = (status.lower().strip(), base_name.lower().strip(), info.lower().strip())
            if key in seen:
                continue
            seen.add(key)
            result.append([status, name, info, url])
        return result

    def _status_class(self, status: str) -> str:
        s = (status or '').lower()
        if s in ('failed', 'error'):
            return 'failed'
        if s == 'warning':
            return 'warning'
        if s == 'passed':
            return 'passed'
        if s == 'timeout':
            return 'timeout'
        return 'unknown'

    def _build_domain_table_html(self, domain: str, data: Dict[str, Any]) -> str:
        rows = self._collect_rows(data)
        def row_html(r: List[str]) -> str:
            status, name, info, url = r
            css = self._status_class(status)
            info_html = htmllib.escape(info)
            name_html = htmllib.escape(name)
            more = f'<a href="{url}" target="_blank">More Info</a>' if url else ''
            return f'<tr class="{css}"><td class="status">{status}</td><td class="name">{name_html}</td><td class="info">{info_html} {more}</td></tr>'
        table_rows = '\n'.join(row_html(r) for r in rows) if rows else '<tr><td colspan="3">No items</td></tr>'
        return f"""
<table class=\"table\">
  <thead><tr><th>Status</th><th>Test</th><th>Info</th></tr></thead>
  <tbody>
    {table_rows}
  </tbody>
</table>
"""

    def _wrap_global_html(self, sections: List[Tuple[str, str]]) -> str:
        # sections: list of (domain, table_html)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        items_html = []
        for idx, (dom, tbl) in enumerate(sections):
            dom_e = htmllib.escape(dom)
            items_html.append(f"""
<div class=\"domain-section\" id=\"dom-{idx}\">
  <h3 class=\"domain-header\" onclick=\"this.parentElement.classList.toggle('open')\">{dom_e} <span class=\"toggle\">▼</span></h3>
  <div class=\"records\">{tbl}</div>
</div>
""")
        content = '\n'.join(items_html)
        return f"""
<!DOCTYPE html>
<html lang=\"ru\">
<head>
<meta charset=\"UTF-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
<title>MXToolbox DNS Report</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 20px; background:#f7f9fb; color:#1f2937; }}
.container {{ max-width: 1100px; margin: auto; background:#fff; border:1px solid #e5e7eb; border-radius:8px; box-shadow:0 4px 10px rgba(0,0,0,.04); }}
.header {{ padding: 18px 22px; border-bottom:1px solid #e5e7eb; display:flex; justify-content:space-between; align-items:center; }}
.header h1 {{ margin:0; font-size:20px; }}
.header .meta {{ color:#6b7280; font-size:13px; }}
.table {{ width:100%; border-collapse:collapse; }}
.table th, .table td {{ padding:12px 14px; border-bottom:1px solid #eef2f7; vertical-align:top; }}
.table th {{ background:#f8fafc; text-align:left; font-weight:600; color:#374151; }}
tr.failed {{ background:#fff1f2; }}
tr.warning {{ background:#fff7ed; }}
tr.passed {{ background:#f0fdf4; }}
tr.timeout {{ background:#f3f4f6; }}
.status {{ width:110px; font-weight:600; text-transform:capitalize; }}
.name {{ width:320px; }}
.info a {{ color:#2563eb; text-decoration:none; }}
.info a:hover {{ text-decoration:underline; }}
.domain-section {{ border-top:1px solid #e5e7eb; }}
.domain-header {{ margin:0; padding:14px 18px; cursor:pointer; user-select:none; }}
.domain-header .toggle {{ font-size:12px; color:#6b7280; margin-left:6px; }}
.records {{ display:none; padding: 0 18px 18px; }}
.domain-section.open .records {{ display:block; }}
.footer {{ padding: 12px 14px; color:#6b7280; font-size:12px; border-top:1px solid #e5e7eb; }}
</style>
</head>
<body>
<div class=\"container\">
  <div class=\"header\"><h1>DNS Report</h1><div class=\"meta\">Generated: {timestamp}</div></div>
  {content}
  <div class=\"footer\">Source: MXToolbox API</div>
</div>
</body>
</html>
"""

    def run(self, domains: List[str], save_json: bool = False, save_html: bool = False, json_output: bool = False) -> None:
        # Больше не схлопываем до eTLD+1: проверяем все переданные домены как есть (с уникализацией порядка)
        seen = set()
        target_domains: List[str] = []
        for d in domains:
            if d not in seen:
                seen.add(d)
                target_domains.append(d)

        json_paths: List[Tuple[str, str]] = []
        html_sections: List[Tuple[str, str]] = []
        reports_dir = Path('reports')
        if save_json or save_html:
            reports_dir.mkdir(parents=True, exist_ok=True)

        for d in target_domains:
            try:
                data_dns = self.lookup_dns(d)
                data_mx = self.lookup_mx(d)
                data_spf = self.lookup_spf(d)
                rows_dns = self._collect_rows(data_dns, prefix='DNS: ')
                rows_mx = self._collect_rows(data_mx, prefix='MX: ')
                rows_spf = self._collect_rows(data_spf, prefix='SPF: ')
                rows = self._dedup_rows(rows_dns + rows_mx + rows_spf)

                # Сортировка по критичности для консоли
                def priority(s: str) -> int:
                    s = (s or '').lower()
                    if s in ('failed', 'error'):
                        return 0
                    if s == 'warning':
                        return 1
                    if s == 'passed':
                        return 2
                    if s == 'timeout':
                        return 3
                    return 4
                rows.sort(key=lambda r: (priority(r[0]), r[1]))

                print(f"\n{Fore.CYAN}=== {d} ==={Style.RESET_ALL}")
                if rows:
                    print(tabulate([[r[0], r[1], r[2]] for r in rows], headers=['Статус', 'Тест', 'Описание'], tablefmt='grid'))
                else:
                    print("Нет элементов Failed/Warning/Passed")

                if save_json:
                    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                    p_dns = reports_dir / f"mxtoolbox_dns_{d.replace('/', '_')}_{ts}.json"
                    p_dns.write_text(json.dumps(data_dns, ensure_ascii=False, indent=2), encoding='utf-8')
                    json_paths.append((d + ' (dns)', str(p_dns.resolve())))
                    p_mx = reports_dir / f"mxtoolbox_mx_{d.replace('/', '_')}_{ts}.json"
                    p_mx.write_text(json.dumps(data_mx, ensure_ascii=False, indent=2), encoding='utf-8')
                    json_paths.append((d + ' (mx)', str(p_mx.resolve())))
                    p_spf = reports_dir / f"mxtoolbox_spf_{d.replace('/', '_')}_{ts}.json"
                    p_spf.write_text(json.dumps(data_spf, ensure_ascii=False, indent=2), encoding='utf-8')
                    json_paths.append((d + ' (spf)', str(p_spf.resolve())))

                if save_html:
                    html_sections.append((d, self.reporter.build_domain_table(rows)))
                time.sleep(0.2)
            except requests.HTTPError as e:
                print(f"{Fore.RED}[{d}] HTTP error: {e}{Style.RESET_ALL}")
                if e.response is not None:
                    try:
                        print(e.response.text)
                    except Exception:
                        pass
            except Exception as e:
                print(f"{Fore.RED}[{d}] Error: {e}{Style.RESET_ALL}")

        if save_html and html_sections:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            out = reports_dir / f"mxtoolbox_report_{ts}.html"
            out.write_text(self.reporter.wrap_global(html_sections), encoding='utf-8')
            print(f"HTML отчет: {out.resolve()}")
        if save_json and json_paths:
            for dom, p in json_paths:
                print(f"JSON сохранен [{dom}]: {p}")
