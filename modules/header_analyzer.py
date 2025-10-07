"""
HTTP Security Header Analyzer

Проверяет наличие и качество настроек ключевых HTTP security-заголовков.
Анализируются URL по схемам http:// и https:// с автоследованием редиректов.

Проверяются заголовки и рекомендации (основа: OWASP ASVS/cheatsheets, Mozilla Observatory):
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Embedder-Policy
- Cross-Origin-Resource-Policy
- X-XSS-Protection (исторический)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import re

import requests
from colorama import Fore, Style, init
from tabulate import tabulate

from utils.target_loader import TargetLoader
from utils.url_resolver import resolve_browser_like_url
from modules.reporters import MXTHTMLReporter


init()


class HeaderAnalyzer:
    def __init__(self) -> None:
        self.target_loader = TargetLoader()
        self.reporter = MXTHTMLReporter()
        self._last_fetch_timed_out: bool = False

    def _fetch(self, url: string) -> Optional[requests.Response]:  # type: ignore[name-defined]
        self._last_fetch_timed_out = False
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                               'AppleWebKit/537.36 (KHTML, like Gecko) '
                               'Chrome/124.0 Safari/537.36'
            })
            # Separate connect/read timeouts to avoid hanging TCP/TLS handshakes
            resp = session.get(url, timeout=(10, 50), allow_redirects=True)
            return resp
        except requests.exceptions.Timeout:
            self._last_fetch_timed_out = True
            return None
        except requests.RequestException:
            return None

    def _classify(self, ok: bool, warn: bool, message: str) -> Dict[str, Any]:
        if ok:
            return {'status': 'passed', 'message': message}
        if warn:
            return {'status': 'warning', 'message': message}
        return {'status': 'missing', 'message': message}

    def _check_hsts(self, headers: Dict[str, str], is_https: bool) -> Dict[str, Any]:
        hsts = headers.get('strict-transport-security') or headers.get('Strict-Transport-Security')
        if not is_https:
            return self._classify(False, True, 'HSTS применим только к HTTPS')
        if not hsts:
            return self._classify(False, False, 'Отсутствует Strict-Transport-Security')
        max_age_match = re.search(r'max-age\s*=\s*(\d+)', hsts, flags=re.I)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        include_sub = 'includesubdomains' in hsts.lower()
        preload = 'preload' in hsts.lower()
        ok = (max_age >= 15552000) and include_sub
        warn = (max_age >= 10800) and not ok  # >3 часа, но ниже рекомендуемого
        note = f"HSTS: max-age={max_age}{', includeSubDomains' if include_sub else ''}{', preload' if preload else ''}"
        return self._classify(ok, warn, note)

    def _check_csp(self, headers: Dict[str, str]) -> Dict[str, Any]:
        csp = headers.get('content-security-policy') or headers.get('Content-Security-Policy')
        if not csp:
            return self._classify(False, False, 'Отсутствует Content-Security-Policy')
        has_default = 'default-src' in csp.lower()
        unsafe = "'unsafe-inline'" in csp.lower() or "'unsafe-eval'" in csp.lower()
        star_wildcard = re.search(r'default-src[^;]*\*', csp, flags=re.I) is not None
        ok = has_default and not unsafe and not star_wildcard
        warn = has_default and (unsafe or star_wildcard)
        return self._classify(ok, warn, 'CSP присутствует' + (', содержит небезопасные директивы' if warn else ''))

    def _check_xcto(self, headers: Dict[str, str]) -> Dict[str, Any]:
        xcto = headers.get('x-content-type-options') or headers.get('X-Content-Type-Options')
        ok = xcto is not None and xcto.lower().strip() == 'nosniff'
        return self._classify(ok, False, f"X-Content-Type-Options: {xcto or 'нет'}")

    def _check_xfo(self, headers: Dict[str, str]) -> Dict[str, Any]:
        xfo = headers.get('x-frame-options') or headers.get('X-Frame-Options')
        if not xfo:
            return self._classify(False, False, 'Отсутствует X-Frame-Options (или используйте CSP frame-ancestors)')
        val = xfo.lower().strip()
        ok = val in ('deny', 'sameorigin')
        warn = not ok
        return self._classify(ok, warn, f"X-Frame-Options: {xfo}")

    def _check_referrer(self, headers: Dict[str, str]) -> Dict[str, Any]:
        ref = headers.get('referrer-policy') or headers.get('Referrer-Policy')
        good = { 'no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin' }
        if not ref:
            return self._classify(False, False, 'Отсутствует Referrer-Policy')
        ok = ref.lower().strip() in good
        warn = not ok
        return self._classify(ok, warn, f"Referrer-Policy: {ref}")

    def _check_permissions(self, headers: Dict[str, str]) -> Dict[str, Any]:
        pp = headers.get('permissions-policy') or headers.get('Permissions-Policy') or headers.get('Feature-Policy')
        if not pp:
            return self._classify(False, False, 'Отсутствует Permissions-Policy')
        overly_permissive = '*' in pp
        ok = not overly_permissive
        warn = overly_permissive
        return self._classify(ok, warn, 'Permissions-Policy присутствует' + (' (слишком широкая)' if warn else ''))

    def _check_coop(self, headers: Dict[str, str]) -> Dict[str, Any]:
        v = (headers.get('cross-origin-opener-policy') or headers.get('Cross-Origin-Opener-Policy') or '').lower().strip()
        ok = v in ('same-origin', 'same-origin-allow-popups')
        if not v:
            return self._classify(False, False, 'Отсутствует Cross-Origin-Opener-Policy')
        warn = not ok
        return self._classify(ok, warn, f"COOP: {v}")

    def _check_coep(self, headers: Dict[str, str]) -> Dict[str, Any]:
        v = (headers.get('cross-origin-embedder-policy') or headers.get('Cross-Origin-Embedder-Policy') or '').lower().strip()
        ok = v in ('require-corp',)
        if not v:
            return self._classify(False, True, 'Отсутствует Cross-Origin-Embedder-Policy')
        warn = not ok
        return self._classify(ok, warn, f"COEP: {v}")

    def _check_corp(self, headers: Dict[str, str]) -> Dict[str, Any]:
        v = (headers.get('cross-origin-resource-policy') or headers.get('Cross-Origin-Resource-Policy') or '').lower().strip()
        ok = v in ('same-origin', 'same-site')
        if not v:
            return self._classify(False, True, 'Отсутствует Cross-Origin-Resource-Policy')
        warn = not ok
        return self._classify(ok, warn, f"CORP: {v}")

    def _check_xss(self, headers: Dict[str, str]) -> Dict[str, Any]:
        v = headers.get('x-xss-protection') or headers.get('X-XSS-Protection')
        if not v:
            return self._classify(True, False, 'Отсутствует X-XSS-Protection (современно: CSP)')
        return self._classify(True, False, f"X-XSS-Protection: {v}")

    def _evaluate_headers(self, headers: Dict[str, str], is_https: bool) -> List[Dict[str, Any]]:
        # Нормализуем регистры ключей
        norm = {k.lower(): v for k, v in headers.items()}
        checks = [
            ('Strict-Transport-Security', self._check_hsts(norm, is_https)),
            ('Content-Security-Policy', self._check_csp(norm)),
            ('X-Content-Type-Options', self._check_xcto(norm)),
            ('X-Frame-Options', self._check_xfo(norm)),
            ('Referrer-Policy', self._check_referrer(norm)),
            ('Permissions-Policy', self._check_permissions(norm)),
            ('Cross-Origin-Opener-Policy', self._check_coop(norm)),
            ('Cross-Origin-Embedder-Policy', self._check_coep(norm)),
            ('Cross-Origin-Resource-Policy', self._check_corp(norm)),
            ('X-XSS-Protection', self._check_xss(norm)),
        ]
        results: List[Dict[str, Any]] = []
        for name, verdict in checks:
            results.append({'header': name, **verdict})
        return results

    def _analyze_url(self, url: str) -> Dict[str, Any]:
        resp = self._fetch(url)
        if not resp:
            if self._last_fetch_timed_out:
                return {'url': url, 'ok': False, 'error': 'timeout', 'note': '(timeout in asm)'}
            return {'url': url, 'ok': False, 'error': 'request_failed'}
        is_https = url.lower().startswith('https://') or resp.url.lower().startswith('https://')
        results = self._evaluate_headers(resp.headers or {}, is_https=is_https)
        return {
            'url': url,
            'final_url': resp.url,
            'status': getattr(resp, 'status_code', None),
            'headers': dict(resp.headers or {}),
            'findings': results,
        }

    def _display(self, domain: str, per_url: Dict[str, Any]) -> None:
        print(f"{Fore.GREEN}ДОМЕН: {domain}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'-' * (len(domain) + 8)}{Style.RESET_ALL}")
        for url, payload in per_url.items():
            label = f" {Fore.YELLOW}(timeout in asm){Style.RESET_ALL}" if payload.get('error') == 'timeout' else ''
            print(f"\n{Fore.BLUE}{url}{Style.RESET_ALL}{label}")
            if not payload or not payload.get('findings'):
                print('  Нет данных')
                continue
            rows = []
            for f in payload['findings']:
                rows.append([f.get('status'), f.get('header'), f.get('message')])
            print(tabulate(rows, headers=['Статус', 'Заголовок', 'Комментарий'], tablefmt='grid'))

    def run(self, domains: List[str], save_html: bool = False, json_only: bool = False) -> Dict[str, Any]:
        # Отбираем только домены
        seen: set = set()
        target_domains: List[str] = []
        for d in domains:
            if d in seen:
                continue
            if self.target_loader._is_valid_domain(d) and not self.target_loader._is_valid_ip(d):
                target_domains.append(d)
                seen.add(d)

        if not target_domains:
            if not json_only:
                print(f"{Fore.YELLOW}Во входном списке нет валидных доменов для --headers{Style.RESET_ALL}")
            return {}

        if not json_only:
            print(f"Найдено доменов для проверки заголовков: {len(target_domains)}")

        all_results: Dict[str, Any] = {}
        html_sections: List[Tuple[str, str]] = []

        for d in target_domains:
            if not json_only:
                print(f"\n{Fore.CYAN}Проверяю: {d}{Style.RESET_ALL}")

            # Resolve a single browser-like URL and analyze only it
            resolved_url = resolve_browser_like_url(d, timeout_s=20)
            per_url: Dict[str, Any] = {resolved_url: self._analyze_url(resolved_url)}

            all_results[d] = {
                'domain': d,
                'by_scheme': per_url,
            }

            if not json_only:
                self._display(d, per_url)

            if save_html:
                # Аггрегированная таблица по домену без дублей между http/https
                seen: set = set()
                findings: List[Dict[str, Any]] = []
                for url, payload in per_url.items():
                    for f in (payload.get('findings') or []):
                        key = (f.get('header'), f.get('status'), f.get('message'))
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(f)

                # Сортировка: missing -> warning -> passed
                order = {'missing': 0, 'warning': 1, 'passed': 2}
                findings.sort(key=lambda x: order.get(str(x.get('status')), 99))

                # Цветовая подсветка для статусов в HTML
                def colorize_status(status: str) -> str:
                    s = (status or '').lower()
                    if s == 'missing':
                        return '<span style="color:#d32f2f;font-weight:600">missing</span>'
                    if s == 'passed':
                        return '<span style="color:#2e7d32;font-weight:600">passed</span>'
                    # warning по умолчанию без цвета (или мягкий оранжевый)
                    return '<span style="color:#f57c00;font-weight:600">warning</span>' if s == 'warning' else status

                rows = []
                for f in findings:
                    rows.append([
                        colorize_status(str(f.get('status'))),
                        f.get('header'),
                        f.get('message'),
                    ])

                # Используем raw_html для первой колонки (цветной статус)
                table_html = self.reporter.build_plain_table(['Статус', 'Заголовок', 'Комментарий'], rows, raw_html_cols=[0])
                html_sections.append((d, table_html))

        if save_html and html_sections and not json_only:
            from datetime import datetime
            from pathlib import Path
            reports_dir = Path('reports')
            reports_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            out = reports_dir / f"header_security_report_{ts}.html"
            html = self.reporter.wrap_global(html_sections, title='HTTP Security Headers Report', footer='Sources: OWASP, Mozilla Observatory')
            out.write_text(html, encoding='utf-8')
            print(f"\n{Fore.GREEN}HTML отчет: {out.resolve()}{Style.RESET_ALL}")

        if all_results and not json_only:
            try:
                import json as _json
                print(_json.dumps(all_results, ensure_ascii=False, indent=2))
            except Exception:
                pass

        return all_results


