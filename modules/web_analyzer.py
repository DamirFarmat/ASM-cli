"""
Web Technology Analyzer

Переписано для использования python-Wappalyzer:
- Библиотека: https://github.com/chorsley/python-Wappalyzer/tree/master
- Для каждого домена формируются URL http:// и https:// и анализируются оба.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from colorama import Fore, Style, init
from tabulate import tabulate

from utils.target_loader import TargetLoader
from modules.reporters import MXTHTMLReporter

# python-Wappalyzer
try:
    from Wappalyzer import Wappalyzer, WebPage
except Exception as e:  # pragma: no cover
    Wappalyzer = None  # type: ignore
    WebPage = None  # type: ignore
    _IMPORT_ERROR = e
else:
    _IMPORT_ERROR = None

init()


class WebAnalyzer:
    """
    Анализатор веб-технологий через python-Wappalyzer.
    Формирует табличный консольный вывод и (опционально) общий HTML-отчет.
    """

    def __init__(self) -> None:
        self.target_loader = TargetLoader()
        self.reporter = MXTHTMLReporter()
        self.wappalyzer: Optional[Wappalyzer] = None

    def _ensure_wappalyzer(self) -> bool:
        if _IMPORT_ERROR is not None or Wappalyzer is None or WebPage is None:
            print(f"{Fore.RED}ОШИБКА: Не удалось импортировать python-Wappalyzer: {_IMPORT_ERROR}{Style.RESET_ALL}")
            print("Установите пакет: pip install python-Wappalyzer")
            return False
        if self.wappalyzer is None:
            try:
                # С попыткой получить актуальные технологии
                self.wappalyzer = Wappalyzer.latest(update=True)
            except Exception:
                # Fallback без обновления с интернета
                self.wappalyzer = Wappalyzer.latest()
        return True

    def _analyze_single_url(self, url: str) -> Optional[Dict[str, Dict[str, List[str]]]]:
        try:
            webpage = WebPage.new_from_url(url)
            if self.wappalyzer is None:
                return None
            # {'Tech': {'categories': [...], 'versions': [...]}, ...}
            return self.wappalyzer.analyze_with_versions_and_categories(webpage)  # type: ignore
        except Exception:
            return None

    def _merge_results(self, a: Dict[str, Dict[str, List[str]]], b: Dict[str, Dict[str, List[str]]]) -> Dict[str, Dict[str, List[str]]]:
        merged: Dict[str, Dict[str, List[str]]] = {}
        keys = set(a.keys()) | set(b.keys())
        for k in keys:
            ca = a.get(k, {}).get('categories', [])
            va = a.get(k, {}).get('versions', [])
            cb = b.get(k, {}).get('categories', [])
            vb = b.get(k, {}).get('versions', [])
            merged[k] = {
                'categories': sorted({*ca, *cb}),
                'versions': sorted({*va, *vb})
            }
        return merged

    def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        analysis: Dict[str, Any] = {
            'domain': domain,
            'by_scheme': {},
            'detected': {},  # name -> {categories:[], versions:[]}
        }

        if not self._ensure_wappalyzer():
            return analysis

        urls = [f"http://{domain}", f"https://{domain}"]
        per_url: Dict[str, Dict[str, Dict[str, List[str]]]] = {}
        for url in urls:
            res = self._analyze_single_url(url)
            if res:
                per_url[url] = res
        analysis['by_scheme'] = per_url

        # Слить по домену
        merged: Dict[str, Dict[str, List[str]]] = {}
        for res in per_url.values():
            merged = self._merge_results(merged, res)
        analysis['detected'] = merged
        return analysis

    def _display_domain_analysis(self, domain: str, analysis: Dict[str, Any]) -> None:
        """Отображает анализ Wappalyzer для конкретного домена"""
        print(f"{Fore.GREEN}ДОМЕН: {domain}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'-' * (len(domain) + 8)}{Style.RESET_ALL}")

        # Вывод по схемам
        for url, res in analysis.get('by_scheme', {}).items():
            print(f"\n{Fore.BLUE}{url}:{Style.RESET_ALL}")
            rows = []
            for name, meta in sorted(res.items()):
                categories = ', '.join(meta.get('categories', [])) or '—'
                versions = ', '.join(meta.get('versions', [])) or '—'
                rows.append([name, categories, versions])
            if rows:
                print(tabulate(rows, headers=['Технология', 'Категории', 'Версии'], tablefmt='grid'))
            else:
                print('  Нет данных')

    def run(self, domains: List[str], save_html: bool = False) -> None:
        """Запускает анализ веб-технологий для списка доменов"""
        if not self._ensure_wappalyzer():
            return

        # Оставляем только домены, без IP
        seen: set = set()
        target_domains: List[str] = []
        for d in domains:
            if d in seen:
                continue
            if self.target_loader._is_valid_domain(d) and not self.target_loader._is_valid_ip(d):
                target_domains.append(d)
                seen.add(d)

        if not target_domains:
            print(f"{Fore.YELLOW}Во входном файле нет валидных доменов для --web{Style.RESET_ALL}")
            return

        print(f"Найдено доменов для анализа веб-технологий: {len(target_domains)}")
        print(f"Используется python-Wappalyzer")

        html_sections: List[Tuple[str, str]] = []
        all_results: Dict[str, Any] = {}

        for d in target_domains:
            print(f"\n{Fore.CYAN}Анализирую: {d}{Style.RESET_ALL}")
            
            analysis = self._analyze_domain(d)
            all_results[d] = analysis
            
            self._display_domain_analysis(d, analysis)

            # Подготавливаем данные для HTML отчета (та же таблица, что и в консоли)
            if save_html:
                rows_plain: List[List[str]] = []
                detected: Dict[str, Dict[str, List[str]]] = analysis.get('detected', {})
                for name, meta in sorted(detected.items()):
                    cats = ', '.join(meta.get('categories', [])) or '—'
                    vers = ', '.join(meta.get('versions', [])) or '—'
                    rows_plain.append([name, cats, vers])
                table_html = self.reporter.build_plain_table(['Технология', 'Категории', 'Версии'], rows_plain)
                html_sections.append((d, table_html))

        # Сохраняем HTML отчет
        if save_html and html_sections:
            from datetime import datetime
            from pathlib import Path
            reports_dir = Path('reports')
            reports_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            out = reports_dir / f"web_analyzer_report_{ts}.html"
            html = self.reporter.wrap_global(html_sections, title='Web Technologies Report', footer='Source: python-Wappalyzer')
            out.write_text(html, encoding='utf-8')
            print(f"\n{Fore.GREEN}HTML отчет: {out.resolve()}{Style.RESET_ALL}")

        # Сохраняем JSON отчет
        if all_results:
            # reports_dir и ts определены выше, но если save_html=False — создадим значения
            from datetime import datetime as _dt
            from pathlib import Path as _Path
            json_reports_dir = _Path('reports')
            json_reports_dir.mkdir(parents=True, exist_ok=True)
            ts_json = _dt.now().strftime('%Y%m%d_%H%M%S')
            json_path = json_reports_dir / f"web_analyzer_report_{ts_json}.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(all_results, f, ensure_ascii=False, indent=2)
            print(f"{Fore.GREEN}JSON отчет: {json_path.resolve()}{Style.RESET_ALL}")
