"""
Web Technology Analyzer

Переписано для использования python-Wappalyzer:
- Библиотека: https://github.com/chorsley/python-Wappalyzer/tree/master
- Для каждого домена формируются URL http:// и https:// и анализируются оба.
- Поддерживает отслеживание редиректов для анализа конечных URL.
- Анализирует все URL в цепочке редиректов и объединяет результаты.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple
import warnings
import requests
from urllib.parse import urljoin, urlparse

from colorama import Fore, Style, init
from tabulate import tabulate

from utils.target_loader import TargetLoader
from utils.url_resolver import resolve_browser_like_url
from modules.reporters import MXTHTMLReporter

# python-Wappalyzer (подавляем предупреждения при импорте)
try:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning)
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
        self.json_only: bool = False

    def _ensure_wappalyzer(self) -> bool:
        if _IMPORT_ERROR is not None or Wappalyzer is None or WebPage is None:
            if not self.json_only:
                print(f"{Fore.RED}ОШИБКА: Не удалось импортировать python-Wappalyzer: {_IMPORT_ERROR}{Style.RESET_ALL}")
                print("Установите пакет: pip install python-Wappalyzer")
            return False
        if self.wappalyzer is None:
            try:
                # С попыткой получить актуальные технологии
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", category=UserWarning)
                    self.wappalyzer = Wappalyzer.latest(update=True)
            except Exception:
                # Fallback без обновления с интернета
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", category=UserWarning)
                    self.wappalyzer = Wappalyzer.latest()
        return True

    def _follow_redirects(self, url: str, max_redirects: int = 10) -> List[str]:
        """
        Отслеживает редиректы для URL и возвращает список всех URL в цепочке редиректов.
        
        Args:
            url: Исходный URL для анализа
            max_redirects: Максимальное количество редиректов для отслеживания
            
        Returns:
            Список URL в порядке следования редиректов
        """
        redirect_chain = [url]
        current_url = url
        
        try:
            # Настройка сессии с таймаутами
            session = requests.Session()
            session.max_redirects = max_redirects
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
            
            # Выполняем запрос с отслеживанием редиректов, разделяя connect/read таймауты
            response = session.get(current_url, timeout=(10, 50), allow_redirects=True)
            
            # Получаем историю редиректов
            for resp in response.history:
                if resp.url not in redirect_chain:
                    redirect_chain.append(resp.url)
            
            # Добавляем финальный URL если он отличается
            if response.url not in redirect_chain:
                redirect_chain.append(response.url)
                
        except requests.exceptions.Timeout:
            # Помечаем таймаут в цепочке
            redirect_chain.append('timeout in asm')
        except requests.exceptions.RequestException:
            # В случае ошибки возвращаем только исходный URL
            pass
        except Exception:
            # В случае любой другой ошибки возвращаем только исходный URL
            pass
            
        return redirect_chain

    def _analyze_single_url(self, url: str, follow_redirects: bool = True) -> Optional[Dict[str, Dict[str, List[str]]]]:
        """
        Анализирует URL с возможностью отслеживания редиректов.
        
        Args:
            url: URL для анализа
            follow_redirects: Следить ли за редиректами
            
        Returns:
            Результат анализа Wappalyzer или None
        """
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=UserWarning)
                
                if follow_redirects:
                    # Получаем цепочку редиректов
                    redirect_chain = self._follow_redirects(url)
                    
                    # Анализируем каждый URL в цепочке редиректов
                    all_results = {}
                    for redirect_url in redirect_chain:
                        try:
                            webpage = WebPage.new_from_url(redirect_url)
                            if self.wappalyzer is None:
                                continue
                            result = self.wappalyzer.analyze_with_versions_and_categories(webpage)
                            if result:
                                # Объединяем результаты
                                all_results = self._merge_results(all_results, result)
                        except Exception:
                            # Пропускаем URL, который не удалось проанализировать
                            continue
                    
                    return all_results if all_results else None
                else:
                    # Оригинальная логика без редиректов
                    webpage = WebPage.new_from_url(url)
                    if self.wappalyzer is None:
                        return None
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
            'redirects': {},  # url -> [redirect_chain]
            'detected': {},  # name -> {categories:[], versions:[]}
        }

        if not self._ensure_wappalyzer():
            return analysis

        # Resolve a single browser-like URL and analyze only it
        resolved_url = resolve_browser_like_url(domain, timeout_s=10)

        # Получаем цепочку редиректов для отображения
        redirect_chain = self._follow_redirects(resolved_url)
        analysis['redirects'][resolved_url] = redirect_chain

        # Анализируем URL с редиректами
        per_url: Dict[str, Dict[str, Dict[str, List[str]]]] = {}
        res = self._analyze_single_url(resolved_url, follow_redirects=True)
        if res:
            per_url[resolved_url] = res

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

        # Вывод информации о редиректах
        redirects = analysis.get('redirects', {})
        if redirects:
            print(f"\n{Fore.YELLOW}РЕДИРЕКТЫ:{Style.RESET_ALL}")
            for url, chain in redirects.items():
                if len(chain) > 1:
                    print(f"  {Fore.CYAN}{url}{Style.RESET_ALL} → {Fore.MAGENTA}{chain[-1]}{Style.RESET_ALL}")
                    if len(chain) > 2:
                        print(f"    Цепочка: {' → '.join(chain)}")
                else:
                    print(f"  {Fore.CYAN}{url}{Style.RESET_ALL} (без редиректов)")

        # Вывод по схемам
        for url, res in analysis.get('by_scheme', {}).items():
            timeout_suffix = ''
            redirects = analysis.get('redirects', {}).get(url) or []
            if redirects and isinstance(redirects[-1], str) and 'timeout in asm' in redirects[-1]:
                timeout_suffix = f" {Fore.YELLOW}(timeout in asm){Style.RESET_ALL}"
            print(f"\n{Fore.BLUE}{url}:{Style.RESET_ALL}{timeout_suffix}")
            rows = []
            for name, meta in sorted(res.items()):
                categories = ', '.join(meta.get('categories', [])) or '—'
                versions = ', '.join(meta.get('versions', [])) or '—'
                rows.append([name, categories, versions])
            if rows:
                print(tabulate(rows, headers=['Технология', 'Категории', 'Версии'], tablefmt='grid'))
            else:
                print('  Нет данных')

    def run(self, domains: List[str], save_html: bool = False, json_only: bool = False) -> Dict[str, Any]:
        self.json_only = json_only
        """Запускает анализ веб-технологий для списка доменов и возвращает результаты.

        Возвращаемая структура:
        {
          domain: {
            "domain": str,
            "by_scheme": { url: { tech: {categories:[], versions:[]} } },
            "redirects": { url: [redirect_chain] },
            "detected": { tech: {categories:[], versions:[]} }
          }, ...
        }
        """
        if not self._ensure_wappalyzer():
            return {}

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
            if not json_only:
                print(f"{Fore.YELLOW}Во входном файле нет валидных доменов для --web{Style.RESET_ALL}")
            return {}

        if not json_only:
            print(f"Найдено доменов для анализа веб-технологий: {len(target_domains)}")
            print(f"Используется python-Wappalyzer")

        html_sections: List[Tuple[str, str]] = []
        all_results: Dict[str, Any] = {}

        for d in target_domains:
            if not json_only:
                print(f"\n{Fore.CYAN}Анализирую: {d}{Style.RESET_ALL}")
            
            analysis = self._analyze_domain(d)
            all_results[d] = analysis
            
            if not json_only:
                self._display_domain_analysis(d, analysis)

            # Подготавливаем данные для HTML отчета (та же таблица, что и в консоли)
            if save_html:
                # Добавляем информацию о редиректах в HTML отчет
                html_content = []
                
                # Информация о редиректах
                redirects = analysis.get('redirects', {})
                if redirects:
                    html_content.append("<h3>Редиректы</h3>")
                    redirect_rows = []
                    for url, chain in redirects.items():
                        if len(chain) > 1:
                            redirect_rows.append([url, chain[-1], ' → '.join(chain)])
                        else:
                            redirect_rows.append([url, "Без редиректов", "—"])
                    if redirect_rows:
                        redirect_table = self.reporter.build_plain_table(['Исходный URL', 'Финальный URL', 'Цепочка'], redirect_rows)
                        html_content.append(redirect_table)
                
                # Технологии
                html_content.append("<h3>Обнаруженные технологии</h3>")
                rows_plain: List[List[str]] = []
                detected: Dict[str, Dict[str, List[str]]] = analysis.get('detected', {})
                for name, meta in sorted(detected.items()):
                    cats = ', '.join(meta.get('categories', [])) or '—'
                    vers = ', '.join(meta.get('versions', [])) or '—'
                    rows_plain.append([name, cats, vers])
                
                if rows_plain:
                    table_html = self.reporter.build_plain_table(['Технология', 'Категории', 'Версии'], rows_plain)
                    html_content.append(table_html)
                else:
                    html_content.append("<p>Технологии не обнаружены</p>")
                
                html_sections.append((d, '\n'.join(html_content)))

        # Сохраняем HTML отчет
        if save_html and html_sections and not json_only:
            from datetime import datetime
            from pathlib import Path
            reports_dir = Path('reports')
            reports_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            out = reports_dir / f"web_analyzer_report_{ts}.html"
            html = self.reporter.wrap_global(html_sections, title='Web Technologies Report', footer='Source: python-Wappalyzer')
            out.write_text(html, encoding='utf-8')
            print(f"\n{Fore.GREEN}HTML отчет: {out.resolve()}{Style.RESET_ALL}")

        # Печатаем JSON результатов в консоль (не сохраняем на диск)
        if all_results and not json_only:
            try:
                print(json.dumps(all_results, ensure_ascii=False, indent=2))
            except Exception:
                pass

        return all_results
