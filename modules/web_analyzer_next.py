"""
Web Technology Analyzer (Enhanced)

Улучшенная версия анализатора веб-технологий с расширенной поддержкой редиректов:
- Использует python-Wappalyzer с улучшенной обработкой редиректов
- Поддерживает отслеживание редиректов для анализа конечных URL
- Анализирует все URL в цепочке редиректов и объединяет результаты
- Предоставляет более детальную информацию о редиректах
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple
import warnings
import requests
import subprocess
import tempfile
import os
from urllib.parse import urljoin, urlparse

from colorama import Fore, Style, init
from tabulate import tabulate

from utils.target_loader import TargetLoader
from utils.url_resolver import resolve_browser_like_url
from modules.reporters import MXTHTMLReporter

# Wappalyzer Next доступность
_WAPPALYZER_NEXT_AVAILABLE = True
_WAPPALYZER_NEXT_ERROR = None

init()


class WebAnalyzerNext:
    """
    Анализатор веб-технологий через Wappalyzer Next.
    Использует более современную библиотеку с поддержкой браузерной эмуляции.
    """

    def __init__(self) -> None:
        self.target_loader = TargetLoader()
        self.reporter = MXTHTMLReporter()
        self.json_only: bool = False

    def _ensure_wappalyzer_next(self) -> bool:
        if not _WAPPALYZER_NEXT_AVAILABLE:
            if not self.json_only:
                print(f"{Fore.RED}ОШИБКА: Wappalyzer Next недоступен{Style.RESET_ALL}")
            return False
        
        # Проверяем, что команда wappalyzer доступна
        try:
            result = subprocess.run(['wappalyzer', '--help'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                if not self.json_only:
                    print(f"{Fore.RED}ОШИБКА: Команда wappalyzer недоступна{Style.RESET_ALL}")
                    print("Установите пакет: pip install wappalyzer")
                    print("Также убедитесь, что установлены Firefox и geckodriver")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            if not self.json_only:
                print(f"{Fore.RED}ОШИБКА: Не удалось запустить wappalyzer: {e}{Style.RESET_ALL}")
                print("Установите пакет: pip install wappalyzer")
            return False
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

    def _analyze_single_url_next(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Анализирует URL с помощью Wappalyzer Next через subprocess.
        
        Args:
            url: URL для анализа
            
        Returns:
            Результат анализа или None
        """
        try:
            # Создаем временный файл для JSON вывода
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                temp_path = temp_file.name
            
            try:
                # Запускаем wappalyzer через subprocess с жёстким таймаутом 60 сек
                proc = subprocess.Popen([
                    'wappalyzer',
                    '-i', url,
                    '-oJ', temp_path,
                    '--scan-type', 'full'
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                try:
                    stdout, stderr = proc.communicate(timeout=60)
                except subprocess.TimeoutExpired:
                    # Жёстко завершаем процесс при таймауте
                    try:
                        proc.kill()
                    finally:
                        try:
                            proc.communicate(timeout=5)
                        except Exception:
                            pass
                    # Маркируем таймаут на уровне вызова
                    setattr(self, '_last_scan_timed_out', True)
                    return None

                if proc.returncode != 0:
                    return None

                # Читаем результат из временного файла
                if os.path.exists(temp_path):
                    with open(temp_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    # Преобразуем результат в формат, совместимый с оригинальным WebAnalyzer
                    # Wappalyzer Next возвращает данные в формате: {url: {tech_name: {version, confidence, categories, groups}}}
                    if isinstance(data, dict):
                        formatted_result = {}
                        for url, technologies in data.items():
                            if isinstance(technologies, dict):
                                for tech_name, tech_info in technologies.items():
                                    if isinstance(tech_info, dict):
                                        formatted_result[tech_name] = {
                                            'categories': tech_info.get('categories', []),
                                            'versions': [tech_info.get('version')] if tech_info.get('version') else []
                                        }
                        return formatted_result
                
                return None
                
            finally:
                # Удаляем временный файл
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                    
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, Exception):
            return None

    def _merge_results(self, a: Dict[str, Dict[str, List[str]]], b: Dict[str, Dict[str, List[str]]]) -> Dict[str, Dict[str, List[str]]]:
        """
        Объединяет результаты анализа технологий.
        """
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

    def _analyze_domain_next(self, domain: str) -> Dict[str, Any]:
        analysis: Dict[str, Any] = {
            'domain': domain,
            'by_scheme': {},
            'redirects': {},  # url -> [redirect_chain]
            'detected': {},  # name -> {categories:[], versions:[]}
        }

        if not self._ensure_wappalyzer_next():
            return analysis

        # Resolve a single browser-like URL and analyze only it
        resolved_url = resolve_browser_like_url(domain, timeout_s=10)

        # Получаем цепочку редиректов для отображения
        redirect_chain = self._follow_redirects(resolved_url)
        analysis['redirects'][resolved_url] = redirect_chain

        # Анализируем URL с Wappalyzer Next
        per_url: Dict[str, Dict[str, Dict[str, List[str]]]] = {}
        # Сбрасываем флаг таймаута перед запуском
        setattr(self, '_last_scan_timed_out', False)
        res = self._analyze_single_url_next(resolved_url)
        if res:
            per_url[resolved_url] = res
        else:
            # Если был таймаут движка Wappalyzer Next – отразим в цепочке
            if getattr(self, '_last_scan_timed_out', False):
                (analysis['redirects'].setdefault(resolved_url, [])).append('timeout in asm')

        analysis['by_scheme'] = per_url

        # Слить по домену
        merged: Dict[str, Dict[str, List[str]]] = {}
        for res in per_url.values():
            merged = self._merge_results(merged, res)
        analysis['detected'] = merged
        return analysis

    def _display_domain_analysis(self, domain: str, analysis: Dict[str, Any]) -> None:
        """Отображает анализ Wappalyzer Next для конкретного домена"""
        print(f"{Fore.GREEN}ДОМЕН: {domain} (Wappalyzer Next){Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'-' * (len(domain) + 20)}{Style.RESET_ALL}")

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
        """Запускает анализ веб-технологий для списка доменов с помощью Wappalyzer Next.

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
        if not self._ensure_wappalyzer_next():
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
                print(f"{Fore.YELLOW}Во входном файле нет валидных доменов для --web-test{Style.RESET_ALL}")
            return {}

        if not json_only:
            print(f"Найдено доменов для анализа веб-технологий: {len(target_domains)}")
            print(f"Используется Wappalyzer Next")

        html_sections: List[Tuple[str, str]] = []
        all_results: Dict[str, Any] = {}

        for d in target_domains:
            if not json_only:
                print(f"\n{Fore.CYAN}Анализирую: {d}{Style.RESET_ALL}")
            
            analysis = self._analyze_domain_next(d)
            all_results[d] = analysis
            
            if not json_only:
                self._display_domain_analysis(d, analysis)

            # Подготавливаем данные для HTML отчета
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
                html_content.append("<h3>Обнаруженные технологии (Wappalyzer Next)</h3>")
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
            out = reports_dir / f"web_analyzer_next_report_{ts}.html"
            html = self.reporter.wrap_global(html_sections, title='Web Technologies Report (Wappalyzer Next)', footer='Source: Wappalyzer Next')
            out.write_text(html, encoding='utf-8')
            print(f"\n{Fore.GREEN}HTML отчет: {out.resolve()}{Style.RESET_ALL}")

        # Печатаем JSON результатов в консоль (не сохраняем на диск)
        if all_results and not json_only:
            try:
                print(json.dumps(all_results, ensure_ascii=False, indent=2))
            except Exception:
                pass

        return all_results
