"""
Web Technology Analyzer

Использует WhatWeb для анализа веб-технологий доменов.
Требует установленный WhatWeb: https://github.com/urbanadventurer/WhatWeb
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from colorama import Fore, Style, init
from tabulate import tabulate

from utils.target_loader import TargetLoader
from modules.reporters import MXTHTMLReporter

init()


class WebAnalyzer:
    """
    Анализатор веб-технологий через WhatWeb.
    Формирует табличный консольный вывод и (опционально) общий HTML-отчет.
    """

    def __init__(self, whatweb_path: str = "whatweb") -> None:
        self.whatweb_path = whatweb_path
        self.target_loader = TargetLoader()
        self.reporter = MXTHTMLReporter()

    def _check_whatweb_installed(self) -> bool:
        """Проверяет, установлен ли WhatWeb"""
        try:
            result = subprocess.run(
                [self.whatweb_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False

    def _run_whatweb(self, domain: str) -> Optional[Dict[str, Any]]:
        """Запускает WhatWeb для домена и парсит результат"""
        try:
            # Формируем URL для проверки
            if not domain.startswith(('http://', 'https://')):
                url = f"http://{domain}"
            else:
                url = domain

            # Запускаем WhatWeb с JSON выводом
            cmd = [
                self.whatweb_path,
                "--no-errors",  # Игнорировать ошибки
                "--json",        # JSON формат вывода
                url
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # Увеличиваем таймаут для веб-запросов
            )

            if result.returncode != 0:
                print(f"{Fore.RED}[{domain}] WhatWeb error: {result.stderr}{Style.RESET_ALL}")
                return None

            # Парсим JSON вывод
            try:
                data = json.loads(result.stdout)
                return data
            except json.JSONDecodeError:
                # Fallback: парсим текстовый вывод
                return self._parse_text_output(result.stdout, domain)

        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[{domain}] WhatWeb timeout{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.RED}[{domain}] WhatWeb error: {e}{Style.RESET_ALL}")
            return None

    def _parse_text_output(self, output: str, domain: str) -> Dict[str, Any]:
        """Парсит текстовый вывод WhatWeb если JSON недоступен"""
        data = {
            "target": {"uri": domain},
            "plugins": {}
        }

        # Ищем основные паттерны в выводе
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Парсим строки вида: [200] Server[nginx/1.18.0], PoweredBy[WordPress]
            if '[' in line and ']' in line:
                parts = line.split(']', 1)
                if len(parts) == 2:
                    status_part = parts[0].strip('[')
                    info_part = parts[1].strip()

                    # Извлекаем статус
                    if status_part.isdigit():
                        data["target"]["status"] = int(status_part)

                    # Парсим информацию о технологиях
                    if info_part:
                        tech_matches = re.findall(r'(\w+)\[([^\]]*)\]', info_part)
                        for tech_name, tech_value in tech_matches:
                            if tech_name not in data["plugins"]:
                                data["plugins"][tech_name] = []
                            data["plugins"][tech_name].append(tech_value)

        return data

    def _extract_technologies(self, whatweb_data: Dict[str, Any]) -> List[Tuple[str, str, str]]:
        """Извлекает технологии из данных WhatWeb"""
        technologies = []
        
        if not whatweb_data or "plugins" not in whatweb_data:
            return technologies

        plugins = whatweb_data["plugins"]
        
        for plugin_name, plugin_data in plugins.items():
            if isinstance(plugin_data, list):
                for item in plugin_data:
                    if isinstance(item, dict):
                        # Структурированные данные
                        version = item.get("version", "")
                        name = item.get("name", "")
                        if version and name:
                            technologies.append((plugin_name, name, version))
                        elif name:
                            technologies.append((plugin_name, name, ""))
                        elif version:
                            technologies.append((plugin_name, plugin_name, version))
                    else:
                        # Простые строки
                        technologies.append((plugin_name, str(item), ""))
            elif isinstance(plugin_data, dict):
                # Одиночный словарь
                version = plugin_data.get("version", "")
                name = plugin_data.get("name", "")
                if version and name:
                    technologies.append((plugin_name, name, version))
                elif name:
                    technologies.append((plugin_name, name, ""))
                elif version:
                    technologies.append((plugin_name, plugin_name, version))
            else:
                # Простые значения
                technologies.append((plugin_name, str(plugin_data), ""))

        return technologies

    def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Анализирует веб-технологии домена"""
        analysis = {
            'domain': domain,
            'technologies': [],
            'status': None,
            'server_info': {},
            'frameworks': [],
            'cms': [],
            'languages': [],
            'databases': [],
            'web_servers': [],
            'other_tech': []
        }

        # Запускаем WhatWeb
        whatweb_data = self._run_whatweb(domain)
        if not whatweb_data:
            return analysis

        # Извлекаем статус
        if "target" in whatweb_data and "status" in whatweb_data["target"]:
            analysis['status'] = whatweb_data["target"]["status"]

        # Извлекаем технологии
        technologies = self._extract_technologies(whatweb_data)
        analysis['technologies'] = technologies

        # Категоризируем технологии
        for tech_type, tech_name, tech_version in technologies:
            tech_info = f"{tech_name}{' ' + tech_version if tech_version else ''}"
            
            # Веб-серверы
            if tech_type.lower() in ['server', 'httpserver', 'apache', 'nginx', 'iis']:
                analysis['web_servers'].append(tech_info)
            
            # CMS
            elif tech_type.lower() in ['wordpress', 'joomla', 'drupal', 'magento', 'opencart']:
                analysis['cms'].append(tech_info)
            
            # Фреймворки
            elif tech_type.lower() in ['framework', 'laravel', 'django', 'rails', 'spring', 'asp.net']:
                analysis['frameworks'].append(tech_info)
            
            # Языки программирования
            elif tech_type.lower() in ['php', 'python', 'ruby', 'java', 'asp', 'dotnet']:
                analysis['languages'].append(tech_info)
            
            # Базы данных
            elif tech_type.lower() in ['mysql', 'postgresql', 'mongodb', 'redis', 'sqlite']:
                analysis['databases'].append(tech_info)
            
            # Остальные технологии
            else:
                analysis['other_tech'].append(tech_info)

        return analysis

    def _display_domain_analysis(self, domain: str, analysis: Dict[str, Any]) -> None:
        """Отображает анализ для конкретного домена"""
        print(f"{Fore.GREEN}ДОМЕН: {domain}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'-' * (len(domain) + 8)}{Style.RESET_ALL}")

        # Статус
        if analysis['status']:
            status_color = Fore.GREEN if analysis['status'] == 200 else Fore.YELLOW
            print(f"\n{Fore.BLUE}Статус:{Style.RESET_ALL} {status_color}{analysis['status']}{Style.RESET_ALL}")

        # Веб-серверы
        if analysis['web_servers']:
            print(f"\n{Fore.BLUE}Веб-серверы:{Style.RESET_ALL}")
            for server in analysis['web_servers']:
                print(f"  🖥️  {server}")

        # CMS
        if analysis['cms']:
            print(f"\n{Fore.BLUE}CMS:{Style.RESET_ALL}")
            for cms in analysis['cms']:
                print(f"  📝 {cms}")

        # Фреймворки
        if analysis['frameworks']:
            print(f"\n{Fore.BLUE}Фреймворки:{Style.RESET_ALL}")
            for framework in analysis['frameworks']:
                print(f"  ⚙️  {framework}")

        # Языки программирования
        if analysis['languages']:
            print(f"\n{Fore.BLUE}Языки программирования:{Style.RESET_ALL}")
            for lang in analysis['languages']:
                print(f"  💻 {lang}")

        # Базы данных
        if analysis['databases']:
            print(f"\n{Fore.BLUE}Базы данных:{Style.RESET_ALL}")
            for db in analysis['databases']:
                print(f"  🗄️  {db}")

        # Остальные технологии
        if analysis['other_tech']:
            print(f"\n{Fore.BLUE}Другие технологии:{Style.RESET_ALL}")
            for tech in analysis['other_tech']:
                print(f"  🔧 {tech}")

        # Общая таблица технологий
        if analysis['technologies']:
            print(f"\n{Fore.BLUE}Все обнаруженные технологии:{Style.RESET_ALL}")
            tech_data = []
            for tech_type, tech_name, tech_version in analysis['technologies']:
                tech_data.append([tech_type, tech_name, tech_version or 'N/A'])
            print(tabulate(tech_data, headers=['Тип', 'Название', 'Версия'], tablefmt='grid'))

    def run(self, domains: List[str], save_html: bool = False) -> None:
        """Запускает анализ веб-технологий для списка доменов"""
        # Проверяем установку WhatWeb
        if not self._check_whatweb_installed():
            print(f"{Fore.RED}ОШИБКА: WhatWeb не установлен или недоступен{Style.RESET_ALL}")
            print(f"Установите WhatWeb: https://github.com/urbanadventurer/WhatWeb")
            print(f"Или укажите путь к исполняемому файлу в конструкторе класса")
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
        print(f"Используется WhatWeb: {self.whatweb_path}")

        html_sections: List[Tuple[str, str]] = []
        all_results: Dict[str, Any] = {}

        for d in target_domains:
            print(f"\n{Fore.CYAN}Анализирую: {d}{Style.RESET_ALL}")
            
            analysis = self._analyze_domain(d)
            all_results[d] = analysis
            
            self._display_domain_analysis(d, analysis)

            # Подготавливаем данные для HTML отчета
            if save_html:
                tech_rows = []
                for tech_type, tech_name, tech_version in analysis['technologies']:
                    status = 'Passed'  # Все найденные технологии считаются успешными
                    tech_info = f"{tech_name}{' ' + tech_version if tech_version else ''}"
                    tech_rows.append([status, f"Tech: {tech_type}", tech_info, ""])
                
                if tech_rows:
                    html_sections.append((d, self.reporter.build_domain_table(tech_rows)))
                else:
                    # Если технологий не найдено
                    no_tech_row = [['Warning', 'Web Technologies', 'No technologies detected', '']]
                    html_sections.append((d, self.reporter.build_domain_table(no_tech_row)))

        # Сохраняем HTML отчет
        if save_html and html_sections:
            from datetime import datetime
            from pathlib import Path
            reports_dir = Path('reports')
            reports_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            out = reports_dir / f"web_analyzer_report_{ts}.html"
            html = self.reporter.wrap_global(html_sections)
            out.write_text(html, encoding='utf-8')
            print(f"\n{Fore.GREEN}HTML отчет: {out.resolve()}{Style.RESET_ALL}")

        # Сохраняем JSON отчет
        if all_results:
            json_path = reports_dir / f"web_analyzer_report_{ts}.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(all_results, f, ensure_ascii=False, indent=2)
            print(f"{Fore.GREEN}JSON отчет: {json_path.resolve()}{Style.RESET_ALL}")
