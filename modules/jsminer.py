#!/usr/bin/env python3
import asyncio
import json
import re
from typing import List, Dict, Any, Set
from urllib.parse import urljoin
import httpx
from bs4 import BeautifulSoup
from modules.reporters import JSMinerReporter
import json

class JSMiner:
    """
    Модуль для обнаружения секретов в JavaScript-файлах на веб-сайтах.
    """

    def __init__(self, threads: int = 10, no_sourcemaps: bool = False, verbose: bool = False):
        """
        Инициализация JSMiner.

        Args:
            threads (int): Количество одновременных потоков.
            no_sourcemaps (bool): Отключить ли поиск sourcemaps.
            verbose (bool): Включить ли подробный вывод.
        """
        self.threads = threads
        self.no_sourcemaps = no_sourcemaps
        self.verbose = verbose
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.rules = self._load_rules()
        self.reporter = JSMinerReporter()
        self.semaphore = asyncio.Semaphore(threads)

    async def run(self, targets: List[str], output_file: str = None, json_only: bool = False):
        """
        Основной метод для запуска сканирования.

        Args:
            targets (List[str]): Список URL-адресов для анализа.
            output_file (str, optional): Путь для сохранения JSON отчета.
            json_only (bool): Выводить ли только JSON в консоль.
        """
        if self.verbose:
            print(f"[+] JSMiner запущен с {self.threads} потоками для {len(targets)} целей.")

        # Асинхронный клиент для HTTP-запросов
        async with httpx.AsyncClient(http2=True, verify=False, headers={'User-Agent': self.user_agent}, timeout=15) as client:
            # Создаем задачи для каждой цели
            tasks = [self._fetch_and_parse_page(client, target) for target in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            all_js_files = set()
            for res in results:
                if isinstance(res, set):
                    all_js_files.update(res)
                elif self.verbose:
                    print(f"[!] Ошибка при обработке цели: {res}")
            
            if self.verbose:
                print(f"[+] Найдено {len(all_js_files)} уникальных JS-файлов для анализа.")

            # Этап 2: Загрузка содержимого всех JS-файлов
            js_content_tasks = [self._fetch_js_content(client, js_url) for js_url in all_js_files]
            js_results = await asyncio.gather(*js_content_tasks, return_exceptions=True)

            # Этап 3: Сканирование содержимого
            findings = []
            scan_tasks = []
            for res in js_results:
                if res and not isinstance(res, Exception):
                    js_url, content = res
                    scan_tasks.append(self._scan_js_content(js_url, content))
            
            scan_results = await asyncio.gather(*scan_tasks)
            for result_list in scan_results:
                findings.extend(result_list)

        # Этап 4: Вывод результатов
        if json_only:
            self.reporter.to_json_console(findings)
        else:
            self.reporter.to_console(findings)

        if output_file:
            self.reporter.to_json_file(findings, output_file)

        return findings

    async def _fetch_and_parse_page(self, client: httpx.AsyncClient, url: str) -> Set[str]:
        """
        Загружает страницу и извлекает из нее все ссылки на JS-файлы.
        """
        async with self.semaphore:
            if self.verbose:
                print(f"[*] Сканируем {url}...")
            
            js_urls = set()
            try:
                response = await client.get(url)
                response.raise_for_status() # Проверяем на ошибки 4xx/5xx

                content_type = response.headers.get('content-type', '').lower()

                # Если это уже JS-файл, просто добавляем его и выходим
                if 'javascript' in content_type or 'application/x-javascript' in content_type:
                    js_urls.add(url)
                    return js_urls

                # Если это HTML, парсим его
                soup = BeautifulSoup(response.text, 'html.parser')

                for script_tag in soup.find_all('script'):
                    if script_tag.get('src'):
                        src = script_tag.get('src')
                        # Собираем абсолютный URL
                        abs_url = urljoin(url, src)
                        js_urls.add(abs_url)
                    else:
                        # TODO: Обработка inline-скриптов
                        pass
                
                return js_urls

            except httpx.RequestError as e:
                if self.verbose:
                    print(f"[!] Не удалось подключиться к {url}: {e}")
                return set()
            except Exception as e:
                if self.verbose:
                    print(f"[!] Неизвестная ошибка при обработке {url}: {e}")
                return set()

    async def _fetch_js_content(self, client: httpx.AsyncClient, js_url: str) -> tuple[str, str] | None:
        """
        Загружает содержимое JS-файла.
        """
        async with self.semaphore:
            try:
                response = await client.get(js_url)
                response.raise_for_status()
                return js_url, response.text
            except httpx.RequestError as e:
                if self.verbose:
                    print(f"[!] Не удалось загрузить {js_url}: {e}")
                return None
            except Exception as e:
                if self.verbose:
                    print(f"[!] Неизвестная ошибка при загрузке {js_url}: {e}")
                return None

    async def _scan_js_content(self, js_url: str, content: str) -> List[Dict[str, Any]]:
        """
        Сканирует содержимое JS-файла на наличие секретов.
        """
        findings = []
        lines = content.splitlines()

        for rule in self.rules:
            try:
                # Компилируем регулярное выражение для производительности
                compiled_regex = re.compile(rule['regex'])
                
                for i, line in enumerate(lines):
                    # Ищем все совпадения в строке
                    for match in compiled_regex.finditer(line):
                        findings.append({
                            "source_js": js_url,
                            "finding_type": rule['name'],
                            "secret": match.group(0),
                            "context": line,
                            "line_number": i + 1,
                            "confidence": "Medium" # Пока что ставим среднюю
                        })
            except re.error as e:
                if self.verbose:
                    print(f"[!] Ошибка в регулярном выражении для правила '{rule['name']}': {e}")
                continue
        
        return findings

    def _load_rules(self) -> List[Dict[str, str]]:
        """
        Загружает правила (регулярные выражения) из файла.
        """
        try:
            with open('rules.json', 'r', encoding='utf-8') as f:
                rules = json.load(f)
            if self.verbose:
                print(f"[+] Загружено {len(rules)} правил из rules.json")
            return rules
        except FileNotFoundError:
            print("[!] Файл с правилами 'rules.json' не найден. Сканирование будет пропущено.")
            return []
        except json.JSONDecodeError:
            print("[!] Ошибка декодирования 'rules.json'. Проверьте синтаксис файла.")
            return []