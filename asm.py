#!/usr/bin/env python3
import argparse
from typing import List
from textwrap import dedent
from dotenv import load_dotenv, find_dotenv
from modules.dns_manual import DNSManual
from modules.web_analyzer import WebAnalyzer
from modules.web_analyzer_next import WebAnalyzerNext
from modules.network import InternetDBNetwork
from modules.vuln import VulnEnricher
from modules.cert import TLSCertAnalyzer
from utils.target_loader import TargetLoader
from modules.header_analyzer import HeaderAnalyzer
from modules.resolve import DNSResolver
from modules.jsminer import JSMiner
from modules.dnsdump_main import DNSDump
from modules.dork import YandexDork
from modules.cve import CVELookup
from colorama import init

def read_targets(file_path: str) -> List[str]:
    loader = TargetLoader()
    return loader.load_targets(file_path)

def main():
    init(autoreset=True)
    parser = argparse.ArgumentParser(
        prog='asm',
        usage=argparse.SUPPRESS,
        description=dedent(
            """\
             █████╗ ███████╗███╗   ███╗       ██████╗██╗     ██╗
            ██╔══██╗██╔════╝████╗ ████║      ██╔════╝██║     ██║
            ███████║███████╗██╔████╔██║█████╗██║     ██║     ██║
            ██╔══██║╚════██║██║╚██╔╝██║╚════╝██║     ██║     ██║
            ██║  ██║███████║██║ ╚═╝ ██║      ╚██████╗███████╗██║
            ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝       ╚═════╝╚══════╝╚═╝

            ASM CLI - модульный пассивный reconnaissance для доменов, IP и URL
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent(
            """\
            Примеры:
              asm --dns-manual -f targets.txt --html --json
              asm --web example.com --html
              asm --vuln -i reports/web_analyzer_report_*.json --csv-out reports/web_enriched.csv
              asm --jsminer -u https://example.com -o reports/jsminer.json --threads 20
              asm --dnsdump -f targets.txt -o reports/dnsdump.json
              asm --dork example.com --dork-pages 3 -o reports/dork.json
              asm --cve -s nginx -v 1.28.0 -o reports/cve_nginx_1.28.0.json

            Подсказки:
              - Для списков целей используйте -f/--file или позиционные targets.
              - Форматы файлов целей: .txt и .csv (по одному значению на строку).
              - --json-only печатает только JSON в stdout и отключает "шум" в консоли.
            """
        ),
    )

    mode_group = parser.add_argument_group('Режимы сканирования (выберите нужный)')
    mode_group.add_argument('--resolve', action='store_true', default=False, help='DNS resolve/reverse: домен -> IP и IP -> hostname')
    mode_group.add_argument('--dns-manual', action='store_true', default=False, help='DNS/Email health без внешних API')
    mode_group.add_argument('--dnsdump', action='store_true', default=False, help='Глубокая DNS-разведка: записи, subdomains, ASN, Geo, InternetDB')
    mode_group.add_argument('--network', action='store_true', default=False, help='Сетевая разведка IP через Shodan InternetDB')
    mode_group.add_argument('--headers', action='store_true', default=False, help='Анализ HTTP security headers (HSTS/CSP/XFO/и др.)')
    mode_group.add_argument('--web', action='store_true', default=False, help='Комбинированный web-режим: технологии + CVE/EOL (inline)')
    mode_group.add_argument('--web-version', action='store_true', default=False, help='Только web stack fingerprint (python-Wappalyzer)')
    mode_group.add_argument('--web-test', action='store_true', default=False, help='Только web stack fingerprint (Wappalyzer Next CLI)')
    mode_group.add_argument('--vuln', action='store_true', default=False, help='CVE/EOL enrichment по входному web JSON (-i/--input)')
    mode_group.add_argument('--cert', action='store_true', default=False, help='TLS/SSL аудит: протоколы + срок действия сертификата')
    mode_group.add_argument('--jsminer', action='store_true', default=False, help='Поиск секретов в JavaScript')
    mode_group.add_argument('--dork', action='store_true', default=False, help='Поиск поддоменов через Yandex dork (rhost:<domain>.*)')
    mode_group.add_argument('--cve', action='store_true', default=False, help='Поиск CVE по ПО и версии (NVD)')

    input_group = parser.add_argument_group('Входные данные')
    input_group.add_argument('-f', '--file', type=str, help='Файл целей (.txt/.csv)')
    input_group.add_argument('targets', nargs='*', help='Цели напрямую: example.com 8.8.8.8 https://site.tld')
    input_group.add_argument('-u', '--url', type=str, help='Один URL для --jsminer')
    input_group.add_argument('-i', '--input', type=str, help='Путь к web JSON для --vuln')
    input_group.add_argument('-s', '--software', type=str, help='Название ПО для --cve (например: nginx)')
    input_group.add_argument('-v', '--version', type=str, help='Версия ПО для --cve (например: 1.28.0)')

    output_group = parser.add_argument_group('Вывод и отчёты')
    output_group.add_argument('--json', action='store_true', default=False, help='Сохранить JSON-отчёты в reports/')
    output_group.add_argument('--html', action='store_true', default=False, help='Сохранить HTML-отчёт в reports/')
    output_group.add_argument('--json-only', action='store_true', default=False, help='Печатать только JSON в stdout')
    output_group.add_argument('-o', '--output', type=str, help='Явный путь выходного файла (для --jsminer, --dnsdump, --dork и --cve)')
    output_group.add_argument('--json-out', type=str, help='Путь enriched JSON для --vuln')
    output_group.add_argument('--csv-out', type=str, help='Путь CSV сводки для --vuln')

    tune_group = parser.add_argument_group('Тонкая настройка')
    tune_group.add_argument('-t', '--threads', type=int, default=10, help='Параллелизм для --jsminer (по умолчанию: 10)')
    tune_group.add_argument('--no-sourcemaps', action='store_true', help='(reserved) Отключить sourcemap-поиск в --jsminer')
    tune_group.add_argument('--cookie', type=str, help='Cookie header для запросов (--jsminer, --dork)')
    tune_group.add_argument('--nvd-api-key', type=str, help='Опциональный API-ключ NVD для --vuln / --web')
    tune_group.add_argument('--dork-pages', type=int, default=3, help='Количество страниц Yandex SERP для --dork (по умолчанию: 3)')
    tune_group.add_argument('-V', '--verbose', action='store_true', help='Подробный вывод')
    args = parser.parse_args()

    # Надежная загрузка .env
    env_path = find_dotenv(usecwd=True)
    if env_path:
        load_dotenv(env_path, override=True)


    if args.dns_manual:
        if args.file:
            all_targets = read_targets(args.file)
        else:
            all_targets = args.targets or []
        if not all_targets:
            parser.error('Для --dns-manual укажите -f targets.txt или перечислите домены напрямую')
        loader = TargetLoader()
        domains: List[str] = [
            t for t in all_targets
            if loader._is_valid_domain(t) and not loader._is_valid_ip(t)
        ]
        if not domains:
            print('Не найдено валидных доменов для --dns-manual')
            return
        client = DNSManual()
        client.run(domains, save_html=(False if args.json_only else args.html), save_json=(args.json and not args.json_only), json_only=args.json_only)
        return

    if args.web_version:
        if args.file:
            all_targets = read_targets(args.file)
        else:
            all_targets = args.targets or []
        if not all_targets:
            parser.error('Для --web-version укажите -f targets.txt или перечислите домены напрямую')
        loader = TargetLoader()
        domains: List[str] = [
            t for t in all_targets
            if loader._is_valid_domain(t) and not loader._is_valid_ip(t)
        ]
        if not domains:
            print('Не найдено валидных доменов для --web-version')
            return
        client = WebAnalyzer()
        results = client.run(domains, save_html=(False if args.json_only else args.html), json_only=args.json_only)
        if args.json_only:
            import json as _json
            print(_json.dumps(results or {}, ensure_ascii=False, indent=2))
        return

    if args.web_test:
        if args.file:
            all_targets = read_targets(args.file)
        else:
            all_targets = args.targets or []
        if not all_targets:
            parser.error('Для --web-test укажите -f targets.txt или перечислите домены напрямую')
        loader = TargetLoader()
        domains: List[str] = [
            t for t in all_targets
            if loader._is_valid_domain(t) and not loader._is_valid_ip(t)
        ]
        if not domains:
            print('Не найдено валидных доменов для --web-test')
            return
        client = WebAnalyzerNext()
        results = client.run(domains, save_html=(False if args.json_only else args.html), json_only=args.json_only)
        if args.json_only:
            import json as _json
            print(_json.dumps(results or {}, ensure_ascii=False, indent=2))
        return

    if args.network:
        if args.file:
            all_targets = read_targets(args.file)
        else:
            all_targets = args.targets or []
        if not all_targets:
            parser.error('Для --network укажите -f targets.txt или перечислите IP напрямую')
        loader = TargetLoader()
        # фильтруем только IP
        ips: List[str] = [t for t in all_targets if loader._is_valid_ip(t)]
        if not ips:
            print('Не найдено валидных IP для --network')
            return
        client = InternetDBNetwork()
        client.run(ips, save_json=(args.json and not args.json_only), save_html=(False if args.json_only else args.html), json_only=args.json_only)
        return

    if args.headers:
        if args.file:
            all_targets = read_targets(args.file)
        else:
            all_targets = args.targets or []
        if not all_targets:
            parser.error('Для --headers укажите -f targets.txt или перечислите домены напрямую')
        loader = TargetLoader()
        domains: List[str] = [
            t for t in all_targets
            if loader._is_valid_domain(t) and not loader._is_valid_ip(t)
        ]
        if not domains:
            print('Не найдено валидных доменов для --headers')
            return
        client = HeaderAnalyzer()
        results = client.run(domains, save_html=(False if args.json_only else args.html), json_only=args.json_only)
        if args.json_only:
            import json as _json
            print(_json.dumps(results or {}, ensure_ascii=False, indent=2))
        return

    if args.cert:
        if args.file:
            all_targets = read_targets(args.file)
        else:
            all_targets = args.targets or []
        if not all_targets:
            parser.error('Для --cert укажите -f targets.txt или перечислите домены напрямую')
        loader = TargetLoader()
        domains: List[str] = [
            t for t in all_targets
            if loader._is_valid_domain(t) and not loader._is_valid_ip(t)
        ]
        if not domains:
            print('Не найдено валидных доменов для --cert')
            return
        client = TLSCertAnalyzer()
        client.run(domains, save_json=args.json, save_html=args.html)
        return

    if args.vuln and not args.web:
        if not args.input:
            parser.error('Для --vuln укажите путь к web_analyzer_report_*.json через -i/--input')
        enricher = VulnEnricher(nvd_api_key=args.nvd_api_key)
        from pathlib import Path
        in_path = Path(args.input)
        enriched = enricher.enrich(in_path)
        json_out = Path(args.json_out) if args.json_out else None
        csv_out = Path(args.csv_out) if args.csv_out else None
        enricher.save_outputs(enriched, json_out=json_out, csv_out=csv_out)
        # Если пути не заданы, просто печатаем краткую сводку
        if not json_out and not csv_out:
            # Печать: домен -> продукт -> версии (кол-во CVE, EOL supported)
            for domain, payload in enriched.items():
                print(f"\n[ {domain} ]")
                enr = payload.get('enriched', {})
                for product, versions in enr.items():
                    for ver, info in versions.items():
                        eol = info.get('eol', {})
                        vulns = info.get('vulnerabilities', [])
                        print(f"  - {product} {ver}: CVE={len(vulns)}, supported={eol.get('supported')}")
        return

    # Комбинированный режим теперь по умолчанию на --web (и можно --html)
    if args.web:
        # 1) цели из файла или позиционные
        if args.file:
            all_targets = read_targets(args.file)
        else:
            all_targets = args.targets or []
        if not all_targets:
            parser.error('Для --web укажите -f targets.txt или перечислите домены напрямую')
        loader = TargetLoader()
        domains: List[str] = [
            t for t in all_targets
            if loader._is_valid_domain(t) and not loader._is_valid_ip(t)
        ]
        if not domains:
            print('Не найдено валидных доменов для --web')
            return
        web = WebAnalyzer()
        # HTML сохраняем опционально; JSON не сохраняется, результаты возвращаются
        web_results = web.run(domains, save_html=(False if args.json_only else args.html), json_only=args.json_only)
        if not web_results:
            if args.json_only:
                import json as _json
                print(_json.dumps({}, ensure_ascii=False, indent=2))
            return
        # 2) обогащаем уязвимостями/EOL в памяти
        enricher = VulnEnricher(nvd_api_key=args.nvd_api_key)
        enriched = enricher.enrich_data(web_results)
        if args.json_only:
            try:
                import json as _json
                print(_json.dumps(enriched, ensure_ascii=False, indent=2))
            except Exception:
                pass
            return
        # 4) формируем HTML раздел с рекомендациями
        from modules.reporters import MXTHTMLReporter
        reporter = MXTHTMLReporter()
        sections = []
        for domain, payload in enriched.items():
            rows = []
            enr = payload.get('enriched', {})
            for product, versions in enr.items():
                for ver, info in versions.items():
                    eol = info.get('eol', {})
                    vulns = info.get('vulnerabilities', [])
                    cwe_set = sorted({cwe for v in vulns for cwe in (v.get('cwe') or [])})
                    adv = []
                    if eol.get('supported') is False:
                        adv.append('EOL: обновить до поддерживаемого цикла')
                    if vulns:
                        adv.append(f"CVE: {len(vulns)} шт.{' (CWE: ' + ', '.join(cwe_set) + ')' if cwe_set else ''}")
                    if not adv:
                        adv.append('Нет данных о CVE; версия поддерживается')
                    info_text = f"{product} {ver} — " + ' | '.join(adv)
                    severity = 'warning' if (eol.get('supported') is False or vulns) else 'passed'
                    rows.append([severity, 'Vulnerability/EOL', info_text, ''])
            sections.append((domain, reporter.build_domain_table(rows)))
        if args.html:
            from pathlib import Path
            reports_dir = Path('reports')
            reports_dir.mkdir(parents=True, exist_ok=True)
            out_html = reports_dir / 'web_vuln_recommendations.html'
            html = reporter.wrap_global(sections, title='Web Vulnerabilities & EOL Recommendations', footer='Sources: NVD, endoflife.date')
            out_html.write_text(html, encoding='utf-8')
            print(f"HTML отчет (vuln): {out_html.resolve()}")
        else:
            # краткая консольная сводка
            for domain, payload in enriched.items():
                print(f"\n[ {domain} ]")
                enr = payload.get('enriched', {})
                for product, versions in enr.items():
                    for ver, info in versions.items():
                        eol = info.get('eol', {})
                        vulns = info.get('vulnerabilities', [])
                        print(f"  - {product} {ver}: CVE={len(vulns)}, supported={eol.get('supported')}")
        # 5) JSON-сводка по рекомендациям (для машинного потребления)
        try:
            summary_json = {}
            for domain, payload in enriched.items():
                items = []
                enr = payload.get('enriched', {})
                for product, versions in enr.items():
                    for ver, info in versions.items():
                        eol = info.get('eol', {})
                        vulns = info.get('vulnerabilities', [])
                        items.append({
                            'product': product,
                            'version': ver,
                            'cve_count': len(vulns),
                            'supported': eol.get('supported'),
                        })
                summary_json[domain] = items
            import json as _json
            print(_json.dumps({'vuln_summary': summary_json}, ensure_ascii=False, indent=2))
        except Exception:
            pass
        return

    if args.resolve:
        if args.file:
            all_targets = read_targets(args.file)
        else:
            all_targets = args.targets or []
        if not all_targets:
            parser.error('Для --resolve укажите -f targets.txt или перечислите цели напрямую')

        client = DNSResolver()
        client.run(all_targets, json_only=args.json_only)
        return

    if args.jsminer:
        import asyncio
        targets = []
        if args.url:
            targets.append(args.url)
        elif args.file:
            targets.extend(read_targets(args.file))
        
        if not targets:
            parser.error('Для --jsminer укажите цель через -u/--url или список в файле -f/--file')
        
        # TODO: Добавить валидацию URL
        
        client = JSMiner(
            threads=args.threads,
            no_sourcemaps=args.no_sourcemaps,
            verbose=args.verbose,
            cookie=args.cookie
        )
        
        # Запускаем асинхронный метод run
        asyncio.run(client.run(
            targets,
            output_file=args.output,
            json_only=args.json_only
        ))
        return
        
    if args.dnsdump:
        import asyncio
        if args.file:
            all_targets = read_targets(args.file)
        else:
            all_targets = args.targets or []
        if not all_targets:
            parser.error('Для --dnsdump укажите -f targets.txt или перечислите домены напрямую')
        
        loader = TargetLoader()
        domains: List[str] = [
            t for t in all_targets
            if loader._is_valid_domain(t) and not loader._is_valid_ip(t)
        ]
        
        if not domains:
            print('Не найдено валидных доменов для --dnsdump')
            return

        client = DNSDump()
        asyncio.run(client.run_parallel(
            domains,
            json_only=args.json_only,
            output_file=args.output
        ))
        return

    if args.dork:
        if args.file:
            all_targets = read_targets(args.file)
        else:
            all_targets = args.targets or []
        if not all_targets:
            parser.error('Для --dork укажите -f targets.txt или перечислите домены напрямую')

        loader = TargetLoader()
        domains: List[str] = [
            t for t in all_targets
            if loader._is_valid_domain(t) and not loader._is_valid_ip(t)
        ]
        if not domains:
            print('Не найдено валидных доменов для --dork')
            return

        dorker = YandexDork(cookie=args.cookie)
        dorker.run(
            domains=domains,
            max_pages=max(1, args.dork_pages),
            json_only=args.json_only,
            output_file=args.output,
        )
        return

    if args.cve:
        cve = CVELookup(nvd_api_key=args.nvd_api_key)
        software = (args.software or '').strip()
        version = (args.version or '').strip()

        # Фолбэк: разрешаем ввод одной строкой через позиционные цели, напр. "nginx 1.28.0"
        if not software or not version:
            raw = " ".join(args.targets or []).strip()
            if raw:
                sw_guess, ver_guess = cve.parse_software_input(raw)
                software = software or sw_guess
                version = version or ver_guess

        if not software or not version:
            parser.error('Для --cve укажите --software/-s и --version/-v, либо строку "software version"')

        cve.run(
            software=software,
            version=version,
            json_only=args.json_only,
            output_file=args.output,
            max_items=10,
        )
        return

    parser.print_help()


if __name__ == '__main__':
    main()
