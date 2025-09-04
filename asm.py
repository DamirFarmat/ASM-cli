#!/usr/bin/env python3
import argparse
import os
from typing import List
from dotenv import load_dotenv, find_dotenv
from modules.mxtoolbox_dns import MXToolboxDNS
from modules.dns_manual import DNSManual
from modules.web_analyzer import WebAnalyzer
from modules.network import InternetDBNetwork
from modules.vuln import VulnEnricher
from utils.target_loader import TargetLoader


def read_targets(file_path: str) -> List[str]:
    """Использует TargetLoader для загрузки целей из файла."""
    loader = TargetLoader()
    return loader.load_targets(file_path)


def main():
    parser = argparse.ArgumentParser(description='ASM - модульное приложение для пассивной разведки')
    parser.add_argument('--dns', action='store_true', help='Анализ email health через MXToolbox API')
    parser.add_argument('--dns-manual', action='store_true', help='Проверка DNS без API, по локальным правилам')
    parser.add_argument('--web', action='store_true', help='Анализ веб-технологий через python-Wappalyzer (http/https)')
    parser.add_argument('--network', action='store_true', help='Проверка IP из файла через Shodan API')
    parser.add_argument('--vuln', action='store_true', help='Анализ уязвимостей и EOL на основе web JSON отчёта')
    parser.add_argument('-f', '--file', type=str, help='Путь к файлу с целями (домены)')
    parser.add_argument('--json', action='store_true', help='Сохранить JSON ответы в reports/')
    parser.add_argument('--html', action='store_true', help='Сохранить один HTML-отчет по всем доменам в reports/')
    # Опции для --vuln
    parser.add_argument('-i', '--input', type=str, help='Путь к web_analyzer_report_*.json для --vuln')
    parser.add_argument('--json-out', type=str, help='Куда сохранить обогащённый JSON (для --vuln)')
    parser.add_argument('--csv-out', type=str, help='Куда сохранить CSV сводку (для --vuln)')
    parser.add_argument('--nvd-api-key', type=str, help='Опциональный API ключ NVD (для --vuln)')
    args = parser.parse_args()

    # Надежная загрузка .env
    env_path = find_dotenv(usecwd=True)
    if env_path:
        load_dotenv(env_path, override=True)

    if args.dns:
        if not args.file:
            parser.error('Для --dns укажите файл целей -f targets.txt')
        all_targets = read_targets(args.file)
        loader = TargetLoader()
        # фильтруем только домены
        domains: List[str] = [
            t for t in all_targets
            if loader._is_valid_domain(t) and not loader._is_valid_ip(t)
        ]
        if not domains:
            print('Во входном файле нет валидных доменов для --dns')
            return
        client = MXToolboxDNS()
        client.run(domains, save_json=args.json, save_html=args.html)
        return

    if args.dns_manual:
        if not args.file:
            parser.error('Для --dns-manual укажите файл целей -f targets.txt')
        all_targets = read_targets(args.file)
        loader = TargetLoader()
        domains: List[str] = [
            t for t in all_targets
            if loader._is_valid_domain(t) and not loader._is_valid_ip(t)
        ]
        if not domains:
            print('Во входном файле нет валидных доменов для --dns-manual')
            return
        client = DNSManual()
        client.run(domains, save_html=args.html)
        return

    if args.web and not args.vuln:
        if not args.file:
            parser.error('Для --web укажите файл целей -f targets.txt')
        all_targets = read_targets(args.file)
        loader = TargetLoader()
        domains: List[str] = [
            t for t in all_targets
            if loader._is_valid_domain(t) and not loader._is_valid_ip(t)
        ]
        if not domains:
            print('Во входном файле нет валидных доменов для --web')
            return
        client = WebAnalyzer()
        client.run(domains, save_html=args.html)
        return

    if args.network:
        if not args.file:
            parser.error('Для --network укажите файл целей -f targets.txt')
        all_targets = read_targets(args.file)
        loader = TargetLoader()
        # фильтруем только IP
        ips: List[str] = [t for t in all_targets if loader._is_valid_ip(t)]
        if not ips:
            print('Во входном файле нет валидных IP для --network')
            return
        client = InternetDBNetwork()
        client.run(ips, save_json=args.json, save_html=args.html)
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

    # Комбинированный режим: --web --vuln (и можно --html)
    if args.web and args.vuln:
        if not args.file:
            parser.error('Для --web/--vuln укажите файл целей -f targets.txt')
        # 1) запускаем веб-скан с сохранением JSON (всегда сохраняем)
        all_targets = read_targets(args.file)
        loader = TargetLoader()
        domains: List[str] = [
            t for t in all_targets
            if loader._is_valid_domain(t) and not loader._is_valid_ip(t)
        ]
        if not domains:
            print('Во входном файле нет валидных доменов для --web/--vuln')
            return
        web = WebAnalyzer()
        # Сохраняем HTML, если запрошено, и JSON (он всегда сохраняется внутри web.run)
        web.run(domains, save_html=args.html)
        # 2) находим самый свежий web_analyzer_report_*.json
        from pathlib import Path
        reports_dir = Path('reports')
        latest_json = None
        if reports_dir.exists():
            candidates = sorted(reports_dir.glob('web_analyzer_report_*.json'))
            if candidates:
                latest_json = candidates[-1]
        if not latest_json:
            print('Не найден JSON отчёт веб-сканирования для обогащения')
            return
        # 3) обогащаем уязвимостями/EOL
        enricher = VulnEnricher(nvd_api_key=args.nvd_api_key)
        enriched = enricher.enrich(latest_json)
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
        return

    parser.print_help()


if __name__ == '__main__':
    main()
