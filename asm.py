#!/usr/bin/env python3
import argparse
import os
from typing import List
from dotenv import load_dotenv, find_dotenv
from modules.mxtoolbox_dns import MXToolboxDNS
from modules.dns_manual import DNSManual
from modules.web_analyzer import WebAnalyzer
from modules.network import InternetDBNetwork
from utils.target_loader import TargetLoader


def read_targets(file_path: str) -> List[str]:
    """Использует TargetLoader для загрузки целей из файла."""
    loader = TargetLoader()
    return loader.load_targets(file_path)


def main():
    parser = argparse.ArgumentParser(description='ASM - модульное приложение для пассивной разведки')
    parser.add_argument('--dns', action='store_true', help='Анализ email health через MXToolbox API')
    parser.add_argument('--dns-manual', action='store_true', help='Проверка DNS без API, по локальным правилам')
    parser.add_argument('--web', action='store_true', help='Анализ веб-технологий через WhatWeb')
    parser.add_argument('--network', action='store_true', help='Проверка IP из файла через Shodan API')
    parser.add_argument('-f', '--file', type=str, help='Путь к файлу с целями (домены)')
    parser.add_argument('--json', action='store_true', help='Сохранить JSON ответы в reports/')
    parser.add_argument('--html', action='store_true', help='Сохранить один HTML-отчет по всем доменам в reports/')
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

    if args.web:
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

    parser.print_help()


if __name__ == '__main__':
    main()
