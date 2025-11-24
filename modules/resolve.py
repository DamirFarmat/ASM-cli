"""
Модуль для разрешения доменных имен в IP-адреса и наоборот.
"""

from __future__ import annotations
import socket
from typing import Dict, List, Union, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from colorama import Fore, Style, init

init()

class DNSResolver:
    """
    Резолвит доменные имена в IP-адреса и наоборот.
    """

    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers

    def _resolve_target(self, target: str) -> Dict[str, Any]:
        """
        Резолвит одну цель (домен или IP).
        """
        try:
            # Попытка разрешить как домен
            if any(c.isalpha() for c in target):
                ips = socket.gethostbyname_ex(target)[2]
                return {'target': target, 'type': 'domain', 'results': ips}
            # Попытка разрешить как IP
            else:
                hostname, _, _ = socket.gethostbyaddr(target)
                return {'target': target, 'type': 'ip', 'results': [hostname]}
        except socket.gaierror:
            return {'target': target, 'type': 'unknown', 'error': 'Could not resolve'}
        except socket.herror:
            return {'target': target, 'type': 'ip', 'error': 'No domain name associated'}
        except Exception as e:
            return {'target': target, 'type': 'unknown', 'error': str(e)}

    def run(self, targets: List[str], json_only: bool = False) -> Dict[str, Any]:
        """
        Запускает разрешение для списка целей.
        """
        results = {}
        all_ips = set()
        all_domains = set()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {executor.submit(self._resolve_target, target): target for target in targets}
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results[target] = result
                    if 'error' not in result:
                        if result['type'] == 'domain':
                            all_domains.add(target)
                            for ip in result['results']:
                                all_ips.add(ip)
                        elif result['type'] == 'ip':
                            all_ips.add(target)
                            for domain in result['results']:
                                all_domains.add(domain)
                except Exception as e:
                    results[target] = {'target': target, 'error': str(e)}

        if json_only:
            output_data = {
                "results": results,
                "total": {
                    "ips": sorted(list(all_ips)),
                    "domains": sorted(list(all_domains))
                }
            }
            print(json.dumps(output_data, ensure_ascii=False, indent=2))
        else:
            for target, result in results.items():
                if 'error' in result:
                    print(f"{Fore.RED}[{target}] Error: {result['error']}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.CYAN}[{target}] ({result['type']}){Style.RESET_ALL}")
                    for res in result['results']:
                        print(f"  - {res}")
            
            print(f"\n{Fore.GREEN}--- Total ---{Style.RESET_ALL}")
            if all_domains:
                print(f"{Fore.YELLOW}Domains ({len(all_domains)}):{Style.RESET_ALL}")
                for domain in sorted(list(all_domains)):
                    print(f"  - {domain}")
            if all_ips:
                print(f"{Fore.YELLOW}IPs ({len(all_ips)}):{Style.RESET_ALL}")
                for ip in sorted(list(all_ips)):
                    print(f"  - {ip}")

        return results