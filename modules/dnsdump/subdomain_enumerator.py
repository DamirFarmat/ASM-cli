import asyncio
import dns.resolver
import dns.zone
import dns.exception
import aiohttp
import asyncio
from typing import List

async def passive_crt_sh(domain: str, json_only: bool = False) -> List[str] | None:
    """
    Пассивно ищет субдомены с использованием crt.sh.
    В случае ошибки возвращает None.
    """
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=20) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        if name_value:
                            subdomains.update(h.strip() for h in name_value.split('\n') if h.strip().endswith(domain) and not h.startswith('*.'))
                    
                    if not json_only:
                        print(f"[+] Found {len(subdomains)} unique subdomains via crt.sh.")
                    return list(subdomains)
                else:
                    if not json_only:
                        print(f"[-] crt.sh query failed with status: {response.status}. The service may be unavailable.")
                    return None
    except (asyncio.TimeoutError, aiohttp.ClientError) as e:
        if not json_only:
            print(f"[-] crt.sh is unavailable, please try again later. Error: {e}")
        return None

async def axfr_zone_transfer(domain: str, json_only: bool = False) -> List[str]:
    """
    Пытается выполнить запрос на передачу зоны (AXFR) для обнаружения субдоменов.

    Args:
        domain: Целевой домен.

    Returns:
        Список субдоменов, полученных через AXFR, или пустой список в случае неудачи.
    """
    found_subdomains = []
    try:
        # Сначала найдем NS-серверы для домена
        ns_resolver = dns.resolver.Resolver()
        ns_answers = await asyncio.to_thread(ns_resolver.resolve, domain, 'NS')
        ns_servers = [str(r.target) for r in ns_answers]

        for ns_server in ns_servers:
            try:
                # Попытка передачи зоны с каждого NS-сервера
                zone = await asyncio.to_thread(dns.zone.from_xfr, dns.query.xfr(ns_server, domain, timeout=5))
                if zone:
                    for name, node in zone.nodes.items():
                        subdomain = name.to_text()
                        if subdomain != '@' and subdomain != '*':
                            found_subdomains.append(f"{subdomain}.{domain}")
                    if found_subdomains:
                        if not json_only:
                            print(f"[+] Zone transfer successful from {ns_server} for {domain}!")
                        return list(set(found_subdomains)) # Возвращаем уникальные значения
            except dns.exception.FormError:
                if not json_only:
                    print(f"[-] Zone transfer failed for {domain} from {ns_server}: FormError")
            except dns.exception.Timeout:
                if not json_only:
                    print(f"[-] Zone transfer failed for {domain} from {ns_server}: Timeout")
            except Exception as e:
                # AXFR часто запрещен, поэтому не выводим все ошибки, только основные
                if "REFUSED" in str(e):
                    if not json_only:
                        print(f"[-] Zone transfer REFUSED for {domain} from {ns_server}.")
                elif not json_only:
                    print(f"[-] Zone transfer failed for {domain} from {ns_server}: {type(e).__name__}")

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        if not json_only:
            print(f"[-] Could not find NS records for {domain} to attempt zone transfer.")
    except Exception as e:
        if not json_only:
            print(f"[-] An unexpected error occurred during AXFR attempt for {domain}: {e}")
        
    return []
