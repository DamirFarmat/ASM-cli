import asyncio
import socket
import json
import aiohttp
from typing import Optional, Dict

async def get_shodan_info(ip_address: str, json_only: bool = False) -> Optional[Dict]:
    """
    Получает информацию из Shodan InternetDB для IP-адреса.

    Args:
        ip_address: IP-адрес для запроса.

    Returns:
        Словарь с данными из Shodan или None в случае ошибки.
    """
    url = f"https://internetdb.shodan.io/{ip_address}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "ports": data.get("ports", []),
                        "cpes": data.get("cpes", []),
                        "vulns": data.get("vulns", [])
                    }
                else:
                    # API может вернуть 404, если IP не найден, это нормально
                    if response.status != 404 and not json_only:
                         print(f"[-] Shodan DB request failed for {ip_address}: HTTP {response.status}")
    except asyncio.TimeoutError:
        if not json_only:
            print(f"[-] Shodan DB request timed out for {ip_address}")
    except aiohttp.ClientError as e:
        if not json_only:
            print(f"[-] An error occurred during Shodan DB request for {ip_address}: {e}")
    
    return None

async def get_geolocation_info(ip_address: str, json_only: bool = False) -> Optional[Dict]:
    """
    Получает геолокационные данные для IP-адреса с помощью ip-api.com.

    Args:
        ip_address: IP-адрес для запроса.

    Returns:
        Словарь с широтой и долготой или None в случае ошибки.
    """
    url = f"http://ip-api.com/json/{ip_address}?fields=status,lat,lon"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('status') == 'success':
                        return {
                            "latitude": data.get("lat"),
                            "longitude": data.get("lon"),
                        }
    except asyncio.TimeoutError:
        if not json_only:
            print(f"[-] Geolocation lookup timed out for {ip_address}")
    except aiohttp.ClientError as e:
        if not json_only:
            print(f"[-] An error occurred during geolocation lookup for {ip_address}: {e}")
    
    return None

async def get_asn_info(ip_address: str, json_only: bool = False) -> Optional[Dict]:
    """
    Получает информацию об ASN для IP-адреса, используя Team Cymru WHOIS-сервис.

    Args:
        ip_address: IP-адрес для запроса.

    Returns:
        Словарь с информацией об ASN или None в случае ошибки.
    """
    try:
        # Создаем асинхронный сокет
        reader, writer = await asyncio.open_connection('whois.cymru.com', 43)

        # Формируем и отправляем запрос
        # -v для подробного вывода
        writer.write(f"-v {ip_address}\n".encode('utf-8'))
        await writer.drain()

        # Читаем ответ
        response = await reader.read()
        
        # Закрываем соединение
        writer.close()
        await writer.wait_closed()

        # Парсим ответ
        response_str = response.decode('utf-8')
        # Ответ выглядит так:
        # AS      | IP              | BGP Prefix          | CC | Registry | Allocated  | AS Name
        # 15169   | 8.8.8.8         | 8.8.8.0/24          | US | ARIN     | 2009-08-14 | GOOGLE, US
        # Пропускаем заголовок
        lines = response_str.strip().split('\n')
        if len(lines) > 1:
            parts = [p.strip() for p in lines[1].split('|')]
            if len(parts) == 7:
                return {
                    "number": f"AS{parts[0]}",
                    "owner": parts[6]
                }
    except socket.gaierror:
        if not json_only:
            print(f"[-] ASN lookup failed for {ip_address}: Could not resolve whois.cymru.com")
    except Exception as e:
        if not json_only:
            print(f"[-] An error occurred during ASN lookup for {ip_address}: {e}")
    
    return None
