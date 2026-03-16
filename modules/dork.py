from __future__ import annotations

import json
import re
from typing import Dict, List, Set
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class YandexDork:
    """
    Поиск поддоменов через Yandex search dork:
    rhost:<domain>.*
    """

    SEARCH_URL = "https://ya.ru/search/"

    def __init__(self, timeout_s: int = 20, lr: int = 10493, cookie: str | None = None) -> None:
        self.timeout_s = timeout_s
        self.lr = lr
        self.session = requests.Session()
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "ru,en;q=0.9",
        }
        if cookie:
            headers["Cookie"] = cookie
        self.session.headers.update(headers)

    def _is_captcha_page(self, html: str, final_url: str) -> bool:
        url_low = (final_url or "").lower()
        html_low = (html or "").lower()
        return (
            "showcaptchafast" in url_low
            or "showcaptcha" in url_low
            or "captcha" in url_low and "ya.ru" in url_low
            or "showcaptchafast" in html_low
            or "проверка, что вы не робот" in html_low
            or "verification" in html_low and "captcha" in html_low
        )

    def _extract_host_from_candidate(self, candidate: str) -> str | None:
        if not candidate:
            return None
        c = candidate.strip()
        if c.startswith("//"):
            c = "https:" + c
        if not c.startswith(("http://", "https://")):
            return None
        try:
            host = (urlparse(c).hostname or "").lower().rstrip(".")
            return host or None
        except Exception:
            return None

    def _extract_subdomains_from_html(self, html: str, domain: str) -> Set[str]:
        soup = BeautifulSoup(html, "html.parser")
        found: Set[str] = set()
        domain_l = domain.lower().rstrip(".")
        suffix = f".{domain_l}"

        # 1) Прямые ссылки и yandex-редиректы с полезным URL в query-параметрах.
        for a in soup.find_all("a", href=True):
            href = (a.get("href") or "").strip()
            full_href = urljoin(self.SEARCH_URL, href)
            candidates = [full_href]

            try:
                parsed = urlparse(full_href)
                qs = parse_qs(parsed.query)
                for key in ("url", "u", "to", "target", "rdr", "dest"):
                    for val in qs.get(key, []):
                        if val:
                            candidates.append(unquote(val))
            except Exception:
                pass

            for candidate in candidates:
                host = self._extract_host_from_candidate(candidate)
                if not host or host == domain_l:
                    continue
                if host.endswith(suffix):
                    found.add(host)

        # 2) Фолбэк: вытащить домены из текста страницы (SERP сниппеты/хлебные крошки).
        host_re = re.compile(rf"\b(?:[a-z0-9-]+\.)+{re.escape(domain_l)}\b", re.IGNORECASE)
        for match in host_re.findall(soup.get_text(" ", strip=True)):
            host = match.lower().rstrip(".")
            if host != domain_l and host.endswith(suffix):
                found.add(host)

        return found

    def _fetch_page(self, query: str, page: int) -> tuple[str, str]:
        params = {
            "text": query,
            "lr": self.lr,
            "p": page,
        }
        resp = self.session.get(self.SEARCH_URL, params=params, timeout=self.timeout_s)
        resp.raise_for_status()
        return resp.text, resp.url

    def _build_rhost_query(self, domain: str) -> str:
        parts = [p for p in domain.lower().split(".") if p]
        reversed_domain = ".".join(reversed(parts))
        return f"rhost:{reversed_domain}.*"

    def _collect_for_domain(self, domain: str, max_pages: int, json_only: bool) -> Dict[str, List[str]]:
        query = self._build_rhost_query(domain)
        all_found: Set[str] = set()
        captcha_hits = 0

        if not json_only:
            print(f"\n[*] Dork query: {query}")

        for page in range(max_pages):
            try:
                if not json_only:
                    print(f"[*] Fetching Yandex page p={page}")
                html, final_url = self._fetch_page(query=query, page=page)
                if self._is_captcha_page(html=html, final_url=final_url):
                    captcha_hits += 1
                    if not json_only:
                        print(f"[!] Yandex returned CAPTCHA page on p={page}: {final_url}")
                    continue
                page_found = self._extract_subdomains_from_html(html=html, domain=domain)
                all_found.update(page_found)
            except requests.RequestException as e:
                if not json_only:
                    print(f"[-] Yandex request error on page {page}: {e}")
            except Exception as e:
                if not json_only:
                    print(f"[-] Parse error on page {page}: {e}")

        return {
            "query": query,
            "subdomains": sorted(all_found),
            "captcha_detected": captcha_hits > 0,
        }

    def run(self, domains: List[str], max_pages: int = 3, json_only: bool = False, output_file: str | None = None) -> Dict[str, Dict[str, List[str]]]:
        # Убираем дубли, сохраняя порядок.
        seen = set()
        normalized_domains: List[str] = []
        for domain in domains:
            d = domain.strip().lower()
            if not d or d in seen:
                continue
            seen.add(d)
            normalized_domains.append(d)

        report: Dict[str, Dict[str, List[str]]] = {}
        for domain in normalized_domains:
            report[domain] = self._collect_for_domain(domain=domain, max_pages=max_pages, json_only=json_only)

        if report:
            print(json.dumps(report, ensure_ascii=False, indent=2))

        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(report, f, ensure_ascii=False, indent=2)
                if not json_only:
                    print(f"[+] Report saved to {output_file}")
            except OSError as e:
                if not json_only:
                    print(f"[-] Error saving report: {e}")

        return report
