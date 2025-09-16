"""
TLS/SSL Certificate and Protocol Checker

Features per domain (port 443):
- Detect supported TLS versions (1.0/1.1/1.2/1.3)
- Fetch certificate (without validation) and check expiry
- Flag usage of TLS 1.0/1.1 as vulnerabilities
- Flag certificates expiring within 30 days (or already expired)

Outputs: console table-like summary and optional JSON/HTML reports.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import socket
import ssl
from datetime import datetime, timedelta
from pathlib import Path
import json

from colorama import Fore, Style, init
from tabulate import tabulate

from modules.reporters import MXTHTMLReporter
from utils.target_loader import TargetLoader


init()


class TLSCertAnalyzer:
    def __init__(self, port: int = 443, timeout_s: int = 10) -> None:
        self.port = port
        self.timeout_s = timeout_s
        self.reporter = MXTHTMLReporter()
        self.target_loader = TargetLoader()

    # --------------- low-level ---------------
    def _probe_tls_version(self, host: str, version: ssl.TLSVersion) -> bool:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = version
            context.maximum_version = version
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, self.port), timeout=self.timeout_s) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    _ = ssock.version()
                    return True
        except Exception:
            return False

    def _fetch_cert(self, host: str) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "subject": None,
            "issuer": None,
            "notBefore": None,
            "notAfter": None,
            "sans": [],
            "error": None,
        }
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, self.port), timeout=self.timeout_s) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
        except Exception as e:
            data["error"] = str(e)
            return data

        if cert:
            # subject and issuer as tuples
            subj = cert.get("subject", [])
            issr = cert.get("issuer", [])
            data["subject"] = ", ".join("{}={}".format(k, v) for r in subj for (k, v) in r)
            data["issuer"] = ", ".join("{}={}".format(k, v) for r in issr for (k, v) in r)
            data["notBefore"] = cert.get("notBefore")
            data["notAfter"] = cert.get("notAfter")
            # subjectAltName
            san = cert.get("subjectAltName") or []
            data["sans"] = [v for (t, v) in san if t.lower() == "dns"]
        return data

    def _parse_not_after(self, not_after: Optional[str]) -> Optional[datetime]:
        if not not_after:
            return None
        # Common OpenSSL text format: 'Jun  1 12:00:00 2025 GMT'
        fmts = ["%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"]
        for f in fmts:
            try:
                return datetime.strptime(not_after, f)
            except Exception:
                pass
        return None

    # --------------- analysis ---------------
    def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "domain": domain,
            "supported_versions": [],
            "certificate": {},
            "findings": [],  # list of {level, name, info}
        }

        # Probe TLS versions
        supported: List[str] = []
        version_map: List[Tuple[str, ssl.TLSVersion]] = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]
        for name, ver in version_map:
            if self._probe_tls_version(domain, ver):
                supported.append(name)
        result["supported_versions"] = supported

        # Fetch cert and evaluate expiry
        cert = self._fetch_cert(domain)
        result["certificate"] = cert
        not_after_dt = self._parse_not_after(cert.get("notAfter")) if cert else None
        if not_after_dt:
            days_left = (not_after_dt - datetime.utcnow()).days
            if days_left < 0:
                result["findings"].append({"level": "Failed", "name": "Certificate Expired", "info": f"expired {abs(days_left)} days ago"})
            elif days_left <= 30:
                result["findings"].append({"level": "Warning", "name": "Certificate Near Expiry", "info": f"expires in {days_left} days"})
        else:
            result["findings"].append({"level": "Warning", "name": "Certificate", "info": "Could not parse NotAfter"})

        # Weak protocol usage
        if "TLSv1.0" in supported:
            result["findings"].append({"level": "Failed", "name": "Weak Protocol Enabled", "info": "TLS 1.0 is supported"})
        if "TLSv1.1" in supported:
            result["findings"].append({"level": "Failed", "name": "Weak Protocol Enabled", "info": "TLS 1.1 is supported"})

        return result

    # --------------- presentation ---------------
    def _print_console(self, domain: str, data: Dict[str, Any]) -> None:
        print(f"{Fore.GREEN}ДОМЕН: {domain}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'-' * (len(domain) + 8)}{Style.RESET_ALL}")
        rows = []
        cert = data.get("certificate", {})
        rows.append(["Subject", cert.get("subject") or '—'])
        rows.append(["Issuer", cert.get("issuer") or '—'])
        rows.append(["Not After", cert.get("notAfter") or '—'])
        rows.append(["Supported TLS", ", ".join(data.get("supported_versions") or []) or '—'])
        print(tabulate(rows, headers=["Поле", "Значение"], tablefmt='grid'))
        if data.get("findings"):
            print("\nFindings:")
            f_rows = [[f["level"], f["name"], f["info"]] for f in data["findings"]]
            print(tabulate(f_rows, headers=["Уровень", "Проблема", "Описание"], tablefmt='grid'))

    def _build_html_section(self, domain: str, data: Dict[str, Any]) -> Tuple[str, str]:
        rows: List[List[str]] = []
        cert = data.get("certificate", {})
        # Summary rows
        rows.append(["Passed", "Subject", cert.get("subject") or '—', ""])
        rows.append(["Passed", "Issuer", cert.get("issuer") or '—', ""])
        rows.append(["Passed", "Not After", cert.get("notAfter") or '—', ""])
        rows.append(["Passed", "Supported TLS", ", ".join(data.get("supported_versions") or []) or '—', ""])
        # Findings
        for f in data.get("findings", []):
            rows.append([f.get("level") or "Warning", f.get("name") or "Finding", f.get("info") or "", ""])
        return domain, self.reporter.build_domain_table(rows)

    # --------------- public API ---------------
    def run(self, domains: List[str], save_json: bool = False, save_html: bool = False) -> None:
        print(f"Найдено доменов для анализа сертификатов: {len(domains)}")
        all_results: Dict[str, Any] = {}
        sections: List[Tuple[str, str]] = []

        for d in domains:
            print(f"\n{Fore.CYAN}Проверяю TLS/SSL: {d}{Style.RESET_ALL}")
            res = self._analyze_domain(d)
            all_results[d] = res
            self._print_console(d, res)
            if save_html:
                sections.append(self._build_html_section(d, res))

        if save_html and sections:
            from datetime import datetime as _dt
            reports_dir = Path('reports')
            reports_dir.mkdir(parents=True, exist_ok=True)
            ts = _dt.now().strftime('%Y%m%d_%H%M%S')
            out = reports_dir / f"cert_report_{ts}.html"
            html = self.reporter.wrap_global(sections, title='TLS/SSL Certificate Report', footer='Checks: TLS versions, expiry')
            out.write_text(html, encoding='utf-8')
            print(f"\n{Fore.GREEN}HTML отчет (cert): {out.resolve()}{Style.RESET_ALL}")

        # Печать JSON в консоль всегда
        if all_results:
            try:
                print(json.dumps(all_results, ensure_ascii=False, indent=2))
            except Exception:
                pass

        if save_json and all_results:
            from datetime import datetime as _dt
            reports_dir = Path('reports')
            reports_dir.mkdir(parents=True, exist_ok=True)
            ts = _dt.now().strftime('%Y%m%d_%H%M%S')
            out = reports_dir / f"cert_report_{ts}.json"
            with open(out, 'w', encoding='utf-8') as f:
                json.dump(all_results, f, ensure_ascii=False, indent=2)
            print(f"{Fore.GREEN}JSON отчет (cert): {out.resolve()}{Style.RESET_ALL}")



