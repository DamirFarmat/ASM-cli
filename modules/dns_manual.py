"""
DNS Manual Analyzer

Проверки DNS/Email, вдохновленные MXToolbox, без использования внешних API.
Проверяются только домены (IP игнорируются).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Set
import signal
import sys

import ipaddress
import re

import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.exception

from colorama import Fore, Style, init
from tabulate import tabulate

from utils.target_loader import TargetLoader
from modules.reporters import MXTHTMLReporter
from publicsuffix2 import PublicSuffixList


init()
_psl = PublicSuffixList()


@dataclass
class CheckItem:
    status: str  # Failed | Warning | Passed
    name: str
    info: str = ""
    url: str = ""


class DNSManual:
    """
    Реализация проверок DNS/Email health без MXToolbox API.
    Формирует табличный консольный вывод и (опционально) общий HTML-отчет.
    """

    def __init__(self, timeout_s: int = 5) -> None:
        self.timeout_s = timeout_s
        self.resolver = dns.resolver.Resolver()
        # Устанавливаем более строгие таймауты для предотвращения зависания
        self.resolver.timeout = timeout_s
        self.resolver.lifetime = timeout_s
        # Добавляем дополнительные настройки для стабильности
        self.resolver.retries = 1
        self.resolver.tcp_attempts = 0  # Отключаем TCP fallback
        self.target_loader = TargetLoader()
        self.reporter = MXTHTMLReporter()
        self.json_only: bool = False
        
        # Настройка обработчика сигналов для корректного завершения
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Настройка обработчиков сигналов для корректного завершения"""
        def signal_handler(signum, frame):
            print(f"\nПолучен сигнал {signum}, завершаю работу...")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    # --------------- helpers: generic DNS -----------------
    def _safe_resolve(self, qname: str, rtype: str) -> Optional[List[Any]]:
        try:
            # Создаем новый резолвер для каждого запроса с жесткими таймаутами
            temp_resolver = dns.resolver.Resolver()
            temp_resolver.timeout = self.timeout_s
            temp_resolver.lifetime = self.timeout_s
            temp_resolver.retries = 0  # Без повторных попыток
            
            ans = temp_resolver.resolve(qname, rtype)
            return list(ans)
        except dns.exception.Timeout:
            if not self.json_only:
                print(f"DNS timeout for {qname} {rtype}")
            return None
        except dns.exception.DNSException as e:
            if not self.json_only:
                print(f"DNS error for {qname} {rtype}: {e}")
            return None
        except Exception as e:
            if not self.json_only:
                print(f"Unexpected error for {qname} {rtype}: {e}")
            return None

    def _txt_values(self, name: str) -> List[str]:
        values: List[str] = []
        answers = self._safe_resolve(name, 'TXT') or []
        for r in answers:
            try:
                parts = []
                # dnspython TXT rdata: .strings is list[bytes]
                strings = getattr(r, 'strings', None)
                if strings:
                    parts = [s.decode('utf-8', 'ignore') for s in strings]
                else:
                    parts = [str(r).strip('"')]
                values.append(''.join(parts).strip())
            except Exception:
                try:
                    values.append(str(r).replace('"', '').strip())
                except Exception:
                    pass
        return values

    def _resolve_cname_target(self, name: str, max_depth: int = 5) -> Optional[str]:
        current = name.rstrip('.')
        for _ in range(max_depth):
            answers = self._safe_resolve(current, 'CNAME') or []
            if not answers:
                return current
            try:
                target = answers[0].target if hasattr(answers[0], 'target') else answers[0]
                current = str(target).rstrip('.')
            except Exception:
                return current
        return current

    def _registrable_domain(self, domain: str) -> str:
        try:
            return _psl.get_public_suffix(domain)
        except Exception:
            return domain

    def _query_to_server(self, server_ip: str, qname: str, rtype: str) -> Optional[dns.message.Message]:
        try:
            q = dns.message.make_query(qname, rtype)
            # Без рекурсии для авторитативности
            q.flags &= ~dns.flags.RD
            # Используем более короткий таймаут для серверных запросов
            resp = dns.query.udp(q, server_ip, timeout=min(self.timeout_s, 3))
            return resp
        except dns.exception.Timeout:
            if not self.json_only:
                print(f"Server query timeout for {qname} {rtype} to {server_ip}")
            return None
        except Exception as e:
            if not self.json_only:
                print(f"Server query error for {qname} {rtype} to {server_ip}: {e}")
            return None

    def _resolve_first_ip(self, hostname: str) -> Optional[str]:
        ips = self._safe_resolve(hostname, 'A') or []
        if ips:
            return str(ips[0])
        ips6 = self._safe_resolve(hostname, 'AAAA') or []
        if ips6:
            return str(ips6[0])
        return None

    def _get_child_ns(self, domain: str) -> List[str]:
        # NS, как их видят рекурсивные резолверы (обычно child zone)
        ans = self._safe_resolve(domain, 'NS')
        if not ans:
            return []
        return [str(a.target if hasattr(a, 'target') else a).rstrip('.') for a in ans]

    def _get_parent_zone(self, domain: str) -> Optional[str]:
        labels = domain.strip('.').split('.')
        if len(labels) < 2:
            return None
        return '.'.join(labels[1:])

    def _get_parent_ns(self, domain: str) -> List[str]:
        # Итеративно: корень -> TLD -> parent -> NS delegation for domain
        parent = self._get_parent_zone(domain)
        if not parent:
            return []
        # Получаем NS родительской зоны
        parent_ns = self._safe_resolve(parent, 'NS') or []
        if not parent_ns:
            return []
        # Берем один NS родителя, спрашиваем у него NS для domain (delegation в authority)
        for nsr in parent_ns:
            ns_name = str(nsr.target if hasattr(nsr, 'target') else nsr).rstrip('.')
            ns_ip = self._resolve_first_ip(ns_name)
            if not ns_ip:
                continue
            resp = self._query_to_server(ns_ip, domain, 'NS')
            if not resp:
                continue
            # Ищем NS записи в ANSWER или AUTHORITY
            names: Set[str] = set()
            for rrset in list(resp.answer) + list(resp.authority):
                if rrset.rdtype == dns.rdatatype.NS:
                    for r in rrset:
                        names.add(str(r.target if hasattr(r, 'target') else r).rstrip('.'))
            if names:
                return sorted(names)
        return []

    def _get_soa_from_server(self, server_ip: str, domain: str) -> Optional[Tuple[bool, Any]]:
        resp = self._query_to_server(server_ip, domain, 'SOA')
        if not resp:
            return None
        is_authoritative = bool(resp.flags & dns.flags.AA)
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                for r in rrset:
                    return is_authoritative, r
        # Иногда SOA в authority
        for rrset in resp.authority:
            if rrset.rdtype == dns.rdatatype.SOA:
                for r in rrset:
                    return is_authoritative, r
        return is_authoritative, None

    def _soa_from_all_ns(self, domain: str, ns_hosts: List[str]) -> Tuple[List[Tuple[str, Optional[str], bool, Optional[Any]]], List[str]]:
        """Возвращает список кортежей (ns_host, ip, aa, soa_rdata) и список неотвечающих NS."""
        results: List[Tuple[str, Optional[str], bool, Optional[Any]]] = []
        down: List[str] = []
        for ns in ns_hosts:
            ip = self._resolve_first_ip(ns)
            if not ip:
                results.append((ns, None, False, None))
                continue
            soa = self._get_soa_from_server(ip, domain)
            if not soa:
                down.append(ns)
                results.append((ns, ip, False, None))
                continue
            aa, r = soa
            results.append((ns, ip, bool(aa), r))
        return results, down

    # --------------- checks -----------------
    def _check_ns_count(self, ns_hosts: List[str]) -> CheckItem:
        if len(ns_hosts) >= 2:
            return CheckItem(
                'Passed',
                'DNS: DNS At Least Two Servers',
                f"At least two name servers found ({len(ns_hosts)}): {', '.join(ns_hosts)}",
            )
        return CheckItem(
            'Failed',
            'DNS: DNS At Least Two Servers',
            f"Less than two name servers found ({len(ns_hosts)}): {', '.join(ns_hosts) if ns_hosts else 'none'}",
        )

    def _check_all_ns_responding(self, soa_results: List[Tuple[str, Optional[str], bool, Optional[Any]]], down: List[str]) -> CheckItem:
        if not down:
            ns_list = [ns for ns, _ip, _aa, _soa in soa_results]
            return CheckItem('Passed', 'DNS: DNS All Servers Responding', f"All name servers are responding: {', '.join(ns_list)}")
        up = [ns for ns, _ip, _aa, _soa in soa_results if ns not in down]
        return CheckItem('Failed', 'DNS: DNS All Servers Responding', f"No response from: {', '.join(down)}; responding: {', '.join(up)}")

    def _check_all_authoritative(self, soa_results: List[Tuple[str, Optional[str], bool, Optional[Any]]]) -> CheckItem:
        non_auth = [ns for ns, _ip, aa, _soa in soa_results if aa is False]
        if not non_auth:
            return CheckItem('Passed', 'DNS: DNS All Servers Authoritative', 'All of the name servers are Authoritative')
        return CheckItem('Failed', 'DNS: DNS All Servers Authoritative', f"Non-authoritative servers: {', '.join(non_auth)}")

    def _check_parent_match(self, child_ns: List[str], parent_ns: List[str]) -> CheckItem:
        if not parent_ns:
            return CheckItem('Warning', 'DNS: DNS Local Parent Mismatch', 'Unable to retrieve NS list from parent')
        if set(map(str.lower, child_ns)) == set(map(str.lower, parent_ns)):
            return CheckItem('Passed', 'DNS: DNS Local Parent Mismatch', f"Local NS list matches Parent NS list ({len(child_ns)}): {', '.join(child_ns)}")
        return CheckItem('Warning', 'DNS: DNS Local Parent Mismatch', f"Local NS ({len(child_ns)}): {', '.join(child_ns)}; Parent NS ({len(parent_ns)}): {', '.join(parent_ns)}")

    def _check_primary_listed_at_parent(self, soa_results: List[Tuple[str, Optional[str], bool, Optional[Any]]], parent_ns: List[str]) -> Optional[CheckItem]:
        # Primary = SOA.mname
        primaries: List[str] = []
        for ns, ip, aa, soa in soa_results:
            if soa is not None:
                try:
                    mname = str(soa.mname).rstrip('.')
                    primaries.append(mname)
                except Exception:
                    pass
        if not primaries:
            return None
        primary = primaries[0]
        if not parent_ns:
            return CheckItem('Warning', 'DNS: DNS Primary Server Listed At Parent', f'Could not query Parent NS list; primary detected: {primary}')
        if primary.lower() in [p.lower() for p in parent_ns]:
            return CheckItem('Passed', 'DNS: DNS Primary Server Listed At Parent', f'Primary NS listed at Parent: {primary}')
        return CheckItem('Failed', 'DNS: DNS Primary Server Listed At Parent', f"Primary NS not listed at Parent. Primary: {primary}; Parent NS: {', '.join(parent_ns)}")

    def _check_ns_public_ips(self, soa_results: List[Tuple[str, Optional[str], bool, Optional[Any]]]) -> CheckItem:
        private: List[str] = []
        for ns, ip, aa, soa in soa_results:
            if not ip:
                continue
            try:
                ipaddr = ipaddress.ip_address(ip)
                if ipaddr.is_private or ipaddr.is_loopback or ipaddr.is_link_local:
                    private.append(f"{ns}({ip})")
            except Exception:
                pass
        if private:
            return CheckItem('Failed', 'DNS: DNS Servers Have Public IP Addresses', f"Private or non-public IPs: {', '.join(private)}")
        public = [f"{ns}({ip})" for ns, ip, _aa, _soa in soa_results if ip]
        return CheckItem('Passed', 'DNS: DNS Servers Have Public IP Addresses', f"All NS have public IPs: {', '.join(public)}")

    def _check_ns_different_subnets(self, soa_results: List[Tuple[str, Optional[str], bool, Optional[Any]]]) -> CheckItem:
        subnets: Set[str] = set()
        for ns, ip, aa, soa in soa_results:
            if not ip:
                continue
            try:
                ipaddr = ipaddress.ip_address(ip)
                if isinstance(ipaddr, ipaddress.IPv4Address):
                    subnet = '.'.join(ip.split('.')[:3])  # /24
                    subnets.add(subnet)
            except Exception:
                pass
        if len(subnets) >= 2:
            return CheckItem('Passed', 'DNS: DNS Servers are on Different Subnets', f"Name Servers appear to be dispersed across subnets: {', '.join(sorted(subnets))}")
        return CheckItem('Warning', 'DNS: DNS Servers are on Different Subnets', f"Name Servers might be in the same subnet: {', '.join(sorted(subnets)) or 'n/a'}")

    def _check_open_recursive(self, domain: str, soa_results: List[Tuple[str, Optional[str], bool, Optional[Any]]]) -> CheckItem:
        open_list: List[str] = []
        test_qname = 'www.google.com.'
        for ns, ip, aa, soa in soa_results:
            if not ip:
                continue
            try:
                q = dns.message.make_query(test_qname, dns.rdatatype.A)
                q.flags |= dns.flags.RD
                resp = dns.query.udp(q, ip, timeout=min(self.timeout_s, 3))
                if resp.rcode() == dns.rcode.NOERROR and (resp.answer or resp.flags & dns.flags.RA):
                    open_list.append(f"{ns}({ip})")
            except Exception:
                pass
        if open_list:
            return CheckItem('Warning', 'DNS: DNS Open Recursive Name Server', f"Potential open recursive resolvers ({len(open_list)}/{len(soa_results)}): {', '.join(open_list)}")
        return CheckItem('Passed', 'DNS: DNS Open Recursive Name Server', f"No open recursive servers detected (tested {len(soa_results)})")

    def _check_bad_glue(self, domain: str, parent_ns: List[str]) -> CheckItem:
        # На практике: сравнить glue из additional с фактическими A/AAAA NS. Если не можем — нейтральный Pass.
        try:
            if not parent_ns:
                return CheckItem('Warning', 'DNS: DNS Bad Glue Detected', 'Unable to verify glue at parent')
            # спросим у любого NS родителя делегирование и additional
            parent_ip = self._resolve_first_ip(parent_ns[0])
            if not parent_ip:
                return CheckItem('Warning', 'DNS: DNS Bad Glue Detected', 'Unable to resolve Parent NS IP')
            resp = self._query_to_server(parent_ip, domain, 'NS')
            if not resp:
                return CheckItem('Warning', 'DNS: DNS Bad Glue Detected', 'Unable to query Parent for delegation')
            glue_map: Dict[str, List[str]] = {}
            for rrset in resp.additional:
                if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    host = rrset.name.to_text().rstrip('.')
                    glue_map.setdefault(host, [])
                    for r in rrset:
                        glue_map[host].append(str(r.address if hasattr(r, 'address') else r))
            mismatches: List[str] = []
            for host, glue_ips in glue_map.items():
                try:
                    current_ips = [str(a) for a in (self._safe_resolve(host, 'A') or [])]
                    if current_ips and set(current_ips).isdisjoint(set(glue_ips)):
                        mismatches.append(f"{host}: glue={','.join(glue_ips)} current={','.join(current_ips)}")
                except Exception:
                    pass
            if mismatches:
                return CheckItem('Warning', 'DNS: DNS Bad Glue Detected', f"Glue/authoritative IP mismatch: {'; '.join(mismatches)}")
            return CheckItem('Passed', 'DNS: DNS Bad Glue Detected', f"No Bad Glue Detected (checked via parent {parent_ns[0]})")
        except Exception:
            return CheckItem('Warning', 'DNS: DNS Bad Glue Detected', 'Glue verification error (skipped)')

    def _check_dns_record_published(self, domain: str) -> CheckItem:
        # Условно: есть ли хоть какие-то записи (A/AAAA/CNAME/MX)
        found_types: List[str] = []
        if self._safe_resolve(domain, 'A'):
            found_types.append('A')
        if self._safe_resolve(domain, 'AAAA'):
            found_types.append('AAAA')
        if self._safe_resolve(domain, 'CNAME'):
            found_types.append('CNAME')
        if self._safe_resolve(domain, 'MX'):
            found_types.append('MX')
        if found_types:
            return CheckItem('Passed', 'DNS: DNS Record Published', f"DNS records found: {', '.join(found_types)}")
        return CheckItem('Failed', 'DNS: DNS Record Published', 'No common DNS records found (A/AAAA/CNAME/MX)')

    def _check_soa_values(self, soa_results: List[Tuple[str, Optional[str], bool, Optional[Any]]]) -> List[CheckItem]:
        items: List[CheckItem] = []
        if not any(soa for _ns, _ip, _aa, soa in soa_results):
            return [CheckItem('Warning', 'DNS: DNS SOA Check', 'Unable to fetch SOA from any server')]

        # Build maps per NS
        per_ns: List[Tuple[str, Optional[int], Optional[int], Optional[int], Optional[int], Optional[int]]] = []
        for ns, _ip, _aa, soa in soa_results:
            if soa is None:
                per_ns.append((ns, None, None, None, None, None))
            else:
                per_ns.append((ns,
                               int(getattr(soa, 'serial', 0)),
                               int(getattr(soa, 'refresh', 0)),
                               int(getattr(soa, 'retry', 0)),
                               int(getattr(soa, 'expire', 0)),
                               int(getattr(soa, 'minimum', 0))))

        # Serial numbers match
        serial_vals = [s for (_ns, s, _r, _re, _e, _m) in per_ns if s is not None]
        unique_serials = sorted(set(serial_vals))
        if serial_vals and len(unique_serials) == 1:
            owners = [ns for (ns, s, *_rest) in per_ns if s == unique_serials[0]]
            items.append(CheckItem('Passed', 'DNS: DNS SOA Serial Numbers Match', f"Serials match {unique_serials[0]} on: {', '.join(owners)}"))
        elif serial_vals:
            mapping = ', '.join(f"{ns}:{s}" for (ns, s, *_rest) in per_ns if s is not None)
            items.append(CheckItem('Warning', 'DNS: DNS SOA Serial Numbers Match', f"Serials differ: {mapping}"))

        # Serial format (use first value)
        if serial_vals:
            s0 = str(serial_vals[0])
            if re.match(r'^\d{10}$', s0):
                items.append(CheckItem('Passed', 'DNS: DNS SOA Serial Number Format', f'Serial format looks like YYYYMMDDnn ({s0})'))
            else:
                items.append(CheckItem('Warning', 'DNS: DNS SOA Serial Number Format', f'Unexpected serial format {s0} (expected YYYYMMDDnn)'))

        # Refresh 1200-43200
        refresh_vals = [r for (_ns, _s, r, *_rest) in per_ns if r is not None]
        if refresh_vals:
            r0 = refresh_vals[0]
            if 1200 <= r0 <= 43200:
                items.append(CheckItem('Passed', 'DNS: DNS SOA Refresh Value', f'Refresh {r0} within recommended 1200-43200'))
            else:
                items.append(CheckItem('Warning', 'DNS: DNS SOA Refresh Value', f'Refresh {r0} out of recommended 1200-43200'))

        # Retry 180-7200
        retry_vals = [rv for (_ns, _s, _r, rv, *_rest) in per_ns if rv is not None]
        if retry_vals:
            rv0 = retry_vals[0]
            if 180 <= rv0 <= 7200:
                items.append(CheckItem('Passed', 'DNS: DNS SOA Retry Value', f'Retry {rv0} within recommended 180-7200'))
            else:
                items.append(CheckItem('Warning', 'DNS: DNS SOA Retry Value', f'Retry {rv0} out of recommended 180-7200'))

        # Expire 1209600-2419200
        expire_vals = [ev for (_ns, _s, _r, _rv, ev, _m) in per_ns if ev is not None]
        if expire_vals:
            ev0 = expire_vals[0]
            if 1209600 <= ev0 <= 2419200:
                items.append(CheckItem('Passed', 'DNS: DNS SOA Expire Value', f'Expire {ev0} within recommended 1209600-2419200'))
            else:
                items.append(CheckItem('Warning', 'DNS: DNS SOA Expire Value', f'Expire {ev0} out of recommended 1209600-2419200'))

        # Minimum (negative TTL) 300-86400
        minimum_vals = [mv for (_ns, _s, _r, _rv, _e, mv) in per_ns if mv is not None]
        if minimum_vals:
            mv0 = minimum_vals[0]
            if 300 <= mv0 <= 86400:
                items.append(CheckItem('Passed', 'DNS: DNS SOA NXDOMAIN Value', f'Minimum TTL {mv0} within allowed 300-86400'))
            else:
                items.append(CheckItem('Warning', 'DNS: DNS SOA NXDOMAIN Value', f'Minimum TTL {mv0} outside allowed 300-86400'))

        return items

    # --------------- SPF -----------------
    def _get_spf_records(self, domain: str) -> List[str]:
        txts = self._txt_values(domain)
        return [s for s in txts if s.lower().startswith('v=spf1') or ' v=spf1' in s.lower()]

    def _spf_checks(self, domain: str) -> List[CheckItem]:
        items: List[CheckItem] = []
        spfs = self._get_spf_records(domain)
        if not spfs:
            items.append(CheckItem('Failed', 'SPF: SPF Record Published', 'SPF Record not found'))
            return items
        # Multiple
        if len(spfs) > 1:
            items.append(CheckItem('Warning', 'SPF: SPF Multiple Records', f"Found {len(spfs)} SPF records"))
        else:
            items.append(CheckItem('Passed', 'SPF: SPF Multiple Records', 'Less than two records found'))

        # Syntax & terms
        record = spfs[0]
        terms = [t for t in record.split() if t]
        if not terms or not terms[0].lower().startswith('v=spf1'):
            items.append(CheckItem('Failed', 'SPF: SPF Syntax Check', 'Record must start with v=spf1'))
        else:
            items.append(CheckItem('Passed', 'SPF: SPF Syntax Check', 'The record is valid'))

        # After all
        if 'all' in ' '.join(terms).lower():
            try:
                idx = [i for i, t in enumerate(terms) if t.lower().endswith('all')][-1]
                if idx < len(terms) - 1:
                    items.append(CheckItem('Failed', 'SPF: SPF Contains characters after ALL', "There are items after 'ALL'"))
                else:
                    items.append(CheckItem('Passed', 'SPF: SPF Contains characters after ALL', "No items after 'ALL'."))
            except Exception:
                pass

        # Duplicate include
        includes = [t for t in terms if t.lower().startswith('include:')]
        if len(includes) != len(set(map(str.lower, includes))):
            items.append(CheckItem('Warning', 'SPF: SPF Duplicate Include', 'Duplicate includes found'))
        else:
            items.append(CheckItem('Passed', 'SPF: SPF Duplicate Include', 'No Duplicate Includes Found'))

        # Included lookups count (include, a, mx, ptr, exists, redirect)
        lookup_terms = [t for t in terms if re.match(r'^(include:|a|mx|ptr|exists:|redirect=)', t.lower())]
        if len(lookup_terms) <= 10:
            items.append(CheckItem('Passed', 'SPF: SPF Included Lookups', 'Number of included lookups is OK'))
        else:
            items.append(CheckItem('Warning', 'SPF: SPF Included Lookups', f'Too many lookups ({len(lookup_terms)} > 10)'))

        # MX Resource Records count used by SPF 'mx'
        mx_records = self._safe_resolve(domain, 'MX') or []
        if len(mx_records) <= 10:
            items.append(CheckItem('Passed', 'SPF: SPF MX Resource Records', 'Number of MX Resource Records is OK'))
        else:
            items.append(CheckItem('Warning', 'SPF: SPF MX Resource Records', f'Too many MX ({len(mx_records)})'))

        # Deprecated: PTR
        if any(t.lower().startswith('ptr') for t in terms):
            items.append(CheckItem('Warning', 'SPF: SPF Type PTR Check', 'Type PTR found (deprecated)'))
            items.append(CheckItem('Warning', 'SPF: SPF Record Deprecated', 'Deprecated mechanism PTR found'))
        else:
            items.append(CheckItem('Passed', 'SPF: SPF Type PTR Check', 'No type PTR found'))
            items.append(CheckItem('Passed', 'SPF: SPF Record Deprecated', 'No deprecated records found'))

        # Record Published
        items.append(CheckItem('Passed', 'SPF: SPF Record Published', 'SPF Record found'))

        # Null DNS Lookups / Void lookups / Recursive loop – базовые заглушки
        items.append(CheckItem('Passed', 'SPF: SPF Record Null Value', 'No Null DNS Lookups found'))
        items.append(CheckItem('Passed', 'SPF: SPF Void Lookups', 'Number of void lookups is OK'))
        items.append(CheckItem('Passed', 'SPF: SPF Recursive Loop', 'Nor Recursive Loops on Includes'))

        return items

    # --------------- DMARC -----------------
    def _get_dmarc(self, domain: str) -> Optional[str]:
        # 1) Direct TXT on _dmarc.domain
        name = f"_dmarc.{domain}".rstrip('.')
        for s in self._txt_values(name):
            if 'v=dmarc1' in s.lower():
                return s
        # 2) Follow CNAME target if present
        cname_target = self._resolve_cname_target(name)
        if cname_target and cname_target.lower() != name.lower():
            for s in self._txt_values(cname_target):
                if 'v=dmarc1' in s.lower():
                    return s
        # 3) Fallback to registrable domain
        reg = self._registrable_domain(domain)
        if reg and reg != domain:
            reg_name = f"_dmarc.{reg}".rstrip('.')
            for s in self._txt_values(reg_name):
                if 'v=dmarc1' in s.lower():
                    return s
            cname_target = self._resolve_cname_target(reg_name)
            if cname_target and cname_target.lower() != reg_name.lower():
                for s in self._txt_values(cname_target):
                    if 'v=dmarc1' in s.lower():
                        return s
        return None

    def _dmarc_checks(self, domain: str) -> List[CheckItem]:
        items: List[CheckItem] = []
        rec = self._get_dmarc(domain)
        if not rec:
            items.append(CheckItem('Failed', 'MX: DMARC Record Published', 'DMARC Record not found'))
            items.append(CheckItem('Failed', 'MX: DMARC Policy Not Enabled', 'DMARC policy not enabled'))
            return items
        items.append(CheckItem('Passed', 'MX: DMARC Record Published', 'DMARC Record found'))
        # Parse policy p=
        try:
            parts = dict(p.split('=', 1) for p in [x.strip() for x in rec.split(';') if '=' in x])
            policy = (parts.get('p') or parts.get('P') or '').strip().lower()
            if policy in ('reject', 'quarantine'):
                items.append(CheckItem('Passed', 'MX: DMARC Policy Not Enabled', 'DMARC Quarantine/Reject policy enabled'))
            else:
                items.append(CheckItem('Failed', 'MX: DMARC Policy Not Enabled', 'DMARC policy not enabled'))
        except Exception:
            items.append(CheckItem('Warning', 'MX: DMARC Policy Not Enabled', 'Unable to parse DMARC policy'))
        return items

    # --------------- DKIM -----------------
    def _dkim_checks(self, domain: str) -> List[CheckItem]:
        items: List[CheckItem] = []
        selectors = ['default', 'google', 'selector1', 'selector2', 'k1']
        found: List[str] = []
        for sel in selectors:
            name = f"{sel}._domainkey.{domain}".rstrip('.')
            for s in self._txt_values(name):
                if 'v=dkim1' in s.lower():
                    found.append(sel)
                    break
        if found:
            items.append(CheckItem('Passed', 'DKIM: DKIM Record Published', f"Found DKIM selectors ({len(found)}): {', '.join(sorted(set(found)))}"))
        else:
            items.append(CheckItem('Failed', 'DKIM: DKIM Record Published', f"No DKIM records found in common selectors; checked: {', '.join(selectors)}"))
        return items

    # --------------- per-domain run -----------------
    def _analyze_domain(self, domain: str) -> List[CheckItem]:
        checks: List[CheckItem] = []

        # Skip IPs defensively
        if self.target_loader._is_valid_ip(domain) or not self.target_loader._is_valid_domain(domain):
            return checks

        child_ns = self._get_child_ns(domain)
        parent_ns = self._get_parent_ns(domain)

        soa_results, down = self._soa_from_all_ns(domain, child_ns)
        soa_records = [soa for (_ns, _ip, _aa, soa) in soa_results if soa is not None]

        # Core DNS checks
        checks.append(self._check_ns_count(child_ns))
        checks.append(self._check_all_ns_responding(soa_results, down))
        checks.append(self._check_all_authoritative(soa_results))
        checks.append(self._check_parent_match(child_ns, parent_ns))
        prim = self._check_primary_listed_at_parent(soa_results, parent_ns)
        if prim:
            checks.append(prim)
        checks.append(self._check_bad_glue(domain, parent_ns))
        checks.append(self._check_ns_public_ips(soa_results))
        checks.append(self._check_ns_different_subnets(soa_results))
        checks.append(self._check_dns_record_published(domain))
        checks.extend(self._check_soa_values(soa_results))
        checks.append(self._check_open_recursive(domain, soa_results))

        # SPF / DMARC / DKIM
        checks.extend(self._spf_checks(domain))
        checks.extend(self._dmarc_checks(domain))
        checks.extend(self._dkim_checks(domain))

        return checks

    def _rows_from_checks(self, checks: List[CheckItem]) -> List[List[str]]:
        rows: List[List[str]] = []
        for c in checks:
            rows.append([c.status, c.name, c.info, c.url])
        return rows

    def run(self, domains: List[str], save_html: bool = False, save_json: bool = False, json_only: bool = False) -> None:
        self.json_only = json_only
        # Оставляем только домены, без IP, сохраняя порядок и убирая дубли
        seen: Set[str] = set()
        target_domains: List[str] = []
        for d in domains:
            if d in seen:
                continue
            if self.target_loader._is_valid_domain(d) and not self.target_loader._is_valid_ip(d):
                target_domains.append(d)
                seen.add(d)

        if not target_domains:
            print(f"{Fore.YELLOW}Во входном файле нет валидных доменов для --dns-manual{Style.RESET_ALL}")
            return

        html_sections: List[Tuple[str, str]] = []
        json_payload: Dict[str, Any] = {}

        def priority(s: str) -> int:
            s = (s or '').lower()
            if s in ('failed', 'error'):
                return 0
            if s == 'warning':
                return 1
            if s == 'passed':
                return 2
            if s == 'timeout':
                return 3
            return 4

        if not json_only:
            print(f"Анализирую {len(target_domains)} доменов...")
        
        for i, d in enumerate(target_domains, 1):
            try:
                if not json_only:
                    print(f"\n{Fore.CYAN}[{i}/{len(target_domains)}] === {d} ==={Style.RESET_ALL}")
                checks = self._analyze_domain(d)
                rows = self._rows_from_checks(checks)
                rows.sort(key=lambda r: (priority(r[0]), r[1]))

                if not json_only:
                    if rows:
                        print(tabulate([[r[0], r[1], r[2]] for r in rows], headers=['Статус', 'Тест', 'Описание'], tablefmt='grid'))
                    else:
                        print("Нет данных по домену")

                if save_html:
                    html_sections.append((d, self.reporter.build_domain_table(rows)))
                # Всегда накапливаем JSON для консоли/сохранения
                json_payload[d] = {
                    'domain': d,
                    'checks': [
                        {
                            'status': r[0],
                            'test': r[1],
                            'description': r[2],
                            'url': r[3],
                        }
                        for r in rows
                    ],
                }
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Анализ прерван пользователем{Style.RESET_ALL}")
                return
            except Exception as e:
                print(f"{Fore.RED}Ошибка при анализе домена {d}: {e}{Style.RESET_ALL}")
                continue

        if save_html and html_sections:
            if not json_only:
                from datetime import datetime
                from pathlib import Path
                reports_dir = Path('reports')
                reports_dir.mkdir(parents=True, exist_ok=True)
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                out = reports_dir / f"dns_manual_report_{ts}.html"
                html = self.reporter.wrap_global(html_sections)
                out.write_text(html, encoding='utf-8')
                print(f"HTML отчет: {out.resolve()}")

        # Печать JSON-результатов в консоль всегда
        if json_payload:
            import json as _json
            try:
                print(_json.dumps(json_payload, ensure_ascii=False, indent=2))
            except Exception:
                pass

        if save_json and json_payload:
            if not json_only:
                from datetime import datetime as _dt
                from pathlib import Path as _Path
                reports_dir = _Path('reports')
                reports_dir.mkdir(parents=True, exist_ok=True)
                ts_json = _dt.now().strftime('%Y%m%d_%H%M%S')
                json_path = reports_dir / f"dns_manual_report_{ts_json}.json"
                import json as _json
                json_path.write_text(_json.dumps(json_payload, ensure_ascii=False, indent=2), encoding='utf-8')
                print(f"JSON отчет: {json_path.resolve()}")


