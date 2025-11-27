import asyncio
import json
from typing import List
from .dnsdump.dns_resolver import get_dns_records
from .dnsdump.subdomain_enumerator import axfr_zone_transfer, passive_crt_sh
from .dnsdump.ip_analyzer import get_asn_info, get_shodan_info, get_geolocation_info

class DNSDump:
    """
    Модуль для полной DNS-разведки домена.
    """

    async def run(self, domain: str, json_only: bool = False):
        """
        Основная функция-оркестратор для выполнения всех шагов DNS-разведки.
        """
        if not json_only:
            print(f"[*] Starting DNS reconnaissance for: {domain}")
        
        main_domain_dns = await get_dns_records(domain, json_only=json_only)
        
        final_report = {
            "domain": domain,
            "dns_records": main_domain_dns.get("records", {}),
            "subdomains": []
        }
        
        if not json_only:
            print("[*] Enumerating subdomains via crt.sh and AXFR...")

        crt_sh_subdomains = await passive_crt_sh(domain, json_only=json_only)
        
        if crt_sh_subdomains is None:
            if not json_only:
                print("[-] Could not retrieve subdomains from crt.sh. Please try again later.")
            return final_report

        axfr_subdomains = await axfr_zone_transfer(domain, json_only=json_only)
        
        all_subdomains = sorted(list(set(crt_sh_subdomains + axfr_subdomains)))
        if not json_only:
            print(f"[+] Found {len(all_subdomains)} unique subdomains.")
        
        processed_ips = {}
        for subdomain in all_subdomains:
            if not json_only:
                print(f"[*] Analyzing subdomain: {subdomain}")
            subdomain_data = {"hostname": subdomain, "records": {}}
            
            dns_info = await get_dns_records(subdomain, json_only=json_only)
            subdomain_data["records"] = dns_info.get("records", {})
            
            for record_type in ["A", "AAAA"]:
                if record_type in subdomain_data["records"]:
                    ip_list = subdomain_data["records"][record_type]
                    detailed_ip_list = []
                    
                    for ip in ip_list:
                        if ip in processed_ips:
                            detailed_ip_list.append(processed_ips[ip])
                            continue
                        
                        if not json_only:
                            print(f"  -> Analyzing IP: {ip}")
                        ip_details = {"ip": ip}
                        
                        ip_tasks = {
                            "asn": get_asn_info(ip, json_only=json_only),
                            "shodan": get_shodan_info(ip, json_only=json_only),
                            "geo": get_geolocation_info(ip, json_only=json_only)
                        }
                        
                        results = await asyncio.gather(*ip_tasks.values())
                        ip_info = dict(zip(ip_tasks.keys(), results))

                        if ip_info["asn"]:
                            ip_details["asn"] = ip_info["asn"]
                        if ip_info["shodan"]:
                            ip_details["shodan_db"] = ip_info["shodan"]
                        if ip_info["geo"]:
                            ip_details["geolocation"] = ip_info["geo"]

                        detailed_ip_list.append(ip_details)
                        processed_ips[ip] = ip_details
                    
                    subdomain_data["records"][record_type] = detailed_ip_list

            final_report["subdomains"].append(subdomain_data)
            
        return final_report

    async def run_parallel(self, targets: List[str], json_only: bool = False, output_file: str = None):
        """
        Запускает сканирование для нескольких целей параллельно.
        """
        tasks = [self.run(target, json_only) for target in targets]
        results = await asyncio.gather(*tasks)
        
        final_json = {}
        for report in results:
            if report:
                final_json[report['domain']] = report

        if json_only:
            print(json.dumps(final_json, indent=4))
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(final_json, f, indent=4)
                if not json_only:
                    print(f"\n[+] Report successfully saved to {output_file}")
            except IOError as e:
                if not json_only:
                    print(f"\n[-] Error saving report to file: {e}")
        elif not json_only:
            print("\n\n--- FINAL REPORT ---")
            print(json.dumps(final_json, indent=4))