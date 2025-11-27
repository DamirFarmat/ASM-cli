import asyncio
import dns.resolver
import dns.exception

async def get_dns_records(domain: str, json_only: bool = False) -> dict:
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    results = {"domain": domain, "records": {}}
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    for record_type in record_types:
        try:
            answers = await asyncio.to_thread(resolver.resolve, domain, record_type)
            
            records = []
            if record_type == "MX":
                records = sorted([{"priority": r.preference, "exchange": str(r.exchange)} for r in answers], key=lambda x: x['priority'])
            elif record_type == "TXT":
                records = ["".join(s.decode('utf-8') for s in r.strings) for r in answers]
            else:
                records = [str(r) for r in answers]
            
            if records:
                results["records"][record_type] = records

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            if not json_only:
                print(f"[-] Error resolving {record_type} for {domain}: {e}")

    return results
