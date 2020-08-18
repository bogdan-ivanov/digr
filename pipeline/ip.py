import geoip2.database
import trio
import click

import defaults
from pipeline.base import BaseTransformer

from primitives import query_dns


def ip_payload(ip):
    return {
        'value': ip,
        'type': 'ip_address',
    }


def geoip_payload(asn_response, country_response):
    return {
        'type': 'geoip_data',
        'network': str(asn_response.network),
        'asn': asn_response.autonomous_system_number,
        'asn_name': asn_response.autonomous_system_organization,
        'continent_name': country_response.continent.names['en'],
        'continent_code': country_response.continent.code,
        'country_name': country_response.country.names['en'],
        'country_code': country_response.country.iso_code,
    }


class IPAddressTransformer(BaseTransformer):
    ESSENTIAL = False
    RECOMMENDED = True

    def __init__(self, *args, **kwargs):
        super(IPAddressTransformer, self).__init__(*args, **kwargs)
        self.nameservers = None

    def setup(self):
        nameservers = click.prompt("List of resolvers", default='data/resolvers.txt')
        self.nameservers = [ns.strip() for ns in open(nameservers, 'r').readlines()]

    async def resolve_domains(self):
        limit = trio.CapacityLimiter(defaults.DNS_LIMIT)
        results = []
        async with trio.open_nursery() as nursery:
            for domain, domain_data in self.data.get('domains', {}).items():
                nursery.start_soon(
                    query_dns,
                    domain,
                    self.nameservers,
                    results,
                    limit,
                    None
                )
                for subdomain, subdomain_data in domain_data.get('subdomains', {}).items():
                    nursery.start_soon(
                        query_dns,
                        subdomain,
                        self.nameservers,
                        results,
                        limit,
                        None
                    )

        results = dict(results)
        for domain, domain_data in self.data.get('domains', {}).items():
            domain_data['ip_addresses'] = {
                ip: ip_payload(ip) for ip in results.get(domain, [])
            }
            for subdomain, subdomain_data in domain_data.get('subdomains', {}).items():
                subdomain_data['ip_addresses'] = {
                    ip: ip_payload(ip) for ip in results.get(subdomain, [])
                }

    def run(self):
        trio.run(self.resolve_domains)
        return self.data


class GeoIPTransformer(BaseTransformer):
    ESSENTIAL = False
    RECOMMENDED = True

    def __init__(self, *args, **kwargs):
        super(GeoIPTransformer, self).__init__(*args, **kwargs)
        self.mmdb = None
        self.country_reader = None
        self.asn_reader = None

    def setup(self):
        self.mmdb = click.prompt("MaxMind Database Location", default='data/mmdb')
        self.country_reader = geoip2.database.Reader(f'{self.mmdb}/GeoLite2-Country.mmdb')
        self.asn_reader = geoip2.database.Reader(f'{self.mmdb}/GeoLite2-ASN.mmdb')

    def run(self):
        for domain, domain_data in self.data.get('domains', {}).items():
            if 'ip_addresses' in domain_data:
                for ip_addr, ip_data in domain_data['ip_addresses'].items():
                    country_response = self.country_reader.country(ip_addr)
                    asn_response = self.asn_reader.asn(ip_addr)
                    ip_data['geo_ip'] = geoip_payload(asn_response, country_response)
            for subdomain, subdomain_data in domain_data.get('subdomains', {}).items():
                if 'ip_addresses' in subdomain_data:
                    for ip_addr, ip_data in subdomain_data['ip_addresses'].items():
                        country_response = self.country_reader.country(ip_addr)
                        asn_response = self.asn_reader.asn(ip_addr)
                        ip_data['geo_ip'] = geoip_payload(asn_response, country_response)

        return self.data




