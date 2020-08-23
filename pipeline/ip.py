import geoip2.database
import geoip2.errors
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
        'network': str(asn_response.network) if asn_response else None,
        'asn': asn_response.autonomous_system_number if asn_response else None,
        'asn_name': asn_response.autonomous_system_organization if asn_response else None,
        'continent_name': country_response.continent.names['en'] if country_response else None,
        'continent_code': country_response.continent.code if country_response else None,
        'country_name': country_response.country.names['en'] if country_response else None,
        'country_code': country_response.country.iso_code if country_response else None,
    }


class IPAddressTransformer(BaseTransformer):
    ESSENTIAL = False
    RECOMMENDED = True
    PASSIVE = True

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
            for domain, _ in self.iter_domains():
                nursery.start_soon(
                    query_dns,
                    domain,
                    self.nameservers,
                    results,
                    limit,
                    None
                )

        results = dict(results)
        for domain, domain_data in self.iter_domains():
            domain_data['ip_addresses'] = {
                ip: ip_payload(ip) for ip in results.get(domain, [])
            }

    def run(self):
        trio.run(self.resolve_domains)
        return self.data


class GeoIPTransformer(BaseTransformer):
    ESSENTIAL = False
    RECOMMENDED = True
    PASSIVE = True

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
        for domain, domain_data in self.iter_domains():
            if 'ip_addresses' in domain_data:
                for ip_addr, ip_data in domain_data['ip_addresses'].items():
                    asn_response, country_response = self.get_geoip_data(ip_addr)
                    ip_data['geo_ip'] = geoip_payload(asn_response, country_response)

        return self.data

    def get_geoip_data(self, ip_addr):
        try:
            country_response = self.country_reader.country(ip_addr)
        except geoip2.errors.AddressNotFoundError:
            country_response = None
        try:
            asn_response = self.asn_reader.asn(ip_addr)
        except geoip2.errors.AddressNotFoundError:
            asn_response = None
        return asn_response, country_response




