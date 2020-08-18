import random
import ssl

import asks
import trio
import click

import defaults
from pipeline.base import BaseTransformer
from asks.sessions import Session

from primitives import query_dns


def ip_payload(ip):
    return {
        'value': ip,
        'type': 'ip_address',
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
