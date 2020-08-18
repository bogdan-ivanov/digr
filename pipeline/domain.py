import trio
import click

import bruteforce
import scrape
from pipeline.base import BaseTransformer


def domain_payload(domain, sources):
    return {
        'value': domain,
        'type': 'domain',
        'sources': sources
    }


class SubdomainScraperTransformer(BaseTransformer):
    ESSENTIAL = True
    RECOMMENDED = True

    def run(self):
        for domain, item in self.data.get('domains').items():
            results = trio.run(scrape.scrape_subdomains, domain, scrape.SCRAPERS)
            if 'subdomains' not in item:
                item['subdomains'] = {}
            subdomains = item['subdomains']
            for result in results:
                if result in subdomains:
                    subdomains[result]['sources'].extend(results[results])
                else:
                    subdomains[result] = domain_payload(result, results[result])

        return self.data


class SubdomainBruteForceTransformer(BaseTransformer):
    ESSENTIAL = False
    RECOMMENDED = False

    def __init__(self, *args, **kwargs):
        super(SubdomainBruteForceTransformer, self).__init__(*args, **kwargs)
        self.wordlist = None
        self.nameservers = None

    def setup(self):
        self.wordlist = click.prompt("Wordlist for brute forcing subdomains",
                                     default='data/names_xsmall.txt')
        nameservers = click.prompt("List of resolvers",
                                   default='data/resolvers.txt')
        self.nameservers = [ns.strip() for ns in open(nameservers, 'r').readlines()]

    def run(self):
        for domain, item in self.data.get('domains').items():
            results = trio.run(bruteforce.bruteforce_subdomains, domain, self.wordlist, self.nameservers)
            if 'subdomains' not in item:
                item['subdomains'] = {}
            subdomains = item['subdomains']
            for result, ip_addresses in results:
                if result in subdomains:
                    subdomains[result]['sources'].append('brute')
                else:
                    subdomains[result] = domain_payload(result, ['brute'])

        return self.data
