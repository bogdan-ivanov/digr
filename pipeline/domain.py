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
    PASSIVE = True

    def run(self):
        for domain, item in self.iter_domains(only_base=True):
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
    PASSIVE = True

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
        for domain, item in self.iter_domains(only_base=True):
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


class SubdomainWebsiteScraperTransformer(BaseTransformer):
    ESSENTIAL = False
    RECOMMENDED = True
    PASSIVE = False

    def run(self):
        results = trio.run(scrape.scrape_websites, [d for d, _ in self.iter_domains()])

        for domain, item in self.iter_domains(only_base=True):
            if 'subdomains' not in item:
                item['subdomains'] = {}

            subdomains = item['subdomains']
            for result, _ in results.items():
                if not result.endswith('.' + domain):
                    continue
                if result in subdomains:
                    subdomains[result]['sources'].extend(['website'])
                else:
                    subdomains[result] = domain_payload(result, ['website'])

        return self.data
