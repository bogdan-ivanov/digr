from pprint import pprint

import trio
import click

import bruteforce
import scrape
from pipeline.base import BasePipeline
from utils import append_subdomain


class SubdomainScraperPipeline(BasePipeline):
    def run(self):
        for domain, item in self.data.get('domains').items():
            results = trio.run(scrape.scrape_subdomains, domain, scrape.SCRAPERS)
            subdomains = item.get('subdomains', {})
            for result in results:
                if result in subdomains:
                    subdomains[result]['sources'].extend(results[results])
                else:
                    subdomains[result] = {
                        'value': result,
                        'type': 'domain',
                        'sources': results[result]
                    }


class SubdomainBruteForcePipeline(BasePipeline):
    def __init__(self, *args, **kwargs):
        super(SubdomainBruteForcePipeline, self).__init__(*args, **kwargs)
        self.wordlist = None
        self.nameservers = None

    def setup(self):
        self.wordlist = click.prompt("Wordlist for brute forcing subdomains",
                                     default='data/names.txt')
        nameservers = click.prompt("List of resolvers",
                                   default='data/resolvers.txt')
        self.nameservers = [ns.strip() for ns in open(nameservers, 'r').readlines()]

    def run(self):
        for domain, item in self.data.get('domains').items():
            results = trio.run(bruteforce.bruteforce_subdomains, domain, self.wordlist, self.nameservers)
            pprint(results)
            subdomains = item.get('subdomains', {})
            print(subdomains)
            for result, ip_addresses in results:
                if result in subdomains:
                    subdomains[result]['sources'].extend(results[results])
                else:
                    subdomains[result] = {
                        'value': result,
                        'type': 'domain',
                        'sources': ['brute']
                    }

        return self.data
