from pprint import pprint

import trio
import click

import bruteforce
import scrape
from pipeline.base import BasePipeline


class SubdomainScraperPipeline(BasePipeline):
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
                    subdomains[result] = {
                        'value': result,
                        'type': 'domain',
                        'sources': results[result]
                    }

        return self.data


class SubdomainBruteForcePipeline(BasePipeline):
    def __init__(self, *args, **kwargs):
        super(SubdomainBruteForcePipeline, self).__init__(*args, **kwargs)
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
            pprint(results)
            if 'subdomains' not in item:
                item['subdomains'] = {}
            subdomains = item['subdomains']
            print(subdomains)
            print(results)
            for result, ip_addresses in results:
                if result in subdomains:
                    subdomains[result]['sources'].append('brute')
                else:
                    subdomains[result] = {
                        'value': result,
                        'type': 'domain',
                        'sources': ['brute']
                    }

        return self.data
