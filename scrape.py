import json
import random
import re
from pprint import pprint

import asks
import trio
import parse

import defaults


class DomainScraper(object):
    SOURCE = None

    def __init__(self, domain, **kwargs):
        self.domain = domain
        self.kwargs = kwargs

    async def run(self, results):
        raise NotImplementedError("Implement run method")

    def report_results(self, results, domains):
        for domain in domains:
            if domain not in results:
                results[domain] = []

            results[domain].append(self.__class__.SOURCE)


class CrtShScraper(DomainScraper):
    SOURCE = 'crt.sh'

    async def run(self, results):
        found_domains = []
        API_URL = f'https://crt.sh/?q=%25.{self.domain}'
        params = dict(
            follow_redirects=True,
            retries=defaults.DEFAULT_RETRIES,
            headers={'User-Agent': random.choice(defaults.USER_AGENTS)}
        )
        response = await asks.get(API_URL, **params)

        matches = parse.findall("<TD>{domain}</TD>", str(response.content))
        for item in matches:
            if item['domain'].startswith("<A"):
                continue

            domains = item['domain'].split('<BR>')
            domains = [d for d in domains if d.endswith(self.domain)
                       and '*' not in d and '@' not in d]
            found_domains.extend(domains)

        found_domains = set(found_domains)
        self.report_results(results, found_domains)

        return_ = {'source': 'crt.sh', 'results': sorted(list(found_domains))}
        return return_


class SublisterAPIScraper(DomainScraper):
    SOURCE = 'api.sublist3r.com'

    async def run(self, results):
        API_URL = f'https://api.sublist3r.com/search.php?domain={self.domain}'
        params = dict(
            follow_redirects=True,
            retries=defaults.DEFAULT_RETRIES,
            headers={'User-Agent': random.choice(defaults.USER_AGENTS)}
        )
        response = await asks.get(API_URL, **params)
        found_domains = sorted(list(set(json.loads(response.content))))

        self.report_results(results, found_domains)

        return_ = {'source': 'api.sublist3r.com', 'results': found_domains}
        return return_


class ThreatCrowdScraper(DomainScraper):
    SOURCE = 'threatcrowd.org'

    async def run(self, results):
        API_URL = f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}'
        params = dict(
            follow_redirects=True,
            retries=defaults.DEFAULT_RETRIES,
            headers={'User-Agent': random.choice(defaults.USER_AGENTS)}
        )
        response = await asks.get(API_URL, **params)
        found_domains = sorted(list(set(json.loads(response.content)['subdomains'])))
        found_domains = [d.strip() for d in found_domains]
        found_domains = [d for d in found_domains if d.endswith(self.domain)]

        self.report_results(results, found_domains)

        return_ = {'source': 'threatcrowd.org', 'results': found_domains}
        return return_


async def scrape_subdomains(domain, scrapers):
    results = {}
    async with trio.open_nursery() as nursery:
        for ScraperClass in scrapers:
            scraper = ScraperClass(domain)
            nursery.start_soon(scraper.run, results)

    return results
