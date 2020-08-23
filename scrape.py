import hashlib
import json
import re
from http.cookies import SimpleCookie
from bs4 import BeautifulSoup

import asks
import click
import trio
import parse
import random

import defaults
import sortedcontainers
import urllib.parse as urlparse
from utils import success, warning


class DomainScraper(object):
    SOURCE = None

    def __init__(self, domain, **kwargs):
        self.domain = domain.lower()
        self.kwargs = kwargs
        self.subdomains = sortedcontainers.SortedList([])

    def __add__(self, domain):
        if isinstance(domain, list):
            return [self + d for d in domain]

        if not domain:
            return False

        domain = domain.lower().strip()

        if self.domain == domain:
            return False

        if domain in self.subdomains:
            return False

        self.subdomains.add(domain)
        return True

    def __iter__(self):
        return iter(self.subdomains)

    async def run(self, results):
        raise NotImplementedError("Implement run method")

    def report_results(self, results):
        for domain in self.subdomains:
            if domain not in results:
                results[domain] = []

            results[domain].append(self.__class__.SOURCE)

    def print_table(self):
        if self.subdomains:
            click.echo(f"{self.SOURCE} - {self.domain}")
            click.echo("===============")
            for domain in self.subdomains:
                success(f"\t - {domain}")
            click.echo("\n")


class CrtShScraper(DomainScraper):
    SOURCE = 'crt.sh'

    async def run(self, results):
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
            self + domains

        self.report_results(results)
        self.print_table()

        return_ = {'source': self.SOURCE, 'results': list(self)}
        return return_


class NetcraftScraper(DomainScraper):
    SOURCE = 'searchdns.netcraft.com'

    @staticmethod
    def solve_js_challenge(response):
        if 'set-cookie' not in response.headers:
            return {}

        cookies = SimpleCookie('\r\n'.join(response.headers['set-cookie']))
        cookie_dict = {c: cookies[c].value for c in cookies}

        if 'netcraft_js_verification_challenge' in cookie_dict:
            cookie_dict['netcraft_js_verification_response'] = hashlib.sha1(
                urlparse.unquote(cookie_dict['netcraft_js_verification_challenge']).encode('utf-8')).hexdigest()
        return cookie_dict

    def get_next_page_url(self, response):
        urls = re.findall(
            r'<a.*?href="(.*?)">Next Page',
            response.content.decode('utf-8'))
        if not urls:
            return None
        return 'http://searchdns.netcraft.com' + urls[0]

    async def run(self, results):
        API_URL = f'https://searchdns.netcraft.com/' \
            f'?restriction=site+ends+with&host={self.domain}&position=limited'

        params = dict(
            follow_redirects=True,
            retries=defaults.DEFAULT_RETRIES,
            headers={'User-Agent': random.choice(defaults.USER_AGENTS)},
        )

        response = await asks.get('https://searchdns.netcraft.com/', **params)
        cookies = self.solve_js_challenge(response=response)
        params['cookies'] = cookies

        while True:
            response = await asks.get(API_URL, **params)

            soup = BeautifulSoup(response.content.decode('utf-8'), features='html.parser')
            urls = soup.find_all('a', {'class': 'results-table__host'})
            for url in urls:
                if not url['href']:
                    continue
                domain = urlparse.urlparse(url['href']).netloc
                self + domain

            API_URL = self.get_next_page_url(response)

            if not API_URL:
                break

            cookies = self.solve_js_challenge(response=response)
            if cookies:
                params['cookies'] = cookies

            await trio.sleep(1)

        self.report_results(results)
        self.print_table()

        return_ = {'source': self.SOURCE, 'results': list(self)}
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
        self + json.loads(response.content)

        self.report_results(results)
        self.print_table()

        return_ = {'source': 'api.sublist3r.com', 'results': list(self)}
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
        try:
            found_domains = json.loads(response.content)['subdomains']
        except KeyError:
            warning(f"ThreatCrowd didn't include any subdomains for {self.domain}")
            found_domains = []

        found_domains = [d for d in found_domains if d.endswith(self.domain)]
        self + found_domains

        self.report_results(results)
        self.print_table()

        return_ = {'source': 'threatcrowd.org', 'results': self.subdomains}
        return return_


class VirusTotalScraper(DomainScraper):
    SOURCE = 'www.virustotal.com'

    async def run(self, results):
        API_URL = f'https://www.virustotal.com/ui/domains/{self.domain}/subdomains'
        params = dict(
            follow_redirects=True,
            retries=defaults.DEFAULT_RETRIES,
            headers={'User-Agent': random.choice(defaults.USER_AGENTS)}
        )

        while True:
            response = await asks.get(API_URL, **params)
            payload = json.loads(response.content)
            if 'error' in payload:
                break

            for item in payload['data']:
                if item['type'] != 'domain':
                    continue

                domain = item['id']
                if not domain.endswith(self.domain) or domain == self.domain:
                    continue

                self + domain

            if 'links' in payload and 'next' in payload['links']:
                API_URL = payload['links']['next']
            else:
                break

        self.report_results(results)
        self.print_table()

        return {'source': self.SOURCE, 'results': list(self)}


async def scrape_subdomains(domain, scrapers):
    results = {}
    async with trio.open_nursery() as nursery:
        for ScraperClass in scrapers:
            scraper = ScraperClass(domain)
            nursery.start_soon(scraper.run, results)

    return results


async def scrape_website_for_domains(address, results):
    params = dict(
        follow_redirects=True,
        retries=defaults.DEFAULT_RETRIES,
        headers={'User-Agent': random.choice(defaults.USER_AGENTS)}
    )
    if address.startswith('http'):
        WEBSITE_URL, BASE_DOMAIN = address, urlparse.urlparse(address).netloc
    else:
        WEBSITE_URL, BASE_DOMAIN = f"http://{address}", address

    try:
        with trio.move_on_after(5):
            response = await asks.get(WEBSITE_URL, **params)

            soup = BeautifulSoup(response.content.decode('utf-8'), features='html.parser')

            urls = soup.find_all('a')
            for url in urls:
                if not url.get('href'):
                    continue
                domain = urlparse.urlparse(url['href']).netloc
                if domain and domain.endswith(BASE_DOMAIN) and domain not in results:
                    success(f"Found {domain} in '{WEBSITE_URL}'")
                    results[domain] = WEBSITE_URL
    except (OSError, asks.errors.RequestTimeout):
        pass


async def scrape_websites(addresses):
    results = {}
    async with trio.open_nursery() as nursery:
        for addr in addresses:
            nursery.start_soon(scrape_website_for_domains, addr, results)
    return results


SCRAPERS = [
    CrtShScraper,
    SublisterAPIScraper,
    ThreatCrowdScraper,
    VirusTotalScraper,
    NetcraftScraper,
]