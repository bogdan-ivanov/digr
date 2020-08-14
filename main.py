import trio
import click

from bruteforce import bruteforce_urls, bruteforce_subdomains
from scrape import CrtShScraper, scrape_subdomains, SublisterAPIScraper, ThreatCrowdScraper
from utils import append_dir, append_subdomain


@click.group()
def cli():
    pass


@cli.command()
@click.option('--url', prompt='URL', help='Base URL to bust')
@click.option('--wordlist', default='data/dirs.txt', help='Wordlist used for brute-forcing')
def dirbust(url, wordlist):
    results = trio.run(bruteforce_urls, url, wordlist, append_dir)
    print(results)


@cli.command()
@click.option('--domain', prompt='Domain', help='Domain to find subdomains for')
@click.option('--wordlist', default='data/names.txt', help='Wordlist used for brute-forcing')
def domainbust(domain, wordlist):
    results = trio.run(bruteforce_subdomains, domain, wordlist, append_subdomain)
    print(results)


@cli.command()
@click.option('--domain', prompt='Domain', help='Domain to find subdomains for')
def domainscrape(domain):
    scrapers = [
        CrtShScraper,
        SublisterAPIScraper,
        ThreatCrowdScraper,
    ]
    results = trio.run(scrape_subdomains, domain, scrapers)
    print(results)

if __name__ == "__main__":
    cli()


