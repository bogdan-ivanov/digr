import json
import atexit
import trio
import click

from bruteforce import bruteforce_urls, bruteforce_subdomains
from scrape import scrape_subdomains, SCRAPERS
from utils import append_dir, append_subdomain
import pipeline.domain


COMPLETE_PIPELINE = [
    pipeline.domain.SubdomainScraperTransformer,
    pipeline.domain.SubdomainBruteForceTransformer,
]


@click.group()
def cli():
    pass


@cli.command()
@click.option('--domain', prompt='Domain', help='Domain to find subdomains for', multiple=True)
def investigate(domain):
    config = {}
    data = {
        'domains': {}
    }
    for d in domain:
        data['domains'][d] = {
            'type': 'domain',
            'value': d
        }

    for T in COMPLETE_PIPELINE:
        if not T.ESSENTIAL:
            run_transformer = click.confirm(f"Do you want to run '{T.__name__}'", default=T.RECOMMENDED)
        else:
            run_transformer = True

        if run_transformer:
            t = T(data, config=config)
            t.setup()
            data = t.run()
            print(json.dumps(data, indent=2))
            input("Press Enter ...")

    print(json.dumps(data, indent=2))


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
    results = trio.run(scrape_subdomains, domain, SCRAPERS)
    print(results)


@atexit.register
def cleanup():
    pass


if __name__ == "__main__":
    cli()


