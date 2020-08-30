import json
import yaml
import atexit
from functools import partial

import trio
import click

from bruteforce import bruteforce_urls, bruteforce_subdomains
from scrape import scrape_subdomains, SCRAPERS
from utils import append_path, append_subdomain, warning
import pipeline.domain
import pipeline.http
import pipeline.ip
import pipeline.url
import pipeline.port


COMPLETE_PIPELINE = [
    pipeline.domain.SubdomainScraperTransformer,
    # pipeline.domain.SubdomainWebsiteScraperTransformer,
    # pipeline.domain.SubdomainBruteForceTransformer,
    pipeline.ip.IPAddressTransformer,
    # pipeline.ip.GeoIPTransformer,
    # pipeline.http.HttpProbeTransformer,
    # pipeline.url.SensitiveURLFinderTransformer,
    pipeline.port.PortScannerTransformer
]


OUTPUT_FORMATTERS = {
    'json': partial(json.dump, indent=2),
    'yaml': yaml.dump,
}


@click.group()
def cli():
    pass


@cli.command()
@click.option('--domain', prompt='Domain', help='Domain to find subdomains for', multiple=True)
@click.option('--output', default=None, help='File to save results to')
@click.option('--output-format', default='json', help='File to save results to')
def investigate(domain, output, output_format):
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
            run_transformer = click.confirm(f"[{'PASSIVE' if T.PASSIVE else 'ACTIVE'}] "
                                            f"Do you want to run '{T.__name__}'", default=T.RECOMMENDED)
        else:
            run_transformer = True

        if not run_transformer:
            warning(f"Skipping {T.__name__} ...")

        if run_transformer:
            t = T(data, config=config)
            t.setup()
            data = t.run()
            # print(json.dumps(data, indent=2))
            input("Press Enter ...")

    # print(json.dumps(data, indent=2))

    if output:
        with open(output, 'w') as o_handle:
            OUTPUT_FORMATTERS[output_format](data, o_handle)


@cli.command()
@click.option('--url', prompt='URL', help='Base URL to bust')
@click.option('--wordlist', default='data/dirs.txt', help='Wordlist used for brute-forcing')
def dirbust(url, wordlist):
    results = trio.run(bruteforce_urls, url, wordlist, append_path)
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


@cli.command()
def testing():
    results = trio.run(tcp_scan)


async def tcp_scan(timeout=2):
    conn = trio.socket.socket(trio.socket.AF_INET, trio.socket.SOCK_STREAM)
    # conn.settimeout(2)
    ret = await conn.connect(('192.168.1.54', '22'))
    print(ret)


@atexit.register
def cleanup():
    pass


if __name__ == "__main__":
    cli()


