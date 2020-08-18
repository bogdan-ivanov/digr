import time
import trio

from tqdm import tqdm

import defaults
from primitives import fetch_url, query_dns
from utils import init_source, random_string, append_subdomain


async def bruteforce_urls(base_url, iterator, url_builder, valid_status_codes=None):
    limit = trio.CapacityLimiter(defaults.DEFAULT_CONNECTION_COUNT)
    if valid_status_codes is None:
        valid_status_codes = defaults.DEFAULT_VALID_STATUS_CODES

    valid_status_codes = set(valid_status_codes)

    start_time = time.time()
    total = sum([1 for _ in init_source(iterator)])
    source = init_source(iterator)

    async with trio.open_nursery() as nursery:
        results = []
        for item in [random_string(30, defaults.ALLOWED_CHARS) for _ in range(30)]:
            url = url_builder(base_url, item)
            nursery.start_soon(fetch_url, url, results, limit, valid_status_codes)

    if results:
        wildcard_status_codes = set([item[1] for item in results])
        print(f"Found Wildcard Status Codes: {wildcard_status_codes}, removing them from the Valid Status Codes List")
        valid_status_codes = valid_status_codes.difference(wildcard_status_codes)
        print(f"Valid Status Codes: {valid_status_codes}")

    async with trio.open_nursery() as nursery:
        results = []
        pbar = tqdm(total=total)
        for item in source:
            url = url_builder(base_url, item)
            nursery.start_soon(fetch_url, url, results, limit, valid_status_codes, pbar)

    end_time = time.time()
    print(f"Total Time: {end_time - start_time}s")

    return results


async def bruteforce_subdomains(domain, iterator, nameservers):
    limit = trio.CapacityLimiter(defaults.DNS_LIMIT)

    start_time = time.time()
    source = list(init_source(iterator))

    results = []
    pbar = tqdm(total=len(source))

    while True:
        batch, source = source[:defaults.DNS_BATCH_SZ], source[defaults.DNS_BATCH_SZ:]
        if not batch:
            break
        async with trio.open_nursery() as nursery:
            for item in batch:
                subdomain = append_subdomain(domain, item)
                nursery.start_soon(
                    query_dns,
                    subdomain,
                    nameservers,
                    results,
                    limit,
                    pbar
                )

    end_time = time.time()
    print(f"Total Time: {end_time - start_time}s")

    return results
