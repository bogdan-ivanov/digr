import asks
import random

import dns
from dns import asyncresolver
from dns import resolver
from dns import name

import defaults
from utils import error, success


async def fetch_url(url, results, limit, valid_status_codes, pbar=None):
    DEBUGS = ('.htaccess', '.htpasswd', 'phpmyadmin')
    DEBUG = False
    for d in DEBUGS:
        if d in url:
            DEBUG = True

    params = dict(
        follow_redirects=False,
        timeout=defaults.DEFAULT_TIMEOUT,
        retries=defaults.DEFAULT_RETRIES,
        headers={'User-Agent': random.choice(defaults.USER_AGENTS)}
    )

    try:
        async with limit:
            response = await asks.get(url, **params)
        if DEBUG:
            print(f"Got {response.status_code} for {url}")
        if response.status_code in valid_status_codes:
            results.append((url, response.status_code))
            print(f"[+] Found: {url} - {response.status_code}")
        return response
    except (OSError, asks.errors.RequestTimeout) as e:
        if DEBUG:
            print(f"Exception {url}, {e}")
        return None
    finally:
        if pbar:
            pbar.update()


async def query_dns(domain, nameservers, results, limit, pbar=None):
    random.shuffle(nameservers)
    response = None
    # print("-- Domain", domain)
    # print("Servers: ", nameservers)
    for ns in nameservers:
    # ns = random.choice(nameservers)
    #     print("Before Limit")
        async with limit:
            # print("-- NS", ns)
            try:
                # asyncresolver.nameservers = ['8.8.8.8']
                asyncresolver.nameservers = [ns]
                response = await asyncresolver.resolve(domain, 'A')
                if response:
                    success(f"Found: {domain}")
                    results.append((domain, [ip.to_text() for ip in response]))
                    break
            except (resolver.NXDOMAIN, resolver.NoAnswer, name.EmptyLabel, resolver.NoNameservers, dns.exception.Timeout):
                continue
                pass

    pbar.update()
    return response


