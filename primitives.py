import asks
import random
from dns import asyncresolver
from dns import resolver
from dns import name

import defaults


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


async def query_dns(domain, results, limit, pbar=None):

    async with limit:
        try:
            response = await asyncresolver.resolve(domain, 'A')
            if response:
                print(f"[+] Found: {domain}")
                results.append((domain, [ip.to_text() for ip in response]))
            return response
        except (resolver.NXDOMAIN, resolver.NoAnswer, name.EmptyLabel, resolver.NoNameservers):
            return None
        finally:
            pbar.update()
