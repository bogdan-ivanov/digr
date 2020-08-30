import asks
import random

import dns
import trio
from dns import asyncresolver
from dns import resolver
from dns import name

import defaults
from utils import success


async def fetch_url(url, results, limit, valid_status_codes, pbar=None):
    params = dict(
        follow_redirects=False,
        timeout=defaults.DEFAULT_TIMEOUT,
        retries=defaults.DEFAULT_RETRIES,
        headers={'User-Agent': random.choice(defaults.USER_AGENTS)}
    )

    try:
        async with limit:
            response = await asks.get(url, **params)
        if response.status_code in valid_status_codes:
            results.append((url, response.status_code))
            print(f"[+] Found: {url} - {response.status_code}")
        return response
    except (OSError, asks.errors.RequestTimeout) as e:
        return None
    finally:
        if pbar:
            pbar.update()


async def check_port(ip_addr, port, results, limit):
    return_value = 'closed'
    async with limit:
        with trio.move_on_after(defaults.PORT_SCAN_TIMEOUT):
            conn = trio.socket.socket(trio.socket.AF_INET, trio.socket.SOCK_STREAM)
            try:
                await conn.connect((ip_addr, port))
                return_value = 'open'
            except Exception as e:
                print("check_port:", e)
            finally:
                conn.close()

    if results is not None:
        if ip_addr not in results:
            results[ip_addr] = {}
        results[ip_addr][port] = return_value
    return return_value


async def query_dns(domain, nameservers, results, limit, pbar=None):
    random.shuffle(nameservers)
    response = None
    for ns in nameservers[:5] + ['8.8.8.8']:
        async with limit:
            try:
                asyncresolver.nameservers = [ns]
                asyncresolver.timeout = 5
                asyncresolver.lifetime = 5

                response = None
                with trio.move_on_after(5):
                    response = await asyncresolver.resolve(domain, 'A')

                if response:
                    success(f"Found: {domain}")
                    if results is not None:
                        results.append((domain, [ip.to_text() for ip in response]))
                    break
            except resolver.NXDOMAIN:
                break
            except (resolver.NoAnswer, name.EmptyLabel, resolver.NoNameservers) as e:
                # warning(f"Exception for {domain}: {e}, {type(e)}")
                continue
            except dns.exception.Timeout:
                # warning(f"DNS Timeout for domain={domain}, nameserver={ns}")
                # await trio.sleep(1)
                pass

    if pbar:
        pbar.update()
    return response


