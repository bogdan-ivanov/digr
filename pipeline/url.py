import click
import random

import asks
import trio

import defaults
import utils
from pipeline.base import BaseTransformer
import urllib.parse as urlparse

from utils import warning


def path_payload(path, status_code, redirect_to, description):
    return {
        'type': 'path',
        'value': path,
        'status_code': status_code,
        'redirect_to': redirect_to,
        'description': description
    }


class SensitiveURLFinderTransformer(BaseTransformer):
    ESSENTIAL = False
    RECOMMENDED = True
    PASSIVE = False

    def __init__(self, *args, **kwargs):
        super(SensitiveURLFinderTransformer, self).__init__(*args, **kwargs)
        self.wordlist = None
        self.url_index = None

    def setup(self):
        self.wordlist = click.prompt("Sensitive URLs List file",
                                     default='data/sensitive_urls.txt')

        urls_with_desc = [line.strip().split('\t') for line in open(self.wordlist, 'r').readlines()]
        self.url_index = {}
        for item in urls_with_desc:
            if len(item) == 2:
                url, desc = item
            else:
                url, desc = item[0], '--NO-DESC--'
            self.url_index[url] = desc

    async def probe_url(self, session, url, description=None, valid_status_codes=None, results=None):
        result = None
        params = dict(
            follow_redirects=True,
            timeout=5,
            retries=1,
            headers={'User-Agent': random.choice(defaults.USER_AGENTS)}
        )
        try:
            with trio.move_on_after(5):
                response = await session.get(url, **params)
                result = response
                print(f"{url}\t\t{response.status_code}")
        except (OSError, asks.errors.RequestTimeout):
            pass

        if valid_status_codes is None:
            valid_status_codes = defaults.DEFAULT_VALID_STATUS_CODES
        if result and results is not None:
            if result.status_code in valid_status_codes:
                domain = urlparse.urlparse(url).netloc
                path = urlparse.urlparse(result.url).path
                original_path = urlparse.urlparse(url).path
                if domain not in results:
                    results[domain] = {}
                results[domain][original_path] = path_payload(
                    original_path,
                    result.status_code,
                    path if path != original_path else None,
                    description
                    )

        return result

    async def get_sensitive_urls(self, paths, valid_status_codes=None):
        session = self.get_http_session()
        results = {}

        async with trio.open_nursery() as nursery:
            for path, description in paths.items():
                for domain, _ in self.iter_domains():
                    nursery.start_soon(
                        self.probe_url,
                        session,
                        utils.append_path(f"http://{domain}", path),
                        description,
                        valid_status_codes[domain] if valid_status_codes else None,
                        results
                    )

        return results

    def run(self):
        path404 = "/" + utils.random_string(30, defaults.ALLOWED_CHARS)
        wildcard_responses = trio.run(self.get_sensitive_urls, {path404: ""})

        valid_status_codes = {}
        for domain, _ in self.iter_domains():
            valid_status_codes[domain] = defaults.DEFAULT_VALID_STATUS_CODES[:]
            if domain in wildcard_responses and wildcard_responses[domain]:
                first_key = list(wildcard_responses[domain].keys())[0]
                wildcard_status_code = wildcard_responses[domain][first_key]['status_code']
                warning(f"Found wildcard status_code={wildcard_status_code} for {domain}")
                valid_status_codes[domain].remove(wildcard_status_code)

        sensitive_urls = trio.run(self.get_sensitive_urls, self.url_index, valid_status_codes)
        print("Sensitive URLS: ", sensitive_urls)

        import json
        json.dumps(sensitive_urls, indent=2)

        for domain, domain_data in self.iter_domains():
            domain_data['paths'] = sensitive_urls.get(domain, {})

        return self.data
