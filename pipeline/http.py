import random

import asks
import trio

import defaults
from pipeline.base import BaseTransformer


class HttpProbeTransformer(BaseTransformer):
    ESSENTIAL = False
    RECOMMENDED = True
    PASSIVE = False

    async def probe_url(self, session, url, domain_data, key='http'):
        params = dict(
            follow_redirects=False,
            timeout=5,
            retries=1,
            headers={'User-Agent': random.choice(defaults.USER_AGENTS)}
        )

        results = {
            'live': False,
            'status_code': None,
            'url': url
        }

        try:
            with trio.move_on_after(5):
                response = await session.get(url, **params)
                results['live'], results['status_code'] = True, response.status_code

        except (OSError, asks.errors.RequestTimeout):
            pass
        domain_data[key] = results
        return results['live']

    async def check_urls(self):
        session = self.get_http_session()

        async with trio.open_nursery() as nursery:
            for domain, domain_data in self.iter_domains():
                if 'web' not in domain_data:
                    domain_data['web'] = {}
                url = f"http://{domain}"
                nursery.start_soon(self.probe_url, session, url, domain_data['web'])
                url = f"https://{domain}"
                nursery.start_soon(self.probe_url, session, url, domain_data['web'], 'https')

    def run(self):
        trio.run(self.check_urls)
        return self.data
