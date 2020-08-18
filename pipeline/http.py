import random
import ssl

import asks
import trio

import defaults
from pipeline.base import BaseTransformer
from asks.sessions import Session


class HttpProbeTransformer(BaseTransformer):
    ESSENTIAL = False
    RECOMMENDED = True

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
        ssl_context = ssl.SSLContext()
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.check_hostname = False
        session = Session(connections=50, ssl_context=ssl_context)

        async with trio.open_nursery() as nursery:
            for domain, domain_data in self.data.get('domains', {}).items():
                if 'web' not in domain_data:
                    domain_data['web'] = {}
                url = f"http://{domain}"
                nursery.start_soon(self.probe_url, session, url, domain_data['web'])
                url = f"https://{domain}"
                nursery.start_soon(self.probe_url, session, url, domain_data['web'], 'https')
                for subdomain, subdomain_data in domain_data.get('subdomains', {}).items():
                    if 'web' not in subdomain_data:
                        subdomain_data['web'] = {}
                    url = f"http://{subdomain}"
                    nursery.start_soon(self.probe_url, session, url, subdomain_data['web'])
                    url = f"https://{subdomain}"
                    nursery.start_soon(self.probe_url, session, url, subdomain_data['web'], 'https')

    def run(self):
        trio.run(self.check_urls)
        return self.data
