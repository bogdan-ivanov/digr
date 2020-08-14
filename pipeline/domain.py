import trio
import scrape
from pipeline.base import BasePipeline


class SubdomainScraperPipeline(BasePipeline):
    def run(self):
        for item in self.data.get('domains'):
            domain = item['value']
            results = trio.run(scrape.scrape_subdomains, domain, scrape.SCRAPERS)
            item['subdomains'] = [{
                'value': r,
                'type': 'domain',
                'sources': results[r]
            }for r in results]
