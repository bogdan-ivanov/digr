class BaseTransformer(object):
    ESSENTIAL = False
    RECOMMENDED = False

    def __init__(self, data, config):
        self.data = data
        self.config = config

    def iter_domains(self, only_base=False):
        for domain, domain_data in self.data.get('domains', {}).items():
            yield domain, domain_data
            if not only_base:
                for subdomain, subdomain_data in domain_data.get('subdomains', {}).items():
                    yield subdomain, subdomain_data

    @property
    def name(self):
        return self.__class__.__name__

    def setup(self):
        pass

    def run(self):
        pass
