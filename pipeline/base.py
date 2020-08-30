import ssl

import asks


class BaseTransformer(object):
    ESSENTIAL = False
    RECOMMENDED = False
    PASSIVE = False

    def __init__(self, data, config):
        self.data = data
        self.config = config

    @staticmethod
    def get_http_session(connections=50):
        ssl_context = ssl.SSLContext()
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.check_hostname = False
        session = asks.Session(connections=connections, ssl_context=ssl_context)
        return session

    def iter_domains(self, only_base=False):
        for domain, domain_data in self.data.get('domains', {}).items():
            yield domain, domain_data
            if not only_base:
                for subdomain, subdomain_data in domain_data.get('subdomains', {}).items():
                    yield subdomain, subdomain_data

    def iter_ip_addresses(self, only_base=False):
        for _, domain_data in self.data.get('domains', {}).items():
            for ip, ip_data in domain_data.get('ip_addresses', {}).items():
                yield ip, ip_data

            if not only_base:
                for _, subdomain_data in domain_data.get('subdomains', {}).items():
                    for ip, ip_data in subdomain_data.get('ip_addresses', {}).items():
                        yield ip, ip_data

    @property
    def name(self):
        return self.__class__.__name__

    def setup(self):
        pass

    def run(self):
        pass
