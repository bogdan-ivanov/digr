import random
import itertools


def random_string(str_size, allowed_chars):
    return ''.join(random.choice(allowed_chars) for _ in range(str_size))


def append_dir(url, dir):
    if url[-1] == "/":
        url = f"{url}{dir}"
    else:
        url = f"{url}/{dir}"
    return url.strip()


def append_subdomain(domain, subdomain):
    domain = domain.strip()
    subdomain = subdomain.strip()
    return f"{subdomain}.{domain}"


def init_source(source):
    if isinstance(source, str):
        source = open(source, 'r', encoding='latin-1').readlines()
    else:
        source = iter(itertools.tee(source))
    return source

