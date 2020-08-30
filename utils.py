import click
import random
import itertools


def error(text):
    click.echo(click.style("[!] " + text, fg='red', bold=True))


def warning(text):
    click.echo(click.style("[*] " + text, fg='yellow', bold=True))


def success(text):
    click.echo(click.style("[+] " + text, fg='green', bold=True))


def info(text):
    click.echo("[-] " + text)


def random_string(str_size, allowed_chars):
    return ''.join(random.choice(allowed_chars) for _ in range(str_size))


def append_path(url, path):
    url = url.strip()
    path = path.strip()

    if url[-1] == "/":
        url = url[:-1]
    if path[0] == "/":
        path = path[1:]

    url = f"{url}/{path}"
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

