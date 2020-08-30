import click
import trio

import defaults
from pipeline.base import BaseTransformer
from primitives import check_port


def port_payload(port):
    return {
        'value': port,
        'status': 'open',
        'type': 'tcp_port',
    }


class PortScannerTransformer(BaseTransformer):
    ESSENTIAL = False
    RECOMMENDED = False
    PASSIVE = False

    def __init__(self, *args, **kwargs):
        super(PortScannerTransformer, self).__init__(*args, **kwargs)
        self.wordlist = None
        self.ports_index = None

    def setup(self):
        self.wordlist = click.prompt("List of ports", default='data/ports.txt')

        ports_with_desc = [line.strip().split('\t') for line in open(self.wordlist, 'r').readlines()]
        self.ports_index = {}
        for item in ports_with_desc:
            if len(item) == 2:
                port, desc = item
            else:
                port, desc = item[0], '--NO-DESC--'
            self.ports_index[port] = desc

    async def scan_all_ports(self):
        limit = trio.CapacityLimiter(defaults.PORT_SCAN_LIMIT)
        results = {}
        async with trio.open_nursery() as nursery:
            for ip, ip_data in self.iter_ip_addresses():
                if ip in results:
                    continue

                results[ip] = {}
                for port in self.ports_index:
                    nursery.start_soon(
                        check_port,
                        ip,
                        port,
                        results,
                        limit,
                    )

        for ip, ip_data in self.iter_ip_addresses():
            ip_data['ports'] = {}
            for port, status in results[ip].items():
                if status == 'open':
                    ip_data['ports'][port] = port_payload(port)

    def run(self):
        trio.run(self.scan_all_ports)
        return self.data
