"""Review and compare existing Nmap XML reports without running a scan."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

MAX_BYTES = 8 * 1024 * 1024
REVIEW_PORTS = {'tcp': {21, 22, 23, 445, 3389, 5900}, 'udp': {161}}


def parse_report(text):
    # Nmap's plain DOCTYPE is allowed; internal subsets and external DTDs are not.
    text = re.sub(r'<!DOCTYPE\s+nmaprun\s*>', '', text)
    if '<!DOCTYPE' in text or '<!ENTITY' in text:
        raise ValueError('external DTDs and entity declarations are not supported')
    try:
        root = ET.fromstring(text)
    except ET.ParseError as error:
        raise ValueError(f'invalid XML: {error}') from error
    if root.tag != 'nmaprun':
        raise ValueError('expected nmaprun XML root')
    finished = root.find('runstats/finished')
    if finished is None or finished.get('exit') != 'success':
        raise ValueError('report must contain a successful completion marker')
    endpoints, hosts = {}, set()
    for host in root.findall('host'):
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue
        addresses = [node.get('addr') for node in host.findall('address')
                     if node.get('addrtype') in ('ipv4', 'ipv6')]
        if not addresses:
            raise ValueError('up host without an IP address')
        address = str(ipaddress.ip_address(addresses[0]))
        hosts.add(address)
        for port in host.findall('ports/port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            protocol = port.get('protocol')
            number = int(port.get('portid', '0'))
            if protocol not in ('tcp', 'udp', 'sctp') or not 1 <= number <= 65535:
                raise ValueError('unsupported protocol or invalid port')
            service = port.find('service')
            entry = dict(address=address, protocol=protocol, port=number,
                         service=service.get('name', 'unknown') if service is not None else 'unknown',
                         method=service.get('method', 'unknown') if service is not None else 'unknown')
            key = (address, protocol, number)
            if key in endpoints:
                raise ValueError('duplicate open endpoint')
            endpoints[key] = entry
    scope = sorted((node.get('protocol', ''), node.get('services', '')) for node in root.findall('scaninfo'))
    return dict(hosts=sorted(hosts), scope=scope,
                endpoints=sorted(endpoints.values(), key=lambda e: (e['address'], e['protocol'], e['port'])))


def compare(before, after):
    def keyed(report):
        return {(e['address'], e['protocol'], e['port']): e for e in report['endpoints']}
    old, new = keyed(before), keyed(after)
    return dict(newly_observed=[new[k] for k in sorted(new.keys() - old.keys())],
                not_observed=[old[k] for k in sorted(old.keys() - new.keys())],
                service_changed=[dict(before=old[k], after=new[k]) for k in sorted(old.keys() & new.keys())
                                 if old[k] != new[k]],
                scope_changed=before['scope'] != after['scope'],
                host_set_changed=before['hosts'] != after['hosts'])


def load(path):
    with path.open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('XML exceeds 8 MiB limit')
    return parse_report(data.decode('utf-8-sig'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--before', type=Path)
    args = parser.parse_args()
    try:
        current = load(args.report)
        review = [dict(endpoint=e, reason='Porta comumente usada para administração ou serviço sensível; valide o contexto.')
                  for e in current['endpoints'] if e['port'] in REVIEW_PORTS.get(e['protocol'], set())]
        result = dict(inventory=current, review=review)
        if args.before:
            result['changes'] = compare(load(args.before), current)
    except (OSError, ValueError) as error:
        parser.exit(2, f'Error: {error}\n')
    print(json.dumps(result, indent=2, ensure_ascii=False))
    changes = result.get('changes', {})
    return 1 if review or any(changes.values()) else 0


if __name__ == '__main__':
    sys.exit(main())
