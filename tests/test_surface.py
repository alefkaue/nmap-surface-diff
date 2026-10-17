from pathlib import Path
import unittest
from nmap_surface_diff import parse_report, compare

EXAMPLES = Path(__file__).resolve().parents[1] / 'examples'


class SurfaceTests(unittest.TestCase):
    def example(self, name):
        return parse_report((EXAMPLES / name).read_text(encoding='utf-8'))

    def test_inventory_and_changes(self):
        before, after = self.example('before.xml'), self.example('after.xml')
        result = compare(before, after)
        self.assertEqual([e['port'] for e in result['newly_observed']], [443, 3389])
        self.assertEqual([e['port'] for e in result['not_observed']], [80])
        self.assertFalse(result['scope_changed'])
        self.assertFalse(result['host_set_changed'])

    def test_unchanged_is_empty(self):
        report = self.example('before.xml')
        self.assertFalse(any(compare(report, report).values()))

    def test_filtered_and_down_are_not_open(self):
        text = (EXAMPLES / 'before.xml').read_text().replace('state="open"', 'state="open|filtered"')
        self.assertEqual(parse_report(text)['endpoints'], [])
        text = text.replace('state="up"', 'state="down"')
        self.assertEqual(parse_report(text)['hosts'], [])

    def test_ipv6_and_missing_service(self):
        text = (EXAMPLES / 'before.xml').read_text().replace('192.0.2.20', '2001:db8::20').replace('ipv4', 'ipv6')
        text = text.replace('<service name="ssh" method="table"/>', '')
        report = parse_report(text)
        self.assertEqual(report['endpoints'][0]['address'], '2001:db8::20')
        self.assertEqual(report['endpoints'][0]['service'], 'unknown')

    def test_incomplete_malformed_and_entity_inputs(self):
        for text in ['<other/>', '<nmaprun/>', '<broken',
                     '<!DOCTYPE nmaprun [<!ENTITY x "bad">]><nmaprun/>']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_report(text)

    def test_scope_and_service_change(self):
        before = self.example('before.xml')
        text = (EXAMPLES / 'before.xml').read_text().replace('22,80,443,3389', '22,80').replace('name="ssh"', 'name="unknown"')
        result = compare(before, parse_report(text))
        self.assertTrue(result['scope_changed'])
        self.assertEqual(result['service_changed'][0]['after']['port'], 22)
