import unittest
from socks.configure import render,NETWORKS

class SocksConfigTests(unittest.TestCase):
    def test_authentication_required_in_every_pass_rule(self):
        config=render()
        self.assertIn('socksmethod: username',config)
        self.assertNotIn('socksmethod: none',config)
        rules=config.split('socks pass {')[1:]
        self.assertEqual(len(rules),len(NETWORKS))
        for rule in rules:
            body=rule.split('}',1)[0]
            self.assertIn('socksmethod: username',body)
            self.assertIn('user: tgproxy',body)
            self.assertIn('proxyprotocol: socks_v5',body)
            self.assertNotIn('to: 0.0.0.0/0',body)
        self.assertTrue(config.rstrip().endswith('socks block {\n    from: 0.0.0.0/0 to: 0.0.0.0/0\n}'))
    def test_listener_cannot_replace_mtproxy(self):
        for port in (443,80,0,65536):
            with self.assertRaises(ValueError):render(port)
    def test_only_explicit_authentication_identity_can_be_rendered(self):
        with self.assertRaises(ValueError):render(username='root')

if __name__=='__main__':unittest.main()
