import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs,urlparse
from xray.configure import initialize,server_config,client_config,link

class RealityTests(unittest.TestCase):
    def credentials(self):
        return dict(host='178.62.199.241',uuid='12345678-1234-4234-8234-123456789abc',short_id='0123456789abcdef',private_key=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('='),public_key=base64.urlsafe_b64encode(bytes(reversed(range(32)))).decode().rstrip('='))
    def test_link_matches_server_and_does_not_include_private_key(self):
        c=self.credentials();s=server_config(c)['inbounds'][0];u=urlparse(link(c));q=parse_qs(u.query)
        self.assertEqual(u.port,s['port']);self.assertNotIn(u.port,(443,8443))
        self.assertEqual(u.username,s['settings']['clients'][0]['id'])
        self.assertEqual(q['sid'],s['streamSettings']['realitySettings']['shortIds'])
        self.assertEqual(q['sni'],s['streamSettings']['realitySettings']['serverNames'])
        self.assertEqual(q['pbk'],[c['public_key']]);self.assertNotIn(c['private_key'],link(c))
        self.assertNotIn(c['private_key'],json.dumps(client_config(c)))
    def test_redeploy_preserves_credentials_and_restricts_private_files(self):
        c=self.credentials()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            output=f"PrivateKey: {c['private_key']}\nPassword (PublicKey): {c['public_key']}\n"
            with patch('xray.configure.subprocess.check_output',return_value=output) as generate:
                initialize('/fake/xray',root)
                old=(root/'credentials.json').read_bytes()
                initialize('/fake/xray',root)
                generate.assert_called_once()
            self.assertEqual(old,(root/'credentials.json').read_bytes())
            for p in root.iterdir(): self.assertEqual(p.stat().st_mode&0o777,0o600)
            self.assertNotIn('private_key',json.loads((root/'client-credentials.json').read_text()))
    def test_unauthenticated_clients_are_not_configured(self):
        s=server_config(self.credentials())
        clients=s['inbounds'][0]['settings']['clients']
        self.assertEqual(len(clients),1)
        self.assertEqual(clients[0]['flow'],'xtls-rprx-vision')
        self.assertTrue(s['routing']['rules'][0]['ip'])

if __name__=='__main__':unittest.main()
